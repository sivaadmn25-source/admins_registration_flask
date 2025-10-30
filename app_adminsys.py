from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, make_response
import os
import json
import psycopg2
import psycopg2.extras
import pandas as pd
import bcrypt
import pytz
import base64
from werkzeug.utils import secure_filename
from functools import wraps
from collections import defaultdict
from datetime import datetime
from dotenv import load_dotenv

# --- INITIALIZATION ---
# Load environment variables from a .env file for database credentials
load_dotenv()

# --- CONFIGURATION ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'xlsx', 'xls'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.getenv("FLASK_SECRET_KEY", "a_very_strong_secret_key_12345")


# --- FLASK-LOGIN CONFIGURATION ---
class AdminUser(UserMixin):
    # MODIFIED: Added is_super_admin and housing_type attributes
    def __init__(self, user_id, role, society_name, username=None, is_super_admin=False, housing_type=None):
        self.id = str(user_id)
        self.username = username
        self.role = role
        self.society_name = society_name
        self.is_super_admin = is_super_admin
        self.housing_type = housing_type # New attribute for housing type


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_password_prompt'
login_manager.login_message_category = "danger"


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    if not conn:
        return None
    admin_row = None
    try:
        # Use a with statement for the cursor to ensure it's closed automatically
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # MODIFIED: Fetching role AND housing_type
            cur.execute("SELECT id, role, society_name, housing_type FROM admins WHERE id = %s", (user_id,))
            admin_row = cur.fetchone()
    except (Exception, psycopg2.DatabaseError) as error:
        app.logger.error(f"Error loading user {user_id}: {error}")
    finally:
        if conn:
            conn.close()

    if admin_row:
        # MODIFIED: Determine if the loaded user is a Super Admin
        is_sa = admin_row['role'] == 'super_admin'
        
        return AdminUser(
            user_id=admin_row['id'],
            role=admin_row['role'],
            society_name=admin_row['society_name'],
            is_super_admin=is_sa, # Set the new flag
            housing_type=admin_row.get('housing_type') # Set the new attribute
        )
    return None


# --- DATABASE & HELPERS ---
def get_db():
    """Establishes a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(
            dbname=os.getenv("PG_DBNAME"),
            user=os.getenv("PG_USER"),
            password=os.getenv("PG_PASSWORD"),
            host=os.getenv("PG_HOST"),
            port=os.getenv("PG_PORT")
        )
        return conn
    except psycopg2.OperationalError as e:
        app.logger.error(f"Error connecting to PostgreSQL database: {e}")
        return None


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# MODIFIED: Added logic to handle 'individual' community type
def generate_households_from_recipe(recipe_data):
    household_list = []
    society_name = recipe_data.get("society_name", "DEFAULT_SOCIETY")
    housing_type = recipe_data.get("housing_type", "").strip()

    # --- Apartment types ---
    if housing_type.startswith("Apartment"):
        towers = recipe_data.get("apartment", {}).get("towers", [])
        for tower in towers:
            try:
                flats_set = set()
                start_flat = int(tower.get("start_flat", 0))
                end_flat = int(tower.get("end_flat", 0))
                start_series = int(tower.get("start_series", 0))
                end_series = int(tower.get("end_series", 0))
                missing_series = {int(s.strip()) for s in tower.get("missing_series", "").split(',') if s.strip().isdigit()}

                # Generate flats
                for s_num in range(start_series, end_series + 1):
                    if s_num in missing_series:
                        continue
                    for f_num in range(start_flat, end_flat + 1):
                        flats_set.add(f"{s_num:02d}{f_num:02d}")

                # Additional / Remove flats
                additional_raw = tower.get("additional_flats", "")
                remove_raw = tower.get("remove_flats", "")
                if additional_raw:
                    flats_set.update({f"{int(f.strip()):04d}" for f in additional_raw.split(',') if f.strip().isdigit()})
                if remove_raw:
                    flats_set.difference_update({f"{int(f.strip()):04d}" for f in remove_raw.split(',') if f.strip().isdigit()})

                for flat in sorted(list(flats_set)):
                    household_list.append((society_name, tower.get("name", "TOWER_NOTSET"), flat))

            except (ValueError, TypeError) as e:
                print(f"Skipping tower due to data error: {tower.get('name')}, {e}")

    # --- Villas / Individual ---
    elif housing_type.startswith("Villas") or housing_type.startswith("Civil") or housing_type.startswith("Individual"):
        individual_data = recipe_data.get("individual", {})
        has_lane = individual_data.get("has_lane", False)

        if has_lane:
            # Process lanes
            for lane in individual_data.get("lanes", []):
                lane_name = lane.get("name", "LANE_NOTSET").strip().upper()
                house_set = set()

                # Base houses
                base_raw = lane.get("base", "")
                for part in base_raw.split(','):
                    part = part.strip()
                    if not part: continue
                    if '-' in part:
                        try:
                            start, end = map(int, part.split('-'))
                            house_set.update(str(h) for h in range(start, end + 1))
                        except ValueError:
                            continue
                    else:
                        house_set.add(part)

                # Additional houses
                additional_raw = lane.get("additional", "")
                if additional_raw:
                    house_set.update({h.strip() for h in additional_raw.split(',') if h.strip()})

                # Remove houses
                remove_raw = lane.get("remove", "")
                if remove_raw:
                    house_set.difference_update({h.strip() for h in remove_raw.split(',') if h.strip()})

                for house in sorted(list(house_set), key=lambda x: int(x) if x.isdigit() else x):
                    household_list.append((society_name, lane_name, house))

        else:
            # Houses without lanes
            houses_raw = individual_data.get("house_numbers", {}).get("numbers_raw", "")
            house_set = set()
            for part in houses_raw.split(','):
                part = part.strip()
                if not part: continue
                if '-' in part:
                    try:
                        start, end = map(int, part.split('-'))
                        house_set.update(str(h) for h in range(start, end + 1))
                    except ValueError:
                        continue
                else:
                    house_set.add(part)

            for house in sorted(list(house_set), key=lambda x: int(x) if x.isdigit() else x):
                household_list.append((society_name, 'N/A', house))  # 'N/A' for tower/zone

    return household_list

def get_voting_status(society_name):
    """Checks the voting schedule for the given society."""
    conn = get_db()
    if not conn:
        return 'DB_CONNECTION_ERROR'
    schedule = None
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute(
                "SELECT start_time, end_time FROM voting_schedule WHERE society_name = %s",
                (society_name,)
            )
            schedule = cur.fetchone()
    except (Exception, psycopg2.DatabaseError) as error:
        app.logger.error(f"Error getting voting status for {society_name}: {error}")
    finally:
        if conn:
            conn.close()

    if not schedule or not schedule['start_time'] or not schedule['end_time']:
        return 'NOT_CONFIGURED'

    try:
        current_time_utc = datetime.now(pytz.utc)
        start_time_utc = datetime.fromisoformat(schedule['start_time'].replace('Z', '+00:00'))
        end_time_utc = datetime.fromisoformat(schedule['end_time'].replace('Z', '+00:00'))

        if current_time_utc < start_time_utc:
            return 'NOT_STARTED'
        elif start_time_utc <= current_time_utc < end_time_utc:
            return 'ACTIVE'
        else:
            return 'CLOSED'

    except (ValueError, TypeError):
        return 'INVALID_SCHEDULE'


# --- ROUTES & VIEWS ---

@app.route('/')
def root_redirect():
    return redirect(url_for("system_entry"))


@app.route('/system-entry')
def system_entry():
    if current_user.is_authenticated:
        return redirect(url_for('admin_panel'))
    return render_template("system_entry.html")

@app.route('/admin-password', methods=['GET', 'POST'])
def admin_password_prompt():
    if current_user.is_authenticated:
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        society_name_input = request.form.get("society_name", "").strip().upper()
        password = request.form.get("admin_password", "")
        if not society_name_input or not password:
            flash("Society Name and Password are required.", "danger")
            return redirect(url_for('admin_password_prompt'))

        conn = get_db()
        if not conn:
            flash("Database connection error.", "danger")
            return render_template("admin_password_prompt.html")
        
        logged_in_user_data = None
        
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                
                # 1. Fetch ALL possible users: The Admin for the entered society OR the system-wide Super Admin.
                # MODIFIED: Ensure 'housing_type' is selected in the query.
                cur.execute(
                    """
                    SELECT id, role, society_name, password_hash, housing_type FROM admins 
                    WHERE (society_name = %s AND role = 'admin') 
                    OR role = 'super_admin'
                    """,
                    (society_name_input,)
                )
                admin_rows = cur.fetchall() 
                
                # 2. Iterate through all fetched rows and check the password against each hash.
                for row in admin_rows:
                    # FIX: Check the password against the hash for the current row.
                    if bcrypt.checkpw(password.encode('utf-8'), bytes(row['password_hash'])):
                        # Success! Store the user data and immediately stop checking.
                        logged_in_user_data = row
                        break
        
        except (Exception, psycopg2.DatabaseError) as error:
            app.logger.error(f"Database error during admin login: {error}")
            flash("A server error occurred.", "danger")
        finally:
            if conn:
                conn.close()

        # 3. Final Login Success/Failure
        if logged_in_user_data:
            # Successfully logged in a user (Admin or Super Admin)
            user = AdminUser(
                user_id=logged_in_user_data['id'],
                role=logged_in_user_data['role'],
                society_name=logged_in_user_data['society_name'],
                # NEW: Pass the fetched housing_type to the AdminUser object
                housing_type=logged_in_user_data.get('housing_type')
            )
            login_user(user)
            
            # CRUCIAL: Use the society name from the database row (e.g., 'SRGF' or '_system_') for the session.
            session['society_name'] = logged_in_user_data['society_name'].strip().upper() 
            # NEW: Store the housing_type in the session
            session['housing_type'] = logged_in_user_data.get('housing_type')
            session.modified = True
            return redirect(url_for('admin_panel'))
        else:
            # Failed login: No user found OR password didn't match any fetched hash.
            flash("Incorrect Society Name or Password.", "danger")
            return redirect(url_for('admin_password_prompt'))

    return render_template("admin_password_prompt.html")

@app.route('/super-admin-password', methods=['GET', 'POST'])
def super_admin_password_prompt():
    # MODIFIED: Super Admin must now provide the target society name to manage.
    if current_user.is_authenticated:
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        # Super Admin needs to specify which society they intend to manage
        society_name_to_manage = request.form.get("society_name", "").strip().upper() 
        password = request.form.get("super_admin_password", "")
        
        if not society_name_to_manage or not password:
            flash("Society Name and Password are required.", "danger")
            return redirect(url_for('super_admin_password_prompt'))
            
        conn = get_db()
        if not conn:
            flash("Database connection error.", "danger")
            return render_template("super_admin_password_prompt.html")

        admin_row = None
        target_society_housing_type = None # NEW: Variable to hold the housing type of the *target* society
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                # 1. Fetch Super Admin credentials (including their housing_type, which might be NULL/ignored)
                # MODIFIED: Ensure 'housing_type' is selected for the Super Admin
                cur.execute(
                    "SELECT id, role, society_name, password_hash, housing_type FROM admins WHERE society_name = %s AND role = %s",
                    ('_system_', 'super_admin')
                )
                super_admin_row = cur.fetchone()
                
                # 2. Fetch the housing_type for the target society the Super Admin is managing
                cur.execute(
                    "SELECT housing_type FROM admins WHERE society_name = %s AND role = %s",
                    (society_name_to_manage, 'admin') # We assume the target society has a standard 'admin' entry
                )
                target_society_row = cur.fetchone()
                if target_society_row:
                    target_society_housing_type = target_society_row.get('housing_type')

        except (Exception, psycopg2.DatabaseError) as error:
            app.logger.error(f"Database error during super admin login: {error}")
            flash("A server error occurred.", "danger")
        finally:
            if conn:
                conn.close()
        
        # FIX: Explicitly convert the 'memoryview' object to 'bytes' for bcrypt.
        if super_admin_row and bcrypt.checkpw(password.encode('utf-8'), bytes(super_admin_row['password_hash'])):
            # Log in the Super Admin user
            user = AdminUser(
                user_id=super_admin_row['id'],
                role=super_admin_row['role'],
                society_name=super_admin_row['society_name'], # This is '_system_'
                is_super_admin=True, # Explicitly set to True
                housing_type=super_admin_row.get('housing_type') # Use the SA's housing type
            )
            login_user(user)
            
            # CRITICAL: Set the session context to the society the Super Admin wishes to manage
            session['society_name'] = society_name_to_manage
            # NEW: Set the session housing_type to the TARGET society's housing type
            session['housing_type'] = target_society_housing_type 
            session.modified = True
            flash(f"Super Admin logged in. Managing society: {society_name_to_manage}", "success")
            return redirect(url_for('admin_panel'))
        else:
            flash("Incorrect Super Admin Password or missing Society Name.", "danger")

    return render_template("super_admin_password_prompt.html")


@app.route('/admin-panel')
@login_required
def admin_panel():
    society_name = current_user.society_name
    voting_status = get_voting_status(society_name)
    response = make_response(render_template("admin_panel.html", voting_status=voting_status))
    return response


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("system_entry"))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/home-management', methods=['GET', 'POST'])
@login_required
def home_management():
    society_name = session.get('society_name')
    housing_type = session.get('housing_type')

    if not society_name:
        flash("Session expired or invalid. Please log in again.", "danger")
        return redirect(url_for('system_entry'))

    if request.method == 'POST':
        print(f"\n--- DEBUG: POST request received for {society_name} ---")
        conn = get_db()
        if not conn:
            flash("Database connection error.", "danger")
            return redirect(url_for('admin_panel'))

        try:
            housing_type_submitted = request.form.get("housing_type")
            print("housing_type_submitted:", housing_type_submitted)
            print("Form keys received:", list(request.form.keys()))

            # Normalize community type
            if housing_type_submitted.startswith("Apartment"):
                community_type_for_recipe = "apartment"
            elif housing_type_submitted.startswith("Villas"):
                community_type_for_recipe = "individual"
            elif housing_type_submitted.startswith("Civil"):
                community_type_for_recipe = "civil"
            else:
                community_type_for_recipe = housing_type_submitted.lower()

            recipe_to_save = {
                "community_type": community_type_for_recipe,
                "housing_type": housing_type_submitted,
                "society_name": society_name
            }

            # --- Apartment logic ---
            if community_type_for_recipe == "apartment":
                recipe_to_save["apartment"] = {"towers": []}
                tower_indices = sorted(list(set(
                    k.split('[')[1].split(']')[0] for k in request.form if k.startswith('towers[')
                )))
                print("Tower indices:", tower_indices)
                for idx in tower_indices:
                    name = request.form.get(f'towers[{idx}][name]', '').strip().upper()
                    # Only skip if Multi Tower and name empty
                    if housing_type_submitted == "Apartment-Multi Towers" and not name:
                        continue
                    tower_data = {
                        "name": name if name else f"T{idx}",
                        "start_flat": request.form.get(f'towers[{idx}][start_flat]'),
                        "end_flat": request.form.get(f'towers[{idx}][end_flat]'),
                        "start_series": request.form.get(f'towers[{idx}][start_series]'),
                        "end_series": request.form.get(f'towers[{idx}][end_series]'),
                        "missing_series": request.form.get(f'towers[{idx}][missing_series]'),
                        "additional_flats": request.form.get(f'towers[{idx}][additional_flats]'),
                        "remove_flats": request.form.get(f'towers[{idx}][remove_flats]')
                    }
                    recipe_to_save["apartment"]["towers"].append(tower_data)

            # --- Individual / Villas / Civil logic ---
            elif community_type_for_recipe in ("individual", "civil"):
                # Determine has_lane from housing_type_submitted for Villas
                if housing_type_submitted.startswith("Villas"):
                    has_lane = housing_type_submitted.strip() == "Villas-Lanes"
                elif housing_type_submitted.startswith("Civil"):
                    has_lane = False
                else:
                    # fallback to form (if ever used)
                    has_lane = request.form.get('individual_has_lane') == 'yes'

                recipe_to_save["individual"] = {"has_lane": has_lane}
                print("Individual has_lane:", has_lane)

                if has_lane:
                    recipe_to_save["individual"]["lanes"] = []
                    lane_indices = sorted(list(set(
                        k.split('[')[1].split(']')[0] for k in request.form if k.startswith('lanes[')
                    )))
                    print("Lane indices:", lane_indices)
                    for idx in lane_indices:
                        name = request.form.get(f'lanes[{idx}][name]', '').strip()
                        if not name:
                            continue
                        lane_data = {
                            "name": name,
                            "base": request.form.get(f'lanes[{idx}][base]', ''),
                            "additional": request.form.get(f'lanes[{idx}][additional]', ''),
                            "remove": request.form.get(f'lanes[{idx}][remove]', '')
                        }
                        recipe_to_save["individual"]["lanes"].append(lane_data)
                else:
                    recipe_to_save["individual"]["house_numbers"] = {
                        "numbers_raw": request.form.get('houses_no_lane', '')
                    }
                    print("houses_no_lane:", request.form.get('houses_no_lane', ''))

            # --- Generate households ---
            final_household_list = generate_households_from_recipe(recipe_to_save)
            print("final_household_list (first 10):", final_household_list[:10], "… total =", len(final_household_list))

            # --- DB operations ---
            with conn.cursor() as cur:
                cur.execute("DELETE FROM households WHERE society_name = %s;", (society_name,))
                print("Deleted old households for", society_name)

                if final_household_list:
                    cur.executemany(
                        "INSERT INTO households (society_name, tower, flat) VALUES (%s, %s, %s)",
                        final_household_list
                    )
                    print("Inserted", len(final_household_list), "households")

                cur.execute(
                    """
                    INSERT INTO home_data (society_name, data) VALUES (%s, %s)
                    ON CONFLICT (society_name) DO UPDATE SET data = EXCLUDED.data
                    """,
                    (society_name, json.dumps(recipe_to_save))
                )

            conn.commit()
            print("Commit complete ✅")
            flash(f"Home configuration for {society_name} saved. {len(final_household_list)} households created/updated.", "success")

        except (Exception, psycopg2.DatabaseError) as e:
            if conn:
                conn.rollback()
            app.logger.error(f"Error in home_management POST: {e}")
            flash(f"An error occurred while saving: {e}", "danger")
        finally:
            if conn:
                conn.close()

        # Render the same page to show flash immediately
        return render_template(
            "home_management.html",
            recipe=recipe_to_save,
            society_name=society_name,
            housing_type=housing_type
        )

    # --- GET request: Load existing recipe ---
    recipe_data = {}
    try:
        conn = get_db()
        if conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SELECT data FROM home_data WHERE society_name = %s", (society_name,))
                recipe_row = cur.fetchone()
            recipe_data = json.loads(recipe_row['data']) if recipe_row and recipe_row['data'] else {}
            print("Loaded recipe_data for GET:", recipe_data)
    except (Exception, psycopg2.DatabaseError) as e:
        app.logger.error(f"Error in home_management GET: {e}")
        flash("Error loading home configuration.", "danger")
    finally:
        if conn:
            conn.close()

    return render_template(
        "home_management.html",
        recipe=recipe_data,
        society_name=society_name,
        housing_type=housing_type
    )

@app.route('/update_max_selection', methods=['POST'])
@login_required
def update_max_selection():
    data = request.get_json()
    max_selection = data.get('max_candidates_selection')
    if not isinstance(max_selection, int) or max_selection < 1:
        return jsonify({"success": False, "message": "Invalid input."}), 400
    society_name = session.get("society_name")
    if not society_name:
        return jsonify({"success": False, "message": "Admin session not found."}), 403
    
    conn = get_db()
    if not conn:
        return jsonify({"success": False, "message": "Database connection error."}), 500
    
    try:
        with conn.cursor() as cur:
            # The ON CONFLICT syntax is compatible with PostgreSQL. Just change placeholder.
            cur.execute(
                """
                INSERT INTO settings (society_name, max_candidates_selection) VALUES (%s, %s)
                ON CONFLICT(society_name) DO UPDATE SET max_candidates_selection = excluded.max_candidates_selection
                """,
                (society_name, max_selection)
            )
        conn.commit()
        return jsonify({"success": True, "message": "Maximum selection updated."})
    except (Exception, psycopg2.DatabaseError) as e:
        conn.rollback()
        app.logger.error(f"Error updating max selection: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/set-voting-time', methods=['POST'])
@login_required
def set_voting_time():
    society_name = session.get('society_name')
    if not society_name:
        return jsonify({"success": False, "message": "Admin session not found."}), 401
    
    data = request.get_json()
    start_time_str = data.get('startTime')
    end_time_str = data.get('endTime')
    
    if not start_time_str or not end_time_str:
        return jsonify({"success": False, "message": "Start and end times are required."}), 400

    conn = get_db()
    if not conn:
        return jsonify({"success": False, "message": "Database connection error."}), 500
        
    try:
        # 1. Parse strings into timezone-aware datetime objects (UTC)
        # The .replace('Z', '+00:00') handles the 'Z' (Zulu) notation for fromisoformat
        start_time_utc = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
        end_time_utc = datetime.fromisoformat(end_time_str.replace('Z', '+00:00'))
        
        # 2. ✅ CRITICAL SERVER-SIDE CHECK: Compare the two UTC objects
        if end_time_utc <= start_time_utc:
                return jsonify({
                "success": False, 
                "message": "Voting end time can't be before start time."
            }), 400
            
        with conn.cursor() as cur:
            # 3. Use the Python datetime objects for execution (Best Practice for psycopg2)
            cur.execute(
                """
                INSERT INTO voting_schedule (society_name, start_time, end_time) VALUES (%s, %s, %s)
                ON CONFLICT (society_name) DO UPDATE SET start_time = EXCLUDED.start_time, end_time = EXCLUDED.end_time
                """,
                # Pass the UTC datetime objects to psycopg2
                (society_name, start_time_utc, end_time_utc) 
            )
        conn.commit()
        return jsonify({"success": True, "message": "Voting schedule updated."})
        
    except (ValueError, TypeError):
        # This catches errors if the strings aren't valid ISO formats
        return jsonify({"success": False, "message": "Invalid date format."}), 400
    except (Exception, psycopg2.DatabaseError) as e:
        conn.rollback()
        app.logger.error(f"Error setting voting time: {e}", exc_info=True)
        return jsonify({"success": False, "message": "A server error occurred."}), 500
    finally:
        if conn:
            conn.close()

@app.route("/api/verify_code", methods=["POST"])
def verify_code():
    data = request.get_json()
    society_name = data.get('society')
    tower = data.get('tower')
    flat = data.get('flat')
    secret_code = data.get('secret_code')

    if not all([society_name, tower, flat, secret_code]):
        return jsonify({"success": False, "message": "All fields are required."}), 400

    conn = get_db()
    if not conn:
        return jsonify({"success": False, "message": "Could not connect to the database."}), 500

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT start_time, end_time FROM voting_schedule WHERE society_name = %s", (society_name,))
            schedule = cur.fetchone()

            if not schedule or not schedule['start_time'] or not schedule['end_time']:
                return jsonify({"success": False, "message": "Voting schedule not configured."}), 403

            current_time_utc = datetime.now(pytz.utc)
            start_time_utc = datetime.fromisoformat(schedule['start_time'].replace('Z', '+00:00'))
            end_time_utc = datetime.fromisoformat(schedule['end_time'].replace('Z', '+00:00'))
            
            if not (start_time_utc <= current_time_utc < end_time_utc):
                return jsonify({"success": False, "message": "Voting is closed."}), 403

            cur.execute(
                "SELECT * FROM households WHERE society_name = %s AND tower = %s AND flat = %s AND secret_code = %s",
                (society_name, tower, flat, secret_code)
            )
            household = cur.fetchone()

            if not household:
                return jsonify({"success": False, "message": "Invalid credentials."}), 401
            
            VOTED_FLAG = 1
            if household['voted_in_cycle'] == VOTED_FLAG:
                return jsonify({"success": False, "message": "This household has already voted."}), 403

            if household['is_admin_blocked']:
                return jsonify({"success": False, "message": "This household is blocked."}), 403
            if not household['is_vote_allowed']:
                return jsonify({"success": False, "message": "This household is not allowed to vote."}), 403

            session['household_id'] = household['id']
            return jsonify({"success": True, "message": "Verification successful."})

    except (Exception, psycopg2.DatabaseError) as e:
        app.logger.error(f"FATAL ERROR in /api/verify_code: {e}", exc_info=True)
        return jsonify({"success": False, "message": f"A critical server error occurred: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/upload-secret-codes', methods=['POST'])
@login_required
def upload_secret_codes():
    file = request.files.get('secretCodes')
    society_name = session.get('society_name')

    if not society_name:
        flash("Society not set in session.", "danger")
        return redirect(url_for("admin_panel"))

    if not file or not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in ['xlsx', 'xls']):
        flash("Invalid or missing Excel file.", "danger")
        return redirect(url_for("admin_panel"))

    conn = get_db()
    if not conn:
        flash("Database connection error.", "danger")
        return redirect(url_for("admin_panel"))

    try:
        df = pd.read_excel(file, dtype=str).fillna('')
        updates = []

        with conn.cursor() as cur:
            # --- Detect housing type ---
            cur.execute("SELECT housing_type FROM admins WHERE society_name = %s", (society_name,))
            row = cur.fetchone()
            housing_type = row[0] if row else ''
            print(f"Detected housing_type for {society_name}: {housing_type}")

            for _, r in df.iterrows():
                tower = str(r.get('Tower', '')).strip().upper()
                flat = str(r.get('Flat', '')).strip()
                secret_code = str(r.get('SecretCode', '')).strip()
                if not secret_code or not flat:
                    continue

                # --- Matching logic based on housing type ---
                if housing_type.startswith("Apartment"):
                    cur.execute(
                        """SELECT 1 FROM households
                           WHERE TRIM(UPPER(society_name))=%s AND TRIM(UPPER(tower))=%s AND TRIM(flat)=%s""",
                        (society_name.strip().upper(), tower, flat)
                    )
                    if cur.fetchone():
                        updates.append((secret_code, society_name.strip(), tower, flat))

                elif housing_type.startswith("Villas-Lanes"):
                    cur.execute(
                        """SELECT 1 FROM households
                           WHERE TRIM(UPPER(society_name))=%s AND TRIM(UPPER(tower))=%s AND TRIM(flat)=%s""",
                        (society_name.strip().upper(), tower, flat)
                    )
                    if cur.fetchone():
                        updates.append((secret_code, society_name.strip(), tower, flat))

                elif housing_type.startswith("Villas-No Lanes") or housing_type.startswith("Civil"):
                    # Tower ignored
                    cur.execute(
                        """SELECT 1 FROM households
                           WHERE TRIM(UPPER(society_name))=%s AND TRIM(flat)=%s""",
                        (society_name.strip().upper(), flat)
                    )
                    if cur.fetchone():
                        updates.append((secret_code, society_name.strip(), flat))

            # --- Perform updates ---
            if updates:
                if housing_type.startswith(("Villas-No Lanes", "Civil")):
                    cur.executemany(
                        "UPDATE households SET secret_code=%s WHERE TRIM(UPPER(society_name))=%s AND TRIM(flat)=%s",
                        updates
                    )
                else:
                    cur.executemany(
                        "UPDATE households SET secret_code=%s WHERE TRIM(UPPER(society_name))=%s AND TRIM(UPPER(tower))=%s AND TRIM(flat)=%s",
                        updates
                    )

                conn.commit()
                flash(f"Successfully updated secret codes for {len(updates)} households.", "success")
            else:
                flash("No matching rows found to update.", "warning")

    except (Exception, psycopg2.DatabaseError) as e:
        conn.rollback()
        app.logger.error(f"Error processing secret codes file: {e}")
        flash(f"Error processing file: {e}", "danger")
    finally:
        if conn:
            conn.close()

    return redirect(url_for("admin_panel"))

@app.route('/manage-contestants', methods=['GET', 'POST'])
@login_required
def manage_contestants():
    society_name = session.get('society_name')

    if request.method == 'POST':
        try:
            with get_db() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                    action = request.form.get('action')
                    tower = request.form.get('tower')
                    flat = request.form.get('flat')

                    if action == 'add':
                        contestant_name = request.form.get('contestant_name', '').strip()
                        symbol_file = request.files.get('contestant_symbol')
                        photo_file = request.files.get('contestant_photo')

                        # --- Validation ---
                        if not all([tower, flat, contestant_name]):
                            flash("Tower, Flat, and Contestant Name are required.", "danger")
                            return redirect(url_for('manage_contestants'))

                        if not symbol_file or symbol_file.filename == '':
                            flash("Contestant symbol image is required.", "danger")
                            return redirect(url_for('manage_contestants'))

                        symbol_path, photo_b64_string = None, None

                        if symbol_file and allowed_file(symbol_file.filename):
                            filename = secure_filename(f"{tower}_{flat}_{symbol_file.filename}")
                            symbol_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                            symbol_path = filename

                        if photo_file and allowed_file(photo_file.filename):
                            mime_type = photo_file.mimetype or 'image/jpeg'
                            encoded_string = base64.b64encode(photo_file.read()).decode('utf-8')
                            photo_b64_string = f"data:{mime_type};base64,{encoded_string}"

                        # --- Update households ---
                        cur.execute(
                            """
                            UPDATE households
                            SET is_contestant = 1, contestant_name = %s,
                                contestant_symbol = %s, contestant_photo_b64 = %s
                            WHERE society_name = %s AND tower = %s AND flat = %s
                            """,
                            (contestant_name, symbol_path, photo_b64_string, society_name, tower, flat)
                        )

                        # --- Insert into votes ---
                        cur.execute(
                            """
                            INSERT INTO votes (society_name, tower, contestant_name, is_archived, vote_count)
                            VALUES (%s, %s, %s, %s, 0)
                            ON CONFLICT (society_name, tower, contestant_name, is_archived) DO NOTHING
                            """,
                            (society_name, tower, contestant_name, 0)
                        )

                        flash(f"Contestant '{contestant_name}' added successfully.", "success")

                    elif action == 'remove':
                        cur.execute(
                            "SELECT contestant_name FROM households WHERE society_name = %s AND tower = %s AND flat = %s",
                            (society_name, tower, flat)
                        )
                        contestant_to_remove = cur.fetchone()

                        cur.execute(
                            """
                            UPDATE households
                            SET is_contestant = 0, contestant_name = NULL,
                                contestant_symbol = NULL, contestant_photo_b64 = NULL
                            WHERE society_name = %s AND tower = %s AND flat = %s
                            """,
                            (society_name, tower, flat)
                        )

                        if contestant_to_remove and contestant_to_remove['contestant_name']:
                            cur.execute(
                                "DELETE FROM votes WHERE society_name = %s AND contestant_name = %s AND is_archived = 0",
                                (society_name, contestant_to_remove['contestant_name'])
                            )
                            flash(f"Contestant '{contestant_to_remove['contestant_name']}' removed successfully.", "success")

        except (Exception, psycopg2.DatabaseError) as e:
            app.logger.error(f"Error managing contestants: {e}")
            flash("A database error occurred while updating contestants.", "danger")

        return redirect(url_for('manage_contestants'))

    # --- GET Request ---
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    """
                    SELECT tower, flat, is_contestant, contestant_name, contestant_symbol, contestant_photo_b64
                    FROM households
                    WHERE society_name = %s
                    ORDER BY tower, flat
                    """,
                    (society_name,)
                )
                all_households = cur.fetchall()

                available_households_dict = defaultdict(list)
                contestants = []
                unique_towers = sorted(list(set(h['tower'] for h in all_households)))

                for h in all_households:
                    if h['is_contestant']:
                        contestants.append(h)
                    else:
                        available_households_dict[h['tower']].append(h['flat'])

                return render_template(
                    "manage_contestants.html",
                    towers=unique_towers,
                    households_by_tower_json=json.dumps(available_households_dict),
                    contestants=contestants
                )

    except (Exception, psycopg2.DatabaseError) as e:
        app.logger.error(f"Error fetching contestant data: {e}")
        flash("Error loading page data from the database.", "danger")
        return render_template(
            "manage_contestants.html",
            towers=[],
            households_by_tower_json='{}',
            contestants=[]
        )
             
@app.route('/view-results')
@login_required
def view_results():
    society_name = session.get('society_name')
    voting_status = get_voting_status(society_name)

    if voting_status == 'ACTIVE':
        flash("Voting is in progress! Results are available after it concludes.", "danger")
        return redirect(url_for('admin_panel'))
    elif voting_status not in ['CLOSED', 'NOT_STARTED']:
        flash("Voting schedule is not properly configured.", "danger")
        return redirect(url_for('admin_panel'))

    conn = get_db()
    if not conn:
        flash("Database connection error.", "danger")
        return redirect(url_for('admin_panel'))

    results, contestant_details, schedule = [], {}, None
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            current_cycle = 0
            query = """
            SELECT contestant_name, tower, vote_count FROM votes
            WHERE society_name = %s AND is_archived = %s ORDER BY tower, vote_count DESC;
            """
            cur.execute(query, (society_name, current_cycle))
            results = cur.fetchall()

            cur.execute(
                "SELECT contestant_name, contestant_symbol, contestant_photo_b64 FROM households WHERE society_name = %s AND is_contestant = 1",
                (society_name,)
            )
            contestant_details = {row['contestant_name']: {'symbol': row['contestant_symbol'], 'photo': row['contestant_photo_b64']} for row in cur.fetchall()}

            cur.execute("SELECT start_time, end_time FROM voting_schedule WHERE society_name = %s", (society_name,))
            schedule = cur.fetchone()
    except (Exception, psycopg2.DatabaseError) as e:
        app.logger.error(f"Error fetching results data: {e}")
      #  flash("Error loading results.", "danger")
    finally:
        if conn:
            conn.close()

    election_date, start_time_iso = "Not Set", None
    if schedule:
        try:
            if schedule['end_time']:
                end_time_utc = datetime.fromisoformat(schedule['end_time'].replace('Z', '+00:00'))
                end_time_ist = end_time_utc.astimezone(pytz.timezone('Asia/Kolkata'))
                election_date = end_time_ist.strftime('%d-%b-%Y')
            start_time_iso = schedule['start_time']
        except Exception:
            election_date = "Invalid Date"

    result_data = defaultdict(list)
    for row in results:
        details = contestant_details.get(row['contestant_name'], {})
        result_data[row['tower']].append({
            "name": row['contestant_name'], "symbol": details.get('symbol'),
            "photo": details.get('photo'), "vote_count": row['vote_count']
        })

    return render_template(
        "view_results.html", results=result_data, society_name=society_name,
        election_date=election_date, voting_status=voting_status, voting_start=start_time_iso
    )

@app.route('/view-voted-flats')
@login_required
def view_voted_flats():
    society_name = session.get('society_name')
    voting_status = get_voting_status(society_name)

    if voting_status == 'ACTIVE':
        flash("Voted flats list is only available after the election concludes.", "danger")
        return redirect(url_for('admin_panel'))
    elif voting_status not in ['CLOSED', 'NOT_STARTED']:
        flash("Voting schedule is not properly configured.", "danger")
        return redirect(url_for('admin_panel'))

    conn = get_db()
    voting_start = None
    if conn:
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SELECT start_time FROM voting_schedule WHERE society_name = %s", (society_name,))
                schedule = cur.fetchone()
                if schedule: voting_start = schedule['start_time']
        except (Exception, psycopg2.DatabaseError) as e:
            app.logger.error(f"Error fetching schedule for voted flats view: {e}")
        finally:
            conn.close()
            
    return render_template(
        "view_voted_flats.html", voting_status=voting_status,
        voting_start=voting_start, society_name=society_name 
    )

@app.route('/get-voted-flats-data')
@login_required
def get_voted_flats_data():
    society_name = session.get('society_name')
    data = []
    conn = get_db()
    if conn:
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                VOTED_FLAG = 1
                cur.execute("SELECT tower, flat FROM households WHERE voted_in_cycle = %s AND society_name = %s ORDER BY tower, flat", (VOTED_FLAG, society_name))
                data = [f"{r['tower']}-{r['flat']}" for r in cur.fetchall()]
        except (Exception, psycopg2.DatabaseError) as e:
            app.logger.error(f"Error fetching voted flats data: {e}")
        finally:
            conn.close()
    return jsonify(data)

@app.route('/reset_votes', methods=['POST'])
@login_required
def reset_votes():
    # Check if the user is authorized (Admin or Super Admin)
    is_authorized = current_user.role == 'admin' or current_user.is_super_admin
    
    if not is_authorized:
        return jsonify({'success': False, 'message': 'Permission denied. Only Admin or Super Admin can perform this action.'}), 403

    society_name = session.get('society_name')
    if not society_name:
        return jsonify({'success': False, 'message': 'Session expired. Society context is missing.'}), 403

    password = request.json.get('password')
    if not password:
        return jsonify({'success': False, 'message': 'Password is required.'}), 400

    conn = get_db()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection error.'}), 500

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # Verify password based on role
            if current_user.is_super_admin:
                cur.execute("SELECT password_hash FROM admins WHERE role = %s", ('super_admin',))
            else:
                cur.execute("SELECT password_hash FROM admins WHERE id = %s", (current_user.id,))
            
            admin_row = cur.fetchone()

            if not admin_row or not bcrypt.checkpw(password.encode('utf-8'), bytes(admin_row['password_hash'])):
                return jsonify({'success': False, 'message': 'The entered password is not correct.'}), 401

            # Archive handling based on user role
            if current_user.is_super_admin:
                # Super Admin: Increment archive level each time
                cur.execute("SELECT MAX(is_archived) AS max_val FROM votes WHERE society_name = %s", (society_name,))
                max_archive_row = cur.fetchone()
                next_archive_num = (max_archive_row['max_val'] or 0) + 1
                cur.execute(
                    "UPDATE votes SET is_archived = %s WHERE society_name = %s AND is_archived = 0",
                    (next_archive_num, society_name)
                )
            else:
                # Standard Admin: Always mark archive as 1 (fresh reset)
                cur.execute(
                    "UPDATE votes SET is_archived = 1 WHERE society_name = %s AND is_archived = 0",
                    (society_name,)
                )

            # Reset voting state (keep contestants intact)
            cur.execute("UPDATE households SET voted_in_cycle = 0 WHERE society_name = %s", (society_name,))
            cur.execute("UPDATE settings SET voted_count = 0 WHERE society_name = %s", (society_name,))

        conn.commit()
        return jsonify({'success': True, 'message': "Election has been reset successfully. All votes have been cleared."})

    except (Exception, psycopg2.DatabaseError) as e:
        conn.rollback()
        app.logger.error(f"Error during reset: {e}")
        return jsonify({'success': False, 'message': f"Error during reset: {e}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/get-voted-flats-grid-data')
@login_required
def get_voted_flats_grid_data():
    society_name = session.get('society_name')
    conn = get_db()
    if not conn:
        return jsonify({"towers": [], "all_possible_flats": [], "existing_flats": [], "voted_flats": []})

    all_households = []
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT tower, flat, voted_in_cycle FROM households WHERE society_name = %s", (society_name,))
            all_households = cur.fetchall()
    except (Exception, psycopg2.DatabaseError) as e:
        app.logger.error(f"Error fetching grid data: {e}")
    finally:
        if conn:
            conn.close()

    if not all_households:
        return jsonify({"towers": [], "all_possible_flats": [], "existing_flats": [], "voted_flats": []})

    towers = sorted(list({row['tower'] for row in all_households}))
    all_possible_flats = sorted(list({row['flat'] for row in all_households}), key=lambda x: int(x) if x.isdigit() else 9999)
    existing_flats = {f"{row['tower']}-{row['flat']}" for row in all_households}
    voted_flats = {f"{row['tower']}-{row['flat']}" for row in all_households if row['voted_in_cycle'] == 1}
    
    return jsonify({
        "towers": towers,
        "all_possible_flats": all_possible_flats,
        "existing_flats": list(existing_flats),
        "voted_flats": list(voted_flats)
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)