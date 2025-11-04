from flask import Flask, render_template, request, redirect, url_for, flash, session
import psycopg2
import psycopg2.extras
from psycopg2 import OperationalError
import uuid
from datetime import datetime, timedelta
import os 
from dotenv import load_dotenv
from functools import wraps
from constants import house_type 
import secrets 
import pytz 
#from flask_mail import Mail, Message 
import requests
from flask import make_response
# -------------------------
# --- FIX: Import hashing functions ---
from werkzeug.security import generate_password_hash, check_password_hash
# ------------------------- 
# Define your local timezone (assuming IST)
IST = pytz.timezone('Asia/Kolkata') 

# --- Load environment variables ---
load_dotenv()

# --- DATABASE CONFIGURATION ---
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

# --- FLASK APP SETUP ---
app = Flask(__name__)

# --- SECRET KEY (used for session & flash security) ---
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))

# --- EMAIL CONFIGURATION ---
#app.config.update(
#    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
#    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
#    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True').lower() in ['true', 'on', '1'],
#    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
#    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
#    MAIL_DEFAULT_SENDER=os.getenv('MAIL_USERNAME')  # ✅ ensure sender is set
#)
RESEND_API_URL = "https://api.resend.com/emails"
RESEND_API_KEY = os.getenv("RESEND_API_KEY")

#mail = Mail(app)
EMAIL_FROM = os.getenv('MAIL_USERNAME')

# --- SYSTEM CONSTANTS (optional tracking) ---
SYSTEM_ADMIN_ID = '_SYSTEM_'  # for internal audit tracking if used elsewhere

# --- INITIAL SUPER ADMIN SETUP (FIX: Hashing enabled) ---
DEFAULT_SUPER_ADMIN_PASSWORD = os.getenv("DEFAULT_SUPER_ADMIN_PASSWORD")
# --- FIX: Generate a hash from the plain text password ---
DEFAULT_SUPER_ADMIN_HASH = generate_password_hash(DEFAULT_SUPER_ADMIN_PASSWORD)
# -------------------------------------------------------------

def get_current_user():
    """Retrieves basic user info (role) from the session for simple access checks."""
    user_id = session.get('user_id')
    if user_id == SYSTEM_ADMIN_ID:
        return {'id': SYSTEM_ADMIN_ID, 'role': 'SUPER_ADMIN'}
    return None


def super_admin_required(f):
    """Decorator to check if the current user is logged in as the Super Admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') != SYSTEM_ADMIN_ID:
            flash('Access denied: Super Admin credentials required.', 'error')
            # Note: super_admin_login route is missing, using dashboard as fallback
            return redirect(url_for('super_admin_dashboard')) 
        return f(*args, **kwargs)
    return decorated_function
 
def admin_required(f):
    """Custom decorator to check if the user is authenticated."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if user is None:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('super_admin_dashboard', next=request.url))
        
        if user['role'] != 'SUPER_ADMIN':
            flash("🚫 Access denied.", 'error')
            return redirect(url_for('logout')) 
            
        return f(*args, **kwargs)
    return decorated_function


# --- Database Connection Function ---
def get_db_conn():
    """Establishes and returns a PostgreSQL database connection using environment variables."""
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        conn.autocommit = False 
        return conn
    except OperationalError as e:
        # Since app.logger is not available in all contexts, raising a custom error or printing is necessary
        raise ConnectionError("Could not connect to the database. Check .env settings.")

# --- Email Sending Functions (No change here, standard Flask-Mail) --- 
## 🛠️ Corrected Brevo Email Function

def send_email_brevo(to_email, subject, body):
    """Send email using Brevo API (with robust HTML and error handling)."""
    # NOTE: You MUST have 'requests' imported for this function to work.
    brevo_api_key = os.getenv("BREVO_API_KEY")
    
    if not brevo_api_key:
        print("⚠️ No Brevo API key found — simulation mode.")
        print("To:", to_email)
        print("Subject:", subject)
        print("Body:\n", body)
        return True  # Simulate success if key is missing

    # 1. ✅ FIX FOR EMPTY BODY: Convert plain text newlines (\n) to HTML break tags (<br>)
    html_content_with_br = body.replace('\n', '<br>')  # For HTML clients

    # 2. Wrap the <br> content in a standard HTML body
    html_body = f"<html><body style='font-family:Arial,sans-serif;'>{html_content_with_br}</body></html>"

    try:
        url = "https://api.brevo.com/v3/smtp/email"
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": brevo_api_key
        }

        payload = {
            "sender": {"name": "SIVA Admin", "email": "siva.admn25@gmail.com"},
            "to": [{"email": to_email}],
            "subject": subject,
            # Pass original body for text-only clients
            "textContent": body,  # Plain-text content
            "htmlContent": html_body  # HTML content for HTML-capable email clients
        }

        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code in (200, 201):
            print(f"✅ Email sent to {to_email} via Brevo")
            return True
        else:
            # 💡 CRITICAL LOG: Captures API key (401) or bad request errors (400)
            print(f"❌ Brevo API failed: {response.status_code}, {response.text}")
            return False

    except Exception as e:
        # 💡 CRITICAL LOG: Captures connection, network, or import errors
        print(f"❌ send_email_brevo exception: {e}") 
        return False 
        
def send_final_approval_email(recipient_email, society_name):
    """Send the final approval email after society approval."""
    subject = f"✅ Your Society Application ({society_name}) Has Been Approved"
    
    # Create the plain text body
    body = f"""Dear Admin of {society_name},

        Access the admin activities URL: https://siva-admin-activities.onrender.com/system-entry
        If you have any questions, please feel free to contact by replying us.

    Sincerely,
    SIVA Admin Team.""" .strip()

    # Wrap the body in HTML for HTML email clients
    html_body = f"<html><body style='font-family:Arial,sans-serif;'>{body.replace('\n', '<br>')}</body></html>"

    # Send the email using the Brevo API
    email_sent = send_email_brevo(recipient_email, subject, body)  # Send both plain text and HTML versions

    if email_sent:
        return True
    else:
        flash("🚨 Error while sending the final approval email.", 'error')
        return False
 
def send_invite_email(recipient_email, society_name, invite_token, registration_link):
    """Send registration invitation email (Resend or simulate)."""
    subject = f"Registration Invitation for {society_name}"
    body = f"""Dear Admin of {society_name},

Your registration request has been approved!

Please use the link below to complete your society's registration and set up your Super Admin account:

{registration_link}

This link is valid for 2 days. If you have any issues, please contact system support.

Thank you,
The Election Management System Team
""".strip()  # <-- FIX 2A: Added .strip() to clean string
    
    return send_email_brevo(recipient_email, subject, body)
  
def send_rejection_email(recipient_email, society_name, reason=None):
    """Send rejection email (Resend or simulate)."""
    subject = f"❌ Your Society Application ({society_name}) Has Been Rejected"
    body = f"""Dear Admin of {society_name},

We regret to inform you that your registration request for '{society_name}' has been rejected.

{f"Reason: {reason}" if reason else ""}

If you have any questions or believe this was a mistake, please contact the system support team.

Sincerely,
SIVA Admin Team.
""".strip()  # <-- FIX 2C: Added .strip() to clean string
    
    return send_email_brevo(recipient_email, subject, body)

def generate_invite_from_request(request_data, conn):
    """Generates an invitation token, saves it to new_admins (as a placeholder invite), and updates request status."""
    token = secrets.token_urlsafe(32)
    # Set expiry 2 days from now, using the defined IST timezone
    invite_end_at = datetime.now(IST) + timedelta(days=2) 
    
    # --- FIX: Hash the dummy password ---
    DUMMY_HASH = generate_password_hash('dummy_pass_placeholder')
    # ------------------------------------

    with conn.cursor() as cur:
        # 1. Insert into new_admins (as placeholder invite)
        cur.execute(
            """INSERT INTO new_admins (
                   society_name, role, mobile_number, email, password_hash, invite_token, 
                   invite_end_at, max_voters, housing_type, review_status, is_towerwise
               ) 
               VALUES (UPPER(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);""",
            (
                f"INVITE_{request_data['society_name']}", # Using a prefix for society_name as a placeholder
                'admin', 
                request_data['mobile_number'], 
                request_data['email'], 
                DUMMY_HASH, # Hashing preserved
                token, 
                invite_end_at,
                1, # Min required value
                'Apartment-Single Tower', 
                'new_invitation', 
                False
            )
        )
        # 2. Update registration_requests status to approved
        cur.execute("UPDATE registration_requests SET status = 'approved' WHERE id = %s", (request_data['id'],))
        
    return token

# --- INITIAL SETUP HOOK ---
def ensure_super_admin_exists():
    """Checks and creates the initial System Admin record if the table is empty."""
    conn = None
    try:
        conn = get_db_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute("SELECT * FROM admins WHERE society_name = %s;", (SYSTEM_ADMIN_ID,))
        super_admin_record = cursor.fetchone()

        if super_admin_record:
            return True

        cursor.execute("SELECT COUNT(*) FROM admins;")
        count = cursor.fetchone()[0]

        if count == 0:            
            cursor.execute("""
                INSERT INTO admins (
                    society_name, role, password_hash, email, max_voters 
                ) VALUES (%s, %s, %s, %s, %s);
            """, (
                SYSTEM_ADMIN_ID, 
                'super_admin', 
                # --- FIX: Insert the HASH generated at startup ---
                DEFAULT_SUPER_ADMIN_HASH, # Pass the hash
                # --------------------------------------------------
                'system_placeholder@internal.com', 
                1666
            ))
            conn.commit()
            return True
        
        return True 

    except OperationalError:
        return False
    except Exception as e:
        if conn: conn.rollback()
        # app.logger.error(f"Error in ensure_super_admin_exists: {e}")
        return False
    finally:
        if conn: conn.close()
 
@app.route('/super_admin/dashboard', methods=['GET', 'POST'])
def super_admin_dashboard():
    """
    Handles System Admin Login (POST) and displays the Dashboard (GET, authenticated).
    Renders the login form when unauthenticated (GET).
    """ 
    user = get_current_user()
    is_authenticated = user is not None
    ensure_super_admin_exists()
     
    # --- STEP 1: HANDLE LOGIN POST REQUEST ---
    if request.method == 'POST' and not is_authenticated:
        password = request.form.get('password')
        conn = None 
        user_record = None
        
        try:
            conn = get_db_conn()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cursor.execute(
                "SELECT society_name, password_hash, role FROM admins WHERE society_name = %s;", 
                (SYSTEM_ADMIN_ID,)
            )
            user_record = cursor.fetchone()
        except Exception as e: 
            flash(f'Database error during login: {e}', 'error')
            resp = make_response(render_template('super_admin_dashboard.html', is_authenticated=False))
        finally:
            if conn: conn.close()

        if user_record and password:
            stored_hash = user_record['password_hash']
            # --- FIX: Check hashed password ---
            if check_password_hash(stored_hash, password):
            # --------------------------------
                session['user_id'] = SYSTEM_ADMIN_ID
                flash(f'Login successful. Welcome, {user_record["role"]}!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('super_admin_dashboard'))

        flash('Invalid Password.', 'error')
        resp = make_response(render_template('super_admin_dashboard.html', is_authenticated=False))

        # Anti-cache headers for login page
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp

    # --- STEP 2: HANDLE AUTHENTICATED REQUESTS (GET or POST for invite creation) ---
    if is_authenticated: 
        conn = None
        pending_approvals = [] 
        active_invites = []    
        pending_requests = []
        societies = [] 
        
        # Handle POST for Invitation Creation
        if request.method == 'POST':
            token = secrets.token_urlsafe(32) 
            dummy_society_name = f"PLACEHOLDER_{uuid.uuid4().hex[:8]}" 
            dummy_email = f"dummy_{uuid.uuid4().hex[:8]}@invite.com"
            invite_end_time = datetime.now(IST) + timedelta(days=2)
            DUMMY_MOBILE = '9999999999'
            # --- FIX: Hash the dummy password ---
            DUMMY_HASH = generate_password_hash('dummy_pass')  
            # ------------------------------------
            try:
                conn = get_db_conn()
                cursor = conn.cursor()
                cursor.execute(""" 
                    INSERT INTO new_admins (
                        society_name, role, mobile_number, email, password_hash, invite_token, 
                        invite_end_at, max_voters, housing_type, review_status, is_towerwise
                    ) 
                    VALUES (UPPER(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """, (
                    dummy_society_name, 
                    'admin', 
                    DUMMY_MOBILE, 
                    dummy_email, 
                    DUMMY_HASH, # Insert the hash
                    token, 
                    invite_end_time,
                    2, 
                    'xyz', 
                    'new_invitation', 
                    False 
                ))
                conn.commit()
                flash(f"✅ New invitation created. Token: {token[:8]}... Link generated.", 'success')
            except Exception as e: 
                if conn: conn.rollback()
                flash(f"DB INSERT FAILED: {e}", 'error')
            finally:
                if conn: conn.close()
            return redirect(url_for('super_admin_dashboard')) 
                
        # Handle GET (View Dashboard Data)
        try:
            conn = get_db_conn()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            
            cursor.execute("""
                SELECT id, society_name, email, mobile_number, submitted_at
                FROM registration_requests 
                WHERE status = 'pending' 
                ORDER BY submitted_at ASC
            """)
            pending_requests = cursor.fetchall()
            
            cursor.execute(""" 
                SELECT society_name, email, mobile_number, max_voters, housing_type, is_towerwise, responded_at
                FROM new_admins 
                WHERE review_status = 'submitted_for_review' 
                AND responded = TRUE
                ORDER BY responded_at DESC;
            """)
            pending_approvals = cursor.fetchall()
            
            cursor.execute(""" 
                SELECT society_name, invite_token, invited_at, invite_end_at, email
                FROM new_admins 
                WHERE responded = FALSE 
                AND review_status = 'new_invitation' 
                ORDER BY invited_at DESC;
            """)
            active_invites = cursor.fetchall()
        
            cursor.execute("""
                SELECT DISTINCT society_name FROM new_admins 
                WHERE role = 'admin' 
                ORDER BY society_name;
            """)
            societies = [row[0] for row in cursor.fetchall()]

        except Exception as e:
            flash(f"Database Error retrieving dashboard data: {e}", 'error')
            app.logger.error(f"Dashboard Data Fetch Error: {e}")
        finally:
            if conn: conn.close()

        base_url = ""  
        return render_template('super_admin_dashboard.html', 
                               is_authenticated=True, 
                               pending_approvals=pending_approvals, 
                               active_invites=active_invites,
                               pending_requests=pending_requests,
                               societies=societies, 
                               base_url=base_url)

    # --- STEP 3: HANDLE UNAUTHENTICATED GET REQUESTS ---
    else:
        resp = make_response(render_template('super_admin_dashboard.html', is_authenticated=False))
        # Anti-cache headers to prevent back button from showing cached dashboard
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp

@app.route('/super_admin/erase_society', methods=['POST'])
@super_admin_required
def erase_society():
    """
    Handles executing the master erase deletion (POST).
    """
    conn = None
    
    # --- POST LOGIC: EXECUTE DELETION ---
    society_name = request.form.get('society_name')
    if not society_name:
        flash("🚫 Error: Society name is missing for master erase.", 'error')
        return redirect(url_for('super_admin_dashboard'))

    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        
        # Start Transaction
        conn.autocommit = False 

        # Whitelist tables for safety
        simple_delete_tables = ['admins', 'households', 'new_admins', 'settings', 'registration_requests']
        conditional_delete_tables = {'votes': "is_archived = 0"}
        
        deleted_count = 0
        
        # 1. Execute simple deletions
        for table in simple_delete_tables:
            delete_query = f"DELETE FROM {table} WHERE society_name = %s;"
            cursor.execute(delete_query, (society_name,))
            deleted_count += cursor.rowcount
            
        # 2. Execute conditional deletions (Votes table)
        for table, condition in conditional_delete_tables.items():
            delete_query = f"DELETE FROM {table} WHERE society_name = %s AND {condition};"
            cursor.execute(delete_query, (society_name,))
            deleted_count += cursor.rowcount
        
        # Final check and commit/rollback
        total_tables_hit = len(simple_delete_tables) + len(conditional_delete_tables)
        if deleted_count == 0:
            flash(f"⚠️ Error: Society '{society_name}' found, but no non-archived data was deleted from {total_tables_hit} tables.", 'warning')
            conn.rollback()
        else:
            conn.commit()
            flash(f"🔥 MASTER ERASE COMPLETE: **{deleted_count} records** for society **{society_name}** permanently deleted.", 'success')
            
    except Exception as e:
        if conn: conn.rollback()
        flash(f"🚨 FATAL ERROR during master erase for '{society_name}': {e}", 'error')

    finally:
        # Correct cleanup: Reset autocommit to default BEFORE closing connection.
        if conn: 
            conn.autocommit = True
            conn.close()

        return redirect(url_for('super_admin_dashboard'))
    
@app.route('/approve_request/<int:request_id>', methods=['POST'])
@admin_required
def approve_request(request_id):
    conn = None
    try:
        conn = get_db_conn()
        if not conn:
            flash('Database connection error.', 'error')
            return redirect(url_for('super_admin_dashboard'))

        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # Retrieve pending request
            cur.execute(
                """
                SELECT id, society_name, email, mobile_number
                FROM registration_requests
                WHERE id = %s AND status = 'pending'
                """,
                (request_id,)
            )
            request_data = cur.fetchone()

        if not request_data:
            flash("Request not found or already processed.", 'error')
            return redirect(url_for('super_admin_dashboard'))

        # --- TRIM INVITE_ PREFIX FROM SOCIETY NAME ---
        clean_society_name = request_data['society_name'].removeprefix('INVITE_')

        # --- GENERATE INVITE TOKEN USING CLEAN NAME ---
        invite_token = generate_invite_from_request(
            {**dict(request_data), 'society_name': clean_society_name},
            conn
        )
        conn.commit()

        # --- SEND EMAIL WITH CLEAN NAME (FIXED URL) ---
        registration_link = url_for('open_invite', token=invite_token, _external=True)

        email_sent = send_invite_email(
            request_data['email'],
            clean_society_name,
            invite_token, # Pass the generated token
            registration_link # Pass the full dynamic URL as the final argument
        )

        email_status = (
            "and **Email Sent** 📧" if email_sent
            else "but **Email Failed** ❌ (Check server logs)"
        )

        # --- FLASH MESSAGE ---
        flash(
            f"✅ Approved request for **{clean_society_name}**.<br>"
            f"Invite Link: <a href='{registration_link}' target='_blank'>{registration_link}</a><br>"
            f"Email Status: {email_status}",
            'success'
        )

    except Exception as e:
        app.logger.error(f"Approval error for request {request_id}: {e}")
        if conn:
            conn.rollback()
        flash('An error occurred during approval and invite generation. Please check server logs.', 'error')

    finally:
        if conn:
            conn.close()

    return redirect(url_for('super_admin_dashboard'))

@app.route('/reject_request/<int:request_id>', methods=['POST'])
@admin_required
def reject_request(request_id):
    conn = None
    try:
        conn = get_db_conn()
        if not conn:
            flash('Database connection error.', 'error')
            return redirect(url_for('super_admin_dashboard'))

        request_data = None
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # Fetch request details before updating
            cur.execute(
                "SELECT society_name, email FROM registration_requests WHERE id = %s AND status = 'pending'", 
                (request_id,)
            )
            request_data = cur.fetchone()

            # Update status to 'rejected'
            cur.execute(
                "UPDATE registration_requests SET status = 'rejected' WHERE id = %s AND status = 'pending'", 
                (request_id,)
            )

            if cur.rowcount == 0:
                flash("Request not found or was already processed.", 'warning')
            else:
                conn.commit()
                flash("🚫 Registration request rejected successfully.", 'info')

                # --- SEND REJECTION EMAIL ---
                if request_data:
                    send_rejection_email(request_data['email'], request_data['society_name'])

    except Exception as e:
        # app.logger.error(f"Rejection error for request {request_id}: {e}")
        if conn:
            conn.rollback()
        flash('An error occurred during rejection.', 'error')

    finally:
        if conn: 
            conn.close()

    return redirect(url_for('super_admin_dashboard'))

@app.route('/register_request', methods=['GET', 'POST'])
def register_request():
    """Handles the public display and submission of the registration request form."""
    
    if request.method == 'POST':
        society_name = request.form.get('society_name').strip()
        email = request.form.get('email').strip()
        mobile_number = request.form.get('mobile_number').strip()
        
        if not all([society_name, email, mobile_number]):
            flash('All fields are required.', 'error')
            return redirect(url_for('register_request'))

        conn = get_db_conn() 
        if not conn:
            flash('A database connection error occurred.', 'error')
            return redirect(url_for('register_request'))
        
        try:
            with conn.cursor() as cur:
                # Check for duplicate society_name or email
                cur.execute(""" 
                    SELECT society_name, email 
                    FROM registration_requests 
                    WHERE (society_name = %s OR email = %s) 
                    AND status IN ('pending', 'approved')
                """, (society_name, email))
                
                duplicate = cur.fetchone()
                if duplicate:
                    if duplicate[0] == society_name:
                        flash(f"❌ A request for society '{society_name}' already exists. Please mail admin for an invitation.", 'error')
                    elif duplicate[1] == email:
                        flash(f"❌ The email '{email}' is already registered for a Society", 'error')
                    conn.close()
                    return redirect(url_for('register_request'))
                
                # Insert new request
                cur.execute(""" 
                    INSERT INTO registration_requests (society_name, email, mobile_number) 
                    VALUES (%s, %s, %s)
                """, (society_name, email, mobile_number))
                
            conn.commit()
            flash('✅ Your registration request has been submitted successfully for review! You will receive an invitation link soon.', 'success')
            return redirect(url_for('register_request'))
            
        except (Exception, psycopg2.DatabaseError) as e:
            # app.logger.error(f"Registration request submission error: {e}")
            if conn:
                conn.rollback()
            flash('An error occurred during submission. Please try again.', 'error')
            
        finally:
            if conn: conn.close()
    
    # For GET requests, render the registration page
    return render_template('register_request.html')

@app.route('/register', methods=['GET', 'POST'])
def open_invite():
    token = request.args.get('token') or request.form.get('token')

    # --- HANDLE FORM SUBMISSION (POST) ---
    if request.method == 'POST':
        conn = None
        try:
            society_name = request.form['society_name']
            email = request.form['email']
            mobile = request.form['mobile_number']
            password = request.form['password']
            housing_type_selected = request.form['house_type']
            max_voters = request.form['max_voters']
            is_towerwise_flag = True if request.form.get('is_towerwise') == 'on' else False

            vote_per_house_str = request.form.get('vote_per_house')
            if vote_per_house_str not in ['true', 'false']:
                flash("Please select the voting type (1-vote per house or multiple votes per house).", "error")
                return redirect(url_for('open_invite', token=token))

            vote_per_house = (vote_per_house_str == 'true')

            if not all([society_name, email, mobile, password, housing_type_selected, max_voters]):
                flash("All fields are required.", "error")
                return redirect(url_for('open_invite', token=token))

            # --- FIX: Hash the password ---
            hashed_password = generate_password_hash(password)
            # ------------------------------

            conn = get_db_conn()
            cursor = conn.cursor()

            # --- Check if token already used ---
            cursor.execute("""
                SELECT review_status 
                FROM new_admins 
                WHERE invite_token = %s
            """, (token,))
            row = cursor.fetchone()
            if not row:
                flash("Invalid invitation token.", "error")
                return redirect(url_for('register_request'))
            elif row[0] != 'new_invitation':
                flash("❌ This invitation token has already been used.", "error")
                return redirect(url_for('register_request'))

            # --- Proceed with registration ---
            cursor.execute("""
                UPDATE new_admins 
                SET 
                    society_name = %s, 
                    email = %s, 
                    mobile_number = %s, 
                    password_hash = %s, 
                    housing_type = %s, 
                    max_voters = %s,
                    is_towerwise = %s,
                    vote_per_house = %s,
                    review_status = 'submitted_for_review',
                    responded = TRUE,
                    responded_at = CURRENT_TIMESTAMP
                WHERE invite_token = %s
                AND review_status = 'new_invitation';
            """, (
                society_name, email, mobile, hashed_password,
                housing_type_selected, max_voters,
                is_towerwise_flag, vote_per_house,
                token
            ))

            conn.commit() 
            flash('Registration successful! Your application is under review.', 'success')
            return redirect(url_for('thank_you'))

        except Exception as e:
            if conn:
                conn.rollback()
            flash(f"Error during registration: {e}", "error")
        finally:
            if conn:
                conn.close()

        return redirect(url_for('open_invite', token=token))

    # --- HANDLE PAGE LOAD (GET) ---
    if request.method == 'GET': 
        if not token:
            flash("No invitation token provided.", "error")
            return redirect(url_for('register_request'))

        conn = None
        invite = None
        try:
            conn = get_db_conn()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cursor.execute("""
                SELECT society_name, invite_token, invite_end_at, email, review_status 
                FROM new_admins 
                WHERE invite_token = %s;
            """, (token,))
            invite = cursor.fetchone()
        except Exception as e:
            flash(f"Error fetching invite: {e}", "error")
            return redirect(url_for('register_request'))
        finally:
            if conn:
                conn.close()

        if not invite:
            flash("Invalid invitation link.", "error")
            return redirect(url_for('register_request'))

        # --- Check if token already used ---
        if invite['review_status'] != 'new_invitation':
            flash("❌ This invitation token has already been used.", "error")
            return redirect(url_for('register_request'))

        # Trim INVITE_ prefix before rendering
        invite['society_name'] = invite['society_name'].removeprefix('INVITE_')
        return render_template(
            'register.html',
            token=token,
            invite=invite,
            house_type=house_type
        )
   
@app.route('/logout')
def logout():
    """Handles superadmin logout and prevents cached back navigation."""
    session.clear()
    flash('You have been logged out.', 'info')

    response = redirect(url_for('super_admin_dashboard'))  # Redirect to superadmin login form

    # Anti-cache headers
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response

@app.route('/super_admin/approve/<string:society_name>', methods=['POST'])
@admin_required
def approve_society(society_name):
    """Approves a society that has submitted its details."""
    conn = get_db_conn()  # Get database connection
    
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Retrieve society details from the database
        cursor.execute("""
            SELECT 
                society_name, role, password_hash, max_voters, housing_type, 
                is_towerwise, vote_per_house, mobile_number, email 
            FROM 
                new_admins 
            WHERE 
                society_name = %s 
            AND 
                review_status = 'submitted_for_review';
        """, (society_name,))

        new_society = cursor.fetchone()

        # Check if society exists or if already processed
        if not new_society:
            flash("🚨 Error: Submitted details not found or already processed for approval.", 'error')
            return redirect(url_for('super_admin_dashboard'))

        # Insert into admins table
        # NOTE: new_society['password_hash'] is already a hash
        # because it was created in the open_invite() route.
        admin_insert_tuple = (
            new_society['society_name'], 
            'admin', 
            new_society['password_hash'],
            new_society['max_voters'], 
            new_society['housing_type'],
            new_society['email']
        )

        cursor.execute("""
            INSERT INTO admins (society_name, role, password_hash, max_voters, housing_type, email)
            VALUES (%s, %s, %s, %s, %s,%s)
            ON CONFLICT (society_name, role) DO NOTHING;
        """, admin_insert_tuple)

        # Insert into settings table
        cursor.execute("""
            INSERT INTO settings (society_name, max_voters, is_towerwise, housing_type, vote_per_house)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (society_name) DO NOTHING;
        """, (
            new_society['society_name'], 
            new_society['max_voters'], 
            new_society['is_towerwise'], 
            new_society['housing_type'],
            new_society['vote_per_house']
        ))

        # Update new_admins table to mark the society as approved
        cursor.execute("""
            UPDATE new_admins 
            SET review_status = 'approved',
                responded_at = CURRENT_TIMESTAMP
            WHERE society_name = %s;
        """, (society_name,))

        conn.commit()  # Commit changes to the database

        # ✅ Send the final approval email after commit
        email_sent = send_final_approval_email(new_society['email'], 
            new_society['society_name'])

        if email_sent:
            flash(f"🎉 Society '{society_name}' successfully **approved** and added to live system. Final email sent!", 'success')
        else:
            flash(f"🚨 Error: Final approval email could not be sent to '{society_name}'.", 'error')

    except psycopg2.IntegrityError as e:
        if conn: conn.rollback()
        flash(f"🚨 Approval failed: Society '{society_name}' may already exist in the active tables. Error: {e}", 'error')
    except Exception as e:
        if conn: conn.rollback()
        flash(f"An unexpected error occurred during approval: {e}", 'error')

    finally:
        if conn: conn.close()

    return redirect(url_for('super_admin_dashboard'))
  
@app.route('/super_admin/reject/<string:society_name>', methods=['POST'])
@admin_required
def reject_society(society_name):
    """Rejects a society that has submitted its details."""
    conn = get_db_conn()
    
    try:
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE new_admins 
            SET review_status = 'rejected',
                responded_at = CURRENT_TIMESTAMP
            WHERE society_name = %s
            AND review_status = 'submitted_for_review';
        """, (society_name,))

        if cursor.rowcount == 0:
            flash("⚠️ Error: Society not found or was not pending review.", 'warning')
            conn.rollback()
        else:
            conn.commit() 
            flash(f"🚫 Society '{society_name}' successfully **rejected**. Status updated.", 'info')

    except Exception as e:
        if conn: conn.rollback()
        flash(f"An unexpected error occurred during rejection: {e}", 'error')

    finally:
        if conn: conn.close()
    
    return redirect(url_for('super_admin_dashboard'))

@app.route('/')
def index():
    """Redirects to the dashboard route which handles login/view."""
    return redirect(url_for('super_admin_dashboard')) 

@app.route('/thank_you')
def thank_you():
    return "<h1>Thank You! 🙏</h1><p>Your details are submitted and are awaiting Super Admin review.</p>"

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# --- STARTUP HOOK & APP RUN --- 
if __name__ == '__main__':
    with app.app_context():
        # ensures the tables are setup and the system admin exists on startup
        # assuming the tables are properly defined elsewhere or via a schema migration
        ensure_super_admin_exists() 
    # The original file had two app.run() calls; keeping only the one that runs the application
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5003)))