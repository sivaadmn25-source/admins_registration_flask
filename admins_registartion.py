from flask import Flask, render_template, request, redirect, url_for, flash, session
import psycopg2
import psycopg2.extras
from psycopg2 import OperationalError
import uuid
from datetime import datetime, timedelta
import os 
from dotenv import load_dotenv
# import bcrypt # <-- REMOVED: Using plain text authentication.
from functools import wraps
from constants import house_type 
import secrets 
import pytz 
from flask_mail import Mail, Message
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

# Set logging level to debug to see the new log messages
import logging
app.logger.setLevel(logging.DEBUG) 

# --- SECRET KEY (used for session & flash security) ---
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))

# --- EMAIL CONFIGURATION ---
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True').lower() in ['true', 't', '1'],
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER')
)

mail = Mail(app)

# --- GLOBAL HELPERS & DECORATORS ---

def get_db_conn():
    """Establishes a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        return conn
    except OperationalError as e:
        app.logger.error(f"Database connection failed: {e}")
        flash("Database connection error. Please check configuration.", 'error')
        raise

def login_required(f):
    """Decorator to ensure admin is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_email' not in session:
            flash("Please log in to access this page.", 'info')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def check_plain_password(password, stored_password):
    """
    CRITICAL FIX: Robustly compares plain text passwords. 
    Handles cases where the stored_password might be a byte object or have extra spaces.
    """
    # 1. Clean the input password
    clean_input = password.strip()
    
    # 2. Clean the stored password
    clean_stored = stored_password
    if isinstance(stored_password, bytes):
        # Decode if it's still coming back as bytea (old data/schema issue)
        try:
            clean_stored = stored_password.decode('utf-8')
        except UnicodeDecodeError:
             # Handle cases where the byte data isn't valid UTF-8 (e.g., pure hash)
             app.logger.error("Stored password is invalid byte sequence for UTF-8 decoding.")
             return False
    
    # Convert to string and strip any leading/trailing whitespace
    clean_stored = str(clean_stored).strip()
    
    # 3. Final comparison
    return clean_stored == clean_input

# --- INITIAL SETUP FUNCTIONS (ensure_super_admin_exists) ---

def ensure_super_admin_exists():
    """Checks for and creates the initial super admin if none exists."""
    conn = None
    try:
        conn = get_db_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cursor.execute("SELECT COUNT(*) FROM admins WHERE role = 'super_admin';")
        count = cursor.fetchone()[0]

        if count == 0:
            app.logger.info("No super admin found. Creating default SYSTEM_ADMIN.")
            
            # --- START: PLAIN TEXT PASSWORD CONFIGURATION ---
            DEFAULT_SUPER_ADMIN_PASSWORD = os.getenv("DEFAULT_SUPER_ADMIN_PASSWORD")
            
            # Store the plain password string directly (NO HASHING)
            DEFAULT_SUPER_ADMIN_STORED = DEFAULT_SUPER_ADMIN_PASSWORD
            # --- END: PLAIN TEXT PASSWORD CONFIGURATION ---

            if DEFAULT_SUPER_ADMIN_STORED:
                cursor.execute("""
                    INSERT INTO admins (
                        society_name, role, mobile_number, email, password_hash
                    ) 
                    VALUES (%s, %s, %s, %s, %s);
                """, (
                    'SYSTEM_ADMIN', 
                    'super_admin', 
                    os.getenv("DEFAULT_SUPER_ADMIN_MOBILE", '9999999999'),
                    os.getenv("DEFAULT_SUPER_ADMIN_EMAIL"), 
                    # Insert the plain text password string
                    DEFAULT_SUPER_ADMIN_STORED, 
                ))
                conn.commit()
                app.logger.warning(
                    f"✅ DEFAULT SYSTEM_ADMIN created. Email: {os.getenv('DEFAULT_SUPER_ADMIN_EMAIL')}"
                    f" - WARNING: Password is set to plain text: {DEFAULT_SUPER_ADMIN_PASSWORD}"
                )
            else:
                app.logger.error("🚫 DEFAULT_SUPER_ADMIN_PASSWORD is not set in environment variables.")

        else:
            app.logger.info("Super admin already exists. Skipping creation.")

    except OperationalError:
        app.logger.error("Could not connect to database during startup check.")
    except Exception as e:
        app.logger.error(f"Error during super admin check/creation: {e}")
        if conn: conn.rollback()
    finally:
        if conn: conn.close()

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def admin_login():
    """Handles admin login (used by super_admin and society admins)."""
    if 'admin_email' in session:
        return redirect(url_for('super_admin_dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        conn = None

        if not email or not password:
            flash("Email and Password are required.", 'error')
            return render_template('admin_login.html')

        try:
            conn = get_db_conn()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

            # 1. Check in the 'admins' table (Super Admins)
            cursor.execute("""
                SELECT email, password_hash, society_name, role 
                FROM admins 
                WHERE email = %s;
            """, (email,))
            admin_record = cursor.fetchone()

            if admin_record:
                stored_password = admin_record['password_hash']
                
                # --- START DEBUG LOGGING (SECURITY RISK - FOR DEV ONLY) ---
                # WARNING: Printing raw passwords is a major security risk in production!
                # Doing this only for current debugging of comparison mismatch in test environment.
                app.logger.debug("--- RAW PASSWORD DEBUG START (Admins Table) ---")
                app.logger.debug(f"Input Pwd Type/Len: {type(password)}, {len(password.strip())}")
                app.logger.debug(f"Stored Pwd Type/Len: {type(stored_password)}, {len(str(stored_password).strip())}")
                app.logger.debug(f"Input Pwd (RAW): '{password.strip()}'")
                app.logger.debug(f"Stored Pwd (RAW): '{str(stored_password).strip()}'")
                app.logger.debug("--- RAW PASSWORD DEBUG END ---")
                # --- END DEBUG LOGGING (SECURITY RISK - FOR DEV ONLY) ---
                
                # CRITICAL FIX 3: Use the robust plain text check
                if check_plain_password(password, stored_password): 
                    session['admin_email'] = admin_record['email']
                    session['admin_society'] = admin_record['society_name']
                    session['admin_role'] = admin_record['role']
                    flash(f"Welcome, {admin_record['society_name']}!", 'success')
                    return redirect(url_for('super_admin_dashboard'))
            
            # 2. Check in the 'new_admins' table (Pending Admins who have submitted details)
            cursor.execute("""
                SELECT email, password_hash, society_name, role, review_status 
                FROM new_admins 
                WHERE email = %s 
                AND review_status IN ('submitted_for_review', 'approved', 'rejected');
            """, (email,))
            new_admin_record = cursor.fetchone()

            if new_admin_record:
                if new_admin_record['review_status'] == 'approved':
                    stored_password = new_admin_record['password_hash']

                    # --- START DEBUG LOGGING (SECURITY RISK - FOR DEV ONLY) ---
                    # WARNING: Printing raw passwords is a major security risk in production!
                    # Doing this only for current debugging of comparison mismatch in test environment.
                    app.logger.debug("--- RAW PASSWORD DEBUG START (New Admins Table) ---")
                    app.logger.debug(f"Input Pwd Type/Len: {type(password)}, {len(password.strip())}")
                    app.logger.debug(f"Stored Pwd Type/Len: {type(stored_password)}, {len(str(stored_password).strip())}")
                    app.logger.debug(f"Input Pwd (RAW): '{password.strip()}'")
                    app.logger.debug(f"Stored Pwd (RAW): '{str(stored_password).strip()}'")
                    app.logger.debug("--- RAW PASSWORD DEBUG END ---")
                    # --- END DEBUG LOGGING (SECURITY RISK - FOR DEV ONLY) ---

                    if check_plain_password(password, stored_password):
                        flash("Your account is approved but has not yet been migrated. Please contact support.", 'info')
                        return render_template('admin_login.html')

                elif new_admin_record['review_status'] == 'submitted_for_review':
                    flash("Your registration is awaiting Super Admin approval.", 'warning')
                    return render_template('admin_login.html')

                elif new_admin_record['review_status'] == 'rejected':
                    flash("Your registration was rejected. Please contact support for details.", 'error')
                    return render_template('admin_login.html')

            # This flash runs if either password check failed, or no record was found.
            flash("Invalid Email or Password.", 'error')

        except Exception as e:
            app.logger.error(f"Login error: {e}")
            flash("An unexpected error occurred during login.", 'error')
        finally:
            if conn:
                conn.close()

    return render_template('admin_login.html')

@app.route('/dashboard', methods=['GET', 'POST']) 
@login_required
def super_admin_dashboard():
    """Super Admin Dashboard view and invitation creation."""
    is_authenticated = 'admin_email' in session and session.get('admin_role') == 'super_admin'
    
    if not is_authenticated:
        flash("You do not have super admin privileges.", 'error')
        return redirect(url_for('admin_login'))
        
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
            
            # --- PLAIN TEXT FIX FOR DUMMY INVITE ---
            DUMMY_HASH = 'dummy_pass' 
            # ---------------------------------------

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
                    DUMMY_HASH,  
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
                if conn:
                    conn.rollback()
                error_msg = f"DB INSERT FAILED: Check constraints/columns. Error: {e}"
                flash(error_msg, 'error')
            finally:
                if conn:
                    conn.close()

            return redirect(url_for('super_admin_dashboard'))

        # Handle GET (View Dashboard Data)
        try:
            conn = get_db_conn()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

            # Fetch Pending Registration Requests
            cursor.execute(
                """SELECT id, society_name, email, mobile_number, submitted_at
                    FROM registration_requests 
                    WHERE status = 'pending' 
                    ORDER BY submitted_at ASC"""
            )
            pending_requests = cursor.fetchall()

            # Fetch Pending Approvals
            cursor.execute("""
                SELECT 
                    society_name, email, mobile_number, max_voters, housing_type, is_towerwise, responded_at
                FROM 
                    new_admins 
                WHERE 
                    review_status = 'submitted_for_review' 
                AND 
                    responded = TRUE
                ORDER BY responded_at DESC;
            """)
            pending_approvals = cursor.fetchall()

            # Fetch Active Invitations
            cursor.execute("""
                SELECT 
                    society_name, invite_token, invited_at, invite_end_at, email
                FROM 
                    new_admins 
                WHERE 
                    responded = FALSE 
                AND 
                    review_status = 'new_invitation' 
                ORDER BY invited_at DESC;
            """)
            active_invites = cursor.fetchall()

            # Fetch societies for Master Erase dropdown
            cursor.execute(
                """SELECT DISTINCT society_name FROM new_admins 
                    WHERE role = 'admin' 
                    ORDER BY society_name;"""
            )
            societies = [row[0] for row in cursor.fetchall()]

        except Exception as e:
            flash(f"Database Error retrieving dashboard data: {e}", 'error')
            app.logger.error(f"Dashboard Data Fetch Error: {e}")
        finally:
            if conn:
                conn.close()

        base_url = "https://admins-registration-flask.onrender.com/register?token="

        return render_template(
            'super_admin_dashboard.html',
            is_authenticated=True,
            pending_approvals=pending_approvals,
            active_invites=active_invites,
            pending_requests=pending_requests,
            societies=societies,
            base_url=base_url
        )


@app.route('/logout')
def admin_logout():
    """Logs the current admin out."""
    session.pop('admin_email', None)
    session.pop('admin_society', None)
    session.pop('admin_role', None)
    flash("You have been logged out.", 'info')
    return redirect(url_for('admin_login'))

@app.route('/approve_admin/<society_name>', methods=['POST'])
@login_required
def approve_admin(society_name):
    """Approves a submitted admin registration request."""
    if session.get('admin_role') != 'super_admin':
        flash("Authorization denied.", 'error')
        return redirect(url_for('super_admin_dashboard'))

    conn = None
    try:
        conn = get_db_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # 1. Fetch the data from new_admins
        cursor.execute("""
            SELECT society_name, role, mobile_number, email, password_hash
            FROM new_admins 
            WHERE society_name = %s 
            AND review_status = 'submitted_for_review' 
            AND responded = TRUE;
        """, (society_name,))
        new_admin = cursor.fetchone()

        if not new_admin:
            flash("⚠️ Error: Admin request not found or status is incorrect.", 'warning')
            return redirect(url_for('super_admin_dashboard'))

        # 2. Insert into final admins table
        cursor.execute("""
            INSERT INTO admins (
                society_name, role, mobile_number, email, password_hash
            ) 
            VALUES (UPPER(%s), %s, %s, %s, %s);
        """, (
            new_admin['society_name'],
            new_admin['role'],
            new_admin['mobile_number'],
            new_admin['email'],
            # This is already a plain string from new_admins
            new_admin['password_hash'], 
        ))

        # 3. Update status in new_admins (optional, but good for tracking)
        cursor.execute("""
            UPDATE new_admins 
            SET review_status = 'approved',
                responded_at = CURRENT_TIMESTAMP
            WHERE society_name = %s 
            AND review_status = 'submitted_for_review';
        """, (society_name,))
        
        # 4. Remove corresponding entry from registration_requests
        cursor.execute(
            "DELETE FROM registration_requests WHERE society_name = %s AND status = 'pending';",
            (society_name,)
        )

        conn.commit()
        flash(f"✅ Admin for society '{society_name}' successfully **approved** and moved to active admins.", 'success')

    except Exception as e:
        if conn: conn.rollback()
        # Check for unique constraint violation (admin already exists)
        if 'duplicate key value' in str(e):
            error_msg = f"Admin for '{society_name}' already exists in the final admins table."
        else:
            error_msg = f"An unexpected error occurred during approval: {e}"
        
        flash(error_msg, 'error')

    finally:
        if conn: conn.close()
    
    return redirect(url_for('super_admin_dashboard'))


@app.route('/reject_admin/<society_name>', methods=['POST'])
@login_required
def reject_admin(society_name):
    """
    Rejects a submitted admin registration request. 
    It marks the new_admins entry as 'rejected' but doesn't delete it (for audit trail).
    It removes the corresponding registration request entry.
    """
    if session.get('admin_role') != 'super_admin':
        flash("Authorization denied.", 'error')
        return redirect(url_for('super_admin_dashboard'))
    
    conn = get_db_conn()
    
    try:
        cursor = conn.cursor()
        
        # 1. Update the status in new_admins
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
            # 2. Remove corresponding entry from registration_requests
            cursor.execute(
                "DELETE FROM registration_requests WHERE society_name = %s AND status = 'pending';",
                (society_name,)
            )
            conn.commit() 
            flash(f"🚫 Society '{society_name}' successfully **rejected**. Status updated.", 'info')

    except Exception as e:
        if conn: conn.rollback()
        flash(f"An unexpected error occurred during rejection: {e}", 'error')

    finally:
        if conn: conn.close()
    
    return redirect(url_for('super_admin_dashboard'))


@app.route('/delete_invitation/<invite_token>', methods=['POST'])
@login_required
def delete_invitation(invite_token):
    """Deletes an active, unused admin invitation."""
    if session.get('admin_role') != 'super_admin':
        flash("Authorization denied.", 'error')
        return redirect(url_for('super_admin_dashboard'))

    conn = get_db_conn()

    try:
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM new_admins 
            WHERE invite_token = %s 
            AND review_status = 'new_invitation' 
            AND responded = FALSE;
        """, (invite_token,))

        if cursor.rowcount == 0:
            flash("⚠️ Error: Invitation not found or already used.", 'warning')
            conn.rollback()
        else:
            conn.commit()
            flash(f"✅ Invitation with token {invite_token[:8]}... successfully deleted.", 'success')

    except Exception as e:
        if conn: conn.rollback()
        flash(f"An unexpected error occurred during deletion: {e}", 'error')
    finally:
        if conn: conn.close()

    return redirect(url_for('super_admin_dashboard'))


@app.route('/register', methods=['GET', 'POST'])
def admin_register():
    """Handles admin registration via invitation token."""
    token = request.args.get('token')
    
    if not token:
        flash("Invalid or missing registration token.", 'error')
        return redirect(url_for('index'))

    conn = None
    existing_invite = None
    
    # 1. Check token validity
    try:
        conn = get_db_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute("""
            SELECT society_name, invite_end_at, email
            FROM new_admins 
            WHERE invite_token = %s 
            AND review_status = 'new_invitation' 
            AND responded = FALSE;
        """, (token,))
        existing_invite = cursor.fetchone()

        if not existing_invite:
            flash("This invitation is invalid, expired, or has already been used.", 'error')
            return redirect(url_for('index'))

        if existing_invite['invite_end_at'] < datetime.now(IST):
            flash("This invitation has expired.", 'error')
            return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Registration token check error: {e}")
        flash("A database error occurred during token verification.", 'error')
        if conn: conn.close()
        return redirect(url_for('index'))
    finally:
        if conn: conn.close()
        conn = None # Reset conn for POST logic

    # 2. Handle POST submission
    if request.method == 'POST':
        society_name = request.form.get('society_name', '').strip()
        mobile_number = request.form.get('mobile_number', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        max_voters = request.form.get('max_voters', '').strip()
        housing_type = request.form.get('housing_type', '').strip()
        is_towerwise = request.form.get('is_towerwise') == 'on'

        if password != confirm_password:
            flash("Passwords do not match.", 'error')
            return render_template('admin_registration.html', token=token, existing_invite=existing_invite, house_type=house_type)
        
        # Simple validation
        if not all([society_name, mobile_number, email, password, max_voters, housing_type]):
            flash("All fields are required.", 'error')
            return render_template('admin_registration.html', token=token, existing_invite=existing_invite, house_type=house_type)

        try:
            conn = get_db_conn()
            cursor = conn.cursor()
            
            # Store plain password. No hashing.
            plain_password = password 

            # Update the existing new_admins record
            cursor.execute("""
                UPDATE new_admins SET
                    society_name = UPPER(%s),
                    mobile_number = %s,
                    email = %s,
                    password_hash = %s, 
                    max_voters = %s,
                    housing_type = %s,
                    is_towerwise = %s,
                    review_status = 'submitted_for_review',
                    responded = TRUE,
                    responded_at = CURRENT_TIMESTAMP
                WHERE invite_token = %s
                AND review_status = 'new_invitation';
            """, (
                society_name, mobile_number, email, plain_password,
                int(max_voters), housing_type, is_towerwise, token
            ))
            
            if cursor.rowcount == 0:
                flash("Token already used or expired. Please contact support.", 'error')
                conn.rollback()
                return redirect(url_for('index'))

            conn.commit()
            
            return redirect(url_for('thank_you'))
        
        except psycopg2.IntegrityError as e:
            conn.rollback()
            if 'duplicate key' in str(e):
                flash("Error: This email address is already registered or the society name is taken.", 'error')
            else:
                flash(f"A database constraint error occurred: {e}", 'error')
            return render_template('admin_registration.html', token=token, existing_invite=existing_invite, house_type=house_type)
            
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Registration error: {e}")
            flash(f"An unexpected error occurred during registration: {e}", 'error')
            return render_template('admin_registration.html', token=token, existing_invite=existing_invite, house_type=house_type)
        finally:
            if conn: conn.close()

    # 3. Handle GET view
    return render_template('admin_registration.html', token=token, existing_invite=existing_invite, house_type=house_type)


@app.route('/master_erase/<society_name>', methods=['POST'])
@login_required
def master_erase(society_name):
    """
    MASTER ERASE: Deletes all entries related to a society from all tables. 
    Requires confirmation.
    """
    if session.get('admin_role') != 'super_admin':
        flash("Authorization denied.", 'error')
        return redirect(url_for('super_admin_dashboard'))

    conn = get_db_conn()

    try:
        cursor = conn.cursor()
        
        # List of tables to clear data from for the given society_name
        tables_to_clear = ['admins', 'new_admins', 'registration_requests', 'voters'] # Add any other society-specific tables

        for table in tables_to_clear:
            # Note: This assumes all relevant tables have a 'society_name' column
            cursor.execute(f"DELETE FROM {table} WHERE society_name = UPPER(%s);", (society_name,))
            app.logger.warning(f"Cleared {cursor.rowcount} records from {table} for society {society_name}")

        conn.commit()
        flash(f"💣 MASTER ERASE SUCCESSFUL for society '{society_name}'. All related data has been deleted.", 'success')

    except Exception as e:
        if conn: conn.rollback()
        flash(f"MASTER ERASE FAILED: An unexpected error occurred: {e}", 'error')
        app.logger.error(f"MASTER ERASE Error: {e}")

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


# --- STARTUP HOOK & APP RUN ---

# Run this once to ensure the super admin exists before running the app
ensure_super_admin_exists()

if __name__ == '__main__':
    with app.app_context():
        ensure_super_admin_exists()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5003)))
    app.run(debug=True, port=5003)  