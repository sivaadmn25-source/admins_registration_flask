from flask import Flask, render_template, request, redirect, url_for, flash, session
import psycopg2
import psycopg2.extras
from psycopg2 import OperationalError
import uuid
from datetime import datetime, timedelta
import os 
from dotenv import load_dotenv
import bcrypt 
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

# --- SECRET KEY (used for session & flash security) ---
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))

# --- EMAIL CONFIGURATION ---
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True').lower() in ['true', '1'],
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_USERNAME')
)
mail = Mail(app)

# --- SYSTEM CONSTANTS ---
SYSTEM_ADMIN_ID = 'SYSTEM_ADMIN'
# Removed: DEFAULT_SUPER_ADMIN_PASSWORD = os.getenv("DEFAULT_SUPER_ADMIN_PASSWORD")
# Removed: DEFAULT_SUPER_ADMIN_HASH = ...

# --- DATABASE CONNECTION ---
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
        print(f"Database connection failed: {e}")
        flash("Database connection failed. Please check server status.", "error")
        return None

# --- AUTH DECORATOR ---
def login_required(f):
    """Decorator to ensure user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('super_admin_dashboard', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- EMAIL FUNCTIONS ---
def send_email(to, subject, body):
    """Sends an email using Flask-Mail."""
    try:
        msg = Message(subject, recipients=[to], body=body)
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email sending failed to {to}: {e}")
        return False

def send_approval_email(to, society_name, invite_token):
    """Sends the invitation email with the unique registration link."""
    subject = "Your Society Registration Invitation"
    registration_link = url_for('open_invite', token=invite_token, _external=True)
    body = f"""
Dear Admin of {society_name},

Your society's registration request has been approved and an invitation is ready for you!

Please click the link below to complete your registration and set your password:
{registration_link}

This link will expire in 14 days.

If you have any questions, please contact the system administrator.

Regards,
System Admin Team
"""
    return send_email(to, subject, body)

def send_final_approval_email(to, society_name):
    """Sends confirmation after the admin submits their details."""
    subject = "Society Details Submitted"
    body = f"""
Dear Admin of {society_name},

Thank you for submitting your final registration details. 
Your application is now under final review by the Super Admin. You will receive another notification once it's fully approved and ready for use.

Regards,
System Admin Team
"""
    return send_email(to, subject, body)

# --- DATABASE SETUP ---
def ensure_tables_exist():
    """
    Checks if necessary tables exist and creates them if not. 
    Also ensures the Super Admin account exists.
    """
    conn = get_db_conn()
    if not conn:
        return False
        
    try:
        cursor = conn.cursor()
        
        # 1. Create registration_requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS registration_requests (
                id SERIAL PRIMARY KEY,
                society_name TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                mobile_number VARCHAR(15) NOT NULL,
                request_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'pending'
            );
        """)

        # 2. Create new_admins table (for pending invitees)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS new_admins (
                id SERIAL PRIMARY KEY,
                society_name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                mobile_number VARCHAR(15) NOT NULL,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL, -- <--- SET TO TEXT
                max_voters INTEGER NOT NULL DEFAULT 2,
                housing_type TEXT NOT NULL DEFAULT 'xyz',
                reset_token CHARACTER VARYING,
                reset_token_expiry TIMESTAMP WITH TIME ZONE,
                invite_token CHARACTER VARYING UNIQUE,
                invite_end_at TIMESTAMP WITH TIME ZONE,
                review_status VARCHAR(50) DEFAULT 'new_invitation',
                responded BOOLEAN DEFAULT FALSE,
                responded_at TIMESTAMP WITH TIME ZONE,
                is_towerwise BOOLEAN DEFAULT FALSE,
                vote_per_house BOOLEAN NOT NULL DEFAULT FALSE
            );
        """)

        # 3. Create admins table (for active accounts)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                society_name TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL, -- <--- SET TO TEXT
                max_voters INTEGER NOT NULL DEFAULT 2,
                housing_type TEXT NOT NULL DEFAULT 'xyz',
                reset_token CHARACTER VARYING,
                reset_token_expiry TIMESTAMP WITH TIME ZONE,
                email CHARACTER VARYING UNIQUE,
                mobile_number VARCHAR(15),
                is_towerwise BOOLEAN DEFAULT FALSE,
                vote_per_house BOOLEAN NOT NULL DEFAULT FALSE,
                CONSTRAINT unique_society_role UNIQUE (society_name, role)
            );
        """)

        # 4. Check/Insert Super Admin (REMOVED LOGIC)
        # The Super Admin must be inserted manually into the `admins` table for first-time use.
        
        conn.commit()
        return True
        
    except Exception as e:
        print(f"Error during table setup: {e}")
        if conn: conn.rollback()
        return False
    finally:
        if conn: conn.close()

def generate_invite_from_request(request_data, conn):
    """Generates an invitation token, saves it to new_admins (as a placeholder invite), and updates request status."""
    token = secrets.token_urlsafe(32)
    # Set expiry 14 days from now, using the defined IST timezone
    invite_end_at = datetime.now(IST) + timedelta(days=14) 
    # Use dummy values required by new_admins table schema
    DUMMY_PASSWORD = 'dummy_pass' # <--- USE PLAIN TEXT PASSWORD
    
    with conn.cursor() as cur:
        # 1. Insert into new_admins (as placeholder invite)
        cur.execute(
            """INSERT INTO new_admins (
                   society_name, role, mobile_number, email, password_hash, invite_token, 
                   invite_end_at, max_voters, housing_type, review_status, is_towerwise, vote_per_house
               ) 
               VALUES (UPPER(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);""",
            (
                f"INVITE_{request_data['society_name']}", # Using a prefix for society_name as a placeholder
                'admin', 
                request_data['mobile_number'], 
                request_data['email'], 
                DUMMY_PASSWORD, # <--- PASS PLAIN TEXT DIRECTLY
                token, 
                invite_end_at,
                1, # Min required value
                'Apartment-Single Tower', 
                'new_invitation', 
                False,
                False
            )
        )
        # 2. Update registration_requests status to approved
        cur.execute("UPDATE registration_requests SET status = 'approved' WHERE id = %s", (request_data['id'],))
        
    return token

# --- ROUTES ---

@app.before_request
def check_for_tables():
    """Runs database setup before the very first request."""
    if not hasattr(app, 'tables_initialized'):
        if ensure_tables_exist():
            app.tables_initialized = True
        else:
            # Handle error case where tables couldn't be created
            flash("CRITICAL: Database tables could not be initialized.", "error")

@app.route('/super_admin/dashboard', methods=['GET', 'POST'])
def super_admin_dashboard():
    conn = get_db_conn()
    if not conn:
        # If DB connection fails, only show login page (cannot check status)
        return render_template('super_admin_dashboard.html', is_authenticated=False)

    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # --- HANDLE LOGIN (POST) ---
        if request.method == 'POST':
            # 1. Handle Login
            if 'email' in request.form and 'password' in request.form:
                email = request.form['email']
                password = request.form['password']
                
                cursor.execute("SELECT password_hash, role FROM admins WHERE email = %s", (email,))
                user_record = cursor.fetchone()
                
                if user_record and password:
                    stored_password = user_record['password_hash']
                    
                    # Use direct string comparison for plain text password
                    if password == stored_password: 
                        
                        session['user_id'] = SYSTEM_ADMIN_ID
                        flash(f'Login successful. Welcome, {user_record["role"]}!', 'success')
                        next_page = request.args.get('next')
                        return redirect(next_page or url_for('super_admin_dashboard'))
                
                flash('Invalid Credentials (Email or Password).', 'error')
                return render_template('super_admin_dashboard.html', is_authenticated=False)

            # 2. Handle Invitation Creation (Manual)
            token = secrets.token_urlsafe(32) 
            dummy_society_name = f"PLACEHOLDER_{uuid.uuid4().hex[:8]}" 
            dummy_email = f"dummy_{uuid.uuid4().hex[:8]}@invite.com"
            invite_end_time = datetime.now(IST) + timedelta(days=14)
            DUMMY_MOBILE = '9999999999'
            DUMMY_PASSWORD = 'dummy_pass' # <--- USE PLAIN TEXT PASSWORD
            
            try:
                # Check authentication again before manual action
                if 'user_id' not in session:
                    flash('Authentication required for this action.', 'error')
                    return redirect(url_for('super_admin_dashboard'))
                    
                cursor.execute("""
                    INSERT INTO new_admins (
                        society_name, role, mobile_number, email, password_hash, invite_token, 
                        invite_end_at, max_voters, housing_type, review_status, is_towerwise, vote_per_house
                    ) 
                    VALUES (UPPER(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """, (
                    dummy_society_name, 
                    'admin', 
                    DUMMY_MOBILE, 
                    dummy_email, 
                    DUMMY_PASSWORD, # <--- PASS PLAIN TEXT DIRECTLY
                    token, 
                    invite_end_time,
                    2, 
                    'xyz', 
                    'new_invitation', 
                    False, 
                    False
                ))
                conn.commit()
                flash(f"✅ New invitation created. Token: {token[:8]}... Link generated.", 'success')
                
            except Exception as e:
                conn.rollback()
                error_msg = f"DB INSERT FAILED: Check constraints/columns. Error: {e}"
                flash(error_msg, 'error')

            # Must redirect to GET after a POST
            return redirect(url_for('super_admin_dashboard'))


        # --- HANDLE GET (DISPLAY) ---
        if 'user_id' in session:
            # User is logged in (Super Admin view)
            
            # Fetch pending requests
            cursor.execute("SELECT * FROM registration_requests WHERE status = 'pending' ORDER BY request_date DESC")
            pending_requests = cursor.fetchall()
            
            # Fetch pending review submissions
            cursor.execute("SELECT * FROM new_admins WHERE review_status = 'submitted_for_review' ORDER BY responded_at DESC")
            pending_review_submissions = cursor.fetchall()

            return render_template(
                'super_admin_dashboard.html', 
                is_authenticated=True, 
                pending_requests=pending_requests,
                pending_review_submissions=pending_review_submissions
            )
        else:
            # User is not logged in (Login page view)
            return render_template('super_admin_dashboard.html', is_authenticated=False)

    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'error')
        # On error, log out the user and show login page
        session.pop('user_id', None)
        return render_template('super_admin_dashboard.html', is_authenticated=False)
    finally:
        if conn: conn.close()


@app.route('/super_admin/logout')
def super_admin_logout():
    """Logs out the Super Admin."""
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('super_admin_dashboard'))

@app.route('/super_admin/send_invite/<int:request_id>', methods=['POST'])
@login_required
def send_invite(request_id):
    """Generates an invite token and sends the registration link to the requested admin."""
    conn = get_db_conn()
    if not conn:
        return redirect(url_for('super_admin_dashboard'))
        
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # 1. Fetch request details
        cursor.execute("SELECT * FROM registration_requests WHERE id = %s AND status = 'pending'", (request_id,))
        request_data = cursor.fetchone()
        
        if not request_data:
            flash("⚠️ Error: Registration request not found or already processed.", 'warning')
            return redirect(url_for('super_admin_dashboard'))

        # 2. Generate invite and update DB status
        invite_token = generate_invite_from_request(request_data, conn)
        
        # 3. Send email with the invite link
        if send_approval_email(request_data['email'], request_data['society_name'], invite_token):
            conn.commit()
            flash(f"✉️ Invitation sent to {request_data['society_name']} ({request_data['email']}). Status updated.", 'success')
        else:
            conn.rollback() # Rollback DB changes if email fails
            flash("❌ Invitation email failed to send. DB changes were rolled back.", 'error')
        
    except Exception as e:
        if conn: conn.rollback()
        flash(f"An unexpected error occurred during invite: {e}", 'error')

    finally:
        if conn: conn.close()
        
    return redirect(url_for('super_admin_dashboard'))

@app.route('/super_admin/reject_request/<int:request_id>', methods=['POST'])
@login_required
def reject_request(request_id):
    """Rejects a registration request."""
    conn = get_db_conn()
    if not conn:
        return redirect(url_for('super_admin_dashboard'))
        
    try:
        cursor = conn.cursor()
        
        cursor.execute("UPDATE registration_requests SET status = 'rejected' WHERE id = %s AND status = 'pending'", (request_id,))

        if cursor.rowcount == 0:
            flash("⚠️ Error: Request not found or was not pending.", 'warning')
            conn.rollback()
        else:
            conn.commit() 
            flash(f"🚫 Request {request_id} successfully **rejected**. Status updated.", 'info')

    except Exception as e:
        if conn: conn.rollback()
        flash(f"An unexpected error occurred during rejection: {e}", 'error')

    finally:
        if conn: conn.close()
    
    return redirect(url_for('super_admin_dashboard'))

@app.route('/invite/<string:token>', methods=['GET', 'POST'])
def open_invite(token):
    """Allows an invited admin to complete their registration by setting details and password."""
    conn = get_db_conn()
    if not conn:
        return redirect(url_for('super_admin_dashboard'))

    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # --- GET INVITE DETAILS (GET or initial POST check) ---
        cursor.execute("""
            SELECT * FROM new_admins 
            WHERE invite_token = %s 
            AND invite_end_at > CURRENT_TIMESTAMP 
            AND review_status = 'new_invitation';
        """, (token,))
        invite_record = cursor.fetchone()
        
        if not invite_record:
            # Check for expired/used/not-found status
            cursor.execute("SELECT * FROM new_admins WHERE invite_token = %s", (token,))
            any_record = cursor.fetchone()
            if any_record and any_record['invite_end_at'] < datetime.now(IST).replace(tzinfo=None):
                flash("❌ Invitation expired. Please contact Super Admin.", 'error')
            elif any_record and any_record['review_status'] != 'new_invitation':
                flash("⚠️ This invitation has already been submitted for review or approved.", 'warning')
            else:
                flash("🚫 Invalid or previously used invitation link.", 'error')
            return redirect(url_for('super_admin_dashboard'))


        # --- HANDLE FORM SUBMISSION (POST) ---
        if request.method == 'POST':
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

            # Hashed password generation removed. Using plain password.
            
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
                WHERE 
                    invite_token = %s 
                AND 
                    review_status = 'new_invitation';
            """, (
                society_name, email, mobile, password, # <--- USE PLAIN TEXT password VARIABLE
                housing_type_selected, max_voters,
                is_towerwise_flag, vote_per_house,
                token
            ))
            
            conn.commit()
            send_final_approval_email(email, society_name)
            flash('Registration successful! Your application is under review.', 'success')
            return redirect(url_for('thank_you'))

        # --- HANDLE GET (DISPLAY FORM) ---
        return render_template(
            'register.html',
            invite=invite_record,
            token=token,
            house_type_options=house_type
        )

    except Exception as e:
        if conn: conn.rollback()
        flash(f"An unexpected error occurred during registration: {e}", 'error')
        return redirect(url_for('super_admin_dashboard'))
    finally:
        if conn: conn.close()

@app.route('/super_admin/approve_society/<string:society_name>', methods=['POST'])
@login_required
def approve_society(society_name):
    """
    Approves a submitted admin registration. 
    Moves the admin details (including plain text password) from new_admins to admins.
    """
    conn = get_db_conn()
    if not conn:
        return redirect(url_for('super_admin_dashboard'))
    
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # 1. Fetch data from new_admins
        cursor.execute("SELECT * FROM new_admins WHERE society_name = %s AND review_status = 'submitted_for_review'", (society_name,))
        new_society = cursor.fetchone() 

        if not new_society:
            flash("⚠️ Error: Submitted society not found or not ready for approval.", 'warning')
            conn.rollback()
            return redirect(url_for('super_admin_dashboard'))

        admin_insert_tuple = (
            new_society['society_name'], 
            'admin', 
            new_society['password_hash'], # <--- Plain text password transferred
            new_society['max_voters'], 
            new_society['housing_type'],
            new_society['email'],
            new_society['mobile_number'],
            new_society['is_towerwise'],
            new_society['vote_per_house']
        )
        
        # 2. Insert into admins (ON CONFLICT handles unique constraint errors)
        cursor.execute("""
            INSERT INTO admins (
                society_name, role, password_hash, max_voters, housing_type, email, mobile_number, is_towerwise, vote_per_house
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (society_name, role) DO NOTHING;
        """, admin_insert_tuple)
        
        # 3. Update new_admins status
        cursor.execute("""
            UPDATE new_admins 
            SET review_status = 'approved',
                responded_at = CURRENT_TIMESTAMP
            WHERE society_name = %s
            AND review_status = 'submitted_for_review';
        """, (society_name,))

        conn.commit()
        # Optionally send a final confirmation email to the admin here
        flash(f"✅ Society '{society_name}' successfully **approved**. Admin account is now active.", 'success')

    except Exception as e:
        if conn: conn.rollback()
        flash(f"An unexpected error occurred during approval: {e}", 'error')

    finally:
        if conn: conn.close()
    
    return redirect(url_for('super_admin_dashboard'))

@app.route('/super_admin/reject_society/<string:society_name>', methods=['POST'])
@login_required
def reject_society(society_name):
    """Rejects a submitted admin registration after they have submitted its details."""
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


# --- STARTUP HOOK & APP RUN 
if __name__ == '__main__':
    # ensure_tables_exist() is now called via @app.before_request
    app.run(debug=True, port=5003)