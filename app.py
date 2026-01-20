from flask import Flask, request, render_template, redirect, url_for, flash, session
from functools import wraps
import os
import re
from werkzeug.utils import secure_filename
from supabase import Client

# --- CUSTOM MODULE IMPORTS ---
from ml_engine.backend_scanner import scan_logic 
from utils.ocr import run_ocr
from utils.security_filter import check_file_extension
from utils.email_parser import parse_eml_file, check_header_spoofing, extract_sender_domain
from utils.dns_verifier import verify_email_authenticity, analyze_sender_domain

# DATABASE IMPORTS
from database import log_scan, create_user_profile, get_user_profile, get_scan_history, delete_scan_log

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# --- SUPABASE CONFIG ---
SUPABASE_URL = "https://sutccxmhqstoatpublqp.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN1dGNjeG1ocXN0b2F0cHVibHFwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2ODQ5MTgxNywiZXhwIjoyMDg0MDY3ODE3fQ.4iei3BHbae-kdHPV1sUoZY7NKzniZj4H8OrJeYoeg7E"
supabase = Client(SUPABASE_URL, SUPABASE_KEY)

# --- UPLOAD CONFIG ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- AUTH DECORATOR ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            user_id = response.user.id
            profile = get_user_profile(user_id)
            display_name = profile.get('display_name') if profile else email.split('@')[0]

            session['user'] = {
                'id': user_id,
                'email': response.user.email,
                'name': display_name
            }
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f"Login failed: {str(e)}", "danger")
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        display_name = f"{first_name} {last_name}".strip()

        try:
            response = supabase.auth.sign_up({"email": email, "password": password})
            if response.user:
                create_user_profile(response.user.id, first_name, last_name, display_name)
                flash("Account created! Please log in.", "success")
                return redirect(url_for('login'))
        except Exception as e:
            flash(f"Signup failed: {str(e)}", "danger")
            
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('scanner.html', user=session['user'], mode='text')

@app.route('/history')
@login_required
def history():
    logs = get_scan_history(session['user']['id'])
    return render_template('history.html', user=session['user'], logs=logs)

# --- FIX: Changed <int:log_id> to <log_id> to handle UUID strings ---
@app.route('/delete_log/<log_id>', methods=['POST'])
@login_required
def delete_log(log_id):
    # This now accepts the UUID string (e.g., 'eabbf62e-...') correctly
    if delete_scan_log(log_id, session['user']['id']):
        flash("Log deleted.", "success")
    else:
        flash("Could not delete log.", "danger")
    return redirect(url_for('history'))

@app.route('/profile')
@login_required
def profile():
    try:
        user_id = session['user']['id']
        profile_data = get_user_profile(user_id)
        
        if not profile_data:
            profile_data = {
                "first_name": "Unknown", 
                "last_name": "", 
                "display_name": session['user']['name']
            }
            
        return render_template('profile.html', user=session['user'], profile=profile_data)
        
    except Exception as e:
        flash(f"Error fetching profile: {e}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/about')
def about():
    return render_template('about.html', user=session.get('user'))

# --- SCANNING ROUTES ---

@app.route('/scan/text', methods=['POST'])
@login_required
def scan_text():
    text = request.form.get('text_content', '').strip()
    sender = request.form.get('sender_info', 'Unknown').strip()
    if not text:
        flash("Please enter text.", "warning")
        return redirect(url_for('dashboard'))

    try:
        result = scan_logic(body=text, sender=sender if sender else "Unknown")
        log_scan("text", result, sender=sender if sender else "Unknown", content=text, user_id=session['user']['id'])
        return render_template('scanner.html', result=result, mode='text', user=session['user'])
    except Exception as e:
        flash(f"Scan failed: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/scan/url', methods=['POST'])
@login_required
def scan_url():
    url = request.form.get('url_content', '').strip()
    if not url:
        flash("Please enter a URL.", "warning")
        return redirect(url_for('dashboard'))

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        result = scan_logic(body=url, sender=url)
        log_scan("url", result, sender=url, content=url, user_id=session['user']['id'])
        return render_template('scanner.html', result=result, mode='url', user=session['user'])
        
    except ValueError:
        flash("Invalid URL format. Please enter a valid website link.", "danger")
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f"An error occurred while scanning: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/scan/image', methods=['POST'])
@login_required
def scan_image():
    if 'file_upload' not in request.files: return redirect(url_for('dashboard'))
    file = request.files['file_upload']
    if file.filename == '': return redirect(url_for('dashboard'))

    if check_file_extension(file.filename) == "High Risk":
        flash("File blocked: Dangerous extension.", "danger")
        return redirect(url_for('dashboard'))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    extracted_text = run_ocr(filepath)
    
    if extracted_text and extracted_text.strip():
        # Get sender from user input instead of auto-detecting from text
        sender_info = request.form.get('sender_info_image', '').strip()
        
        if sender_info:
            detected_sender = sender_info
        else:
            detected_sender = "Image_OCR"

        try:
            result = scan_logic(body=extracted_text, sender=detected_sender)
            log_scan("image", result, sender=detected_sender, content=extracted_text, user_id=session['user']['id'])
            return render_template('scanner.html', result=result, extracted_text=extracted_text, mode='image', user=session['user'])
        except Exception as e:
            flash(f"Scan failed: {str(e)}", "danger")
            return redirect(url_for('dashboard'))
    else:
        flash("No text extracted.", "warning")
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)