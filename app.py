from flask import Flask, request, render_template, redirect, url_for, flash, session
from functools import wraps
import os
import sys
import re
import json
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()  # read .env if present (local dev / exhibit config)

# --- SCANNING BACKEND ---
# The phishing engine now lives in the "OLD BACKEND" folder. Its folder name
# contains a space, so we add it to sys.path and import the module directly.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "OLD BACKEND"))
from phish_scanner import scan_logic

# --- CUSTOM MODULE IMPORTS ---
from utils.ocr import run_ocr
from utils.security_filter import check_file_extension
from utils.email_parser import parse_eml_file, check_header_spoofing, extract_sender_domain
from utils.dns_verifier import verify_email_authenticity, analyze_sender_domain

# DATABASE IMPORTS (local SQLite -- no internet required)
from database import (
    init_db, seed_demo_data,
    register_user, authenticate_user,
    log_scan, create_user_profile, get_user_profile, update_user_profile,
    verify_user_password, change_user_password,
    get_scan_history, delete_scan_log, clear_scan_history,
    ensure_guest_user,
)

app = Flask(__name__)
# Session key from .env (SECRET_KEY); HOOKD_SECRET_KEY kept as a fallback.
app.secret_key = os.environ.get('SECRET_KEY') or os.environ.get('HOOKD_SECRET_KEY', 'dev-only-change-me')

# --- DEMO / GUEST MODE ---
# DEV_MODE=1 skips login and uses a shared local guest account (instant demo).
# Default OFF: the app uses real local accounts.
DEV_MODE = os.environ.get('DEV_MODE', '0') != '0'
DEV_USER = {'id': 'local-guest', 'email': 'guest@localhost', 'name': 'Guest'}

# Max characters accepted for a single scan's content (keeps the DB tidy).
MAX_SCAN_CHARS = 20000

# --- LOCAL DATABASE SETUP ---
# Creates the SQLite file/tables on first run and seeds a demo account.
init_db()
seed_demo_data()
if DEV_MODE:
    ensure_guest_user()  # so guest scans can still be logged to history

# --- UPLOAD CONFIG ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- AUTH DECORATOR ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if DEV_MODE and 'user' not in session:
            session['user'] = DEV_USER  # auto-login guest for instant demo
        if 'user' not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html', user=session.get('user'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = authenticate_user(email, password)
        if user:
            display_name = user.get('display_name') or user['email'].split('@')[0]
            session['user'] = {
                'id': user['id'],
                'email': user['email'],
                'name': display_name
            }
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed: incorrect email or password.", "danger")

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        display_name = f"{first_name} {last_name}".strip()

        if not email or not password:
            flash("Email and password are required.", "warning")
            return render_template('signup.html')

        try:
            user_id = register_user(email, password, first_name, last_name)
            create_user_profile(user_id, first_name, last_name, display_name)
            flash("Account created! Please log in.", "success")
            return redirect(url_for('login'))
        except ValueError as e:
            flash(f"Signup failed: {str(e)}", "danger")
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

@app.route('/clear_history', methods=['POST'])
@login_required
def clear_history():
    deleted = clear_scan_history(session['user']['id'])
    if deleted:
        flash(f"Cleared {deleted} scan(s) from your history.", "success")
    else:
        flash("History is already empty.", "info")
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

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user_id = session['user']['id']
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()

    if update_user_profile(user_id, first_name, last_name):
        # Keep the name shown in the navbar/session in sync.
        session['user']['name'] = f"{first_name} {last_name}".strip()
        session.modified = True
        flash("Profile updated.", "success")
    else:
        flash("Could not update profile.", "danger")
    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    user_id = session['user']['id']
    current = request.form.get('current_password', '')
    new = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')

    if not current or not new:
        flash("Please fill in all password fields.", "warning")
    elif not verify_user_password(user_id, current):
        flash("Current password is incorrect.", "danger")
    elif len(new) < 6:
        flash("New password must be at least 6 characters.", "warning")
    elif new != confirm:
        flash("New passwords do not match.", "warning")
    elif change_user_password(user_id, new):
        flash("Password updated successfully.", "success")
    else:
        flash("Could not update password.", "danger")
    return redirect(url_for('profile'))

@app.route('/about')
def about():
    return render_template('about.html', user=session.get('user'))

@app.route('/metrics')
def metrics():
    results = None
    try:
        with open(os.path.join(BASE_DIR, 'results.json'), encoding='utf-8') as f:
            results = json.load(f)
    except Exception:
        results = None
    return render_template('metrics.html', user=session.get('user'), results=results)

# --- SCANNING ROUTES ---

@app.route('/scan/text', methods=['POST'])
@login_required
def scan_text():
    text = request.form.get('text_content', '').strip()
    sender = request.form.get('sender_info', 'Unknown').strip()
    if not text:
        flash("Please enter text.", "warning")
        return redirect(url_for('dashboard'))

    if len(text) > MAX_SCAN_CHARS:
        flash(f"Text is too long (max {MAX_SCAN_CHARS:,} characters).", "warning")
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

    if len(url) > 2048:
        flash("URL is too long.", "warning")
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

    try:
        extracted_text = run_ocr(filepath)
    except Exception as e:
        # Most commonly: the Tesseract OCR engine isn't installed. Show a clear
        # message instead of crashing with a 500 page.
        flash(f"Image scanning unavailable: {e}", "warning")
        return redirect(url_for('dashboard'))

    # OCR output length is unpredictable -- cap it to keep scans/DB tidy.
    if extracted_text and len(extracted_text) > MAX_SCAN_CHARS:
        extracted_text = extracted_text[:MAX_SCAN_CHARS]

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
    # Configurable via .env. host 0.0.0.0 lets other devices on the same
    # network (e.g. a phone scanning the booth QR) reach the app.
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=debug)