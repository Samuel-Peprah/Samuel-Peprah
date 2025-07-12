
import os
from datetime import datetime, timezone, timedelta
from flask import Flask, abort, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
#from moviepy.editor import VideoFileClip
from moviepy.video.io.ffmpeg_tools import ffmpeg_extract_subclip
from moviepy.video.io.VideoFileClip import VideoFileClip # Keep this line, it's correct
from moviepy.video.VideoClip import TextClip, ImageClip
import moviepy.video.io.ffmpeg_tools as ffmpeg_tools
import moviepy.video.compositing.CompositeVideoClip
from moviepy.video.VideoClip import VideoClip
import uuid
from collections import defaultdict
from PIL import Image
from flask_moment import Moment
from flask import Response, send_file
from config import APP_VERSION
import subprocess
from flask_login import current_user
from dotenv import load_dotenv
import requests, hmac, hashlib, json
from functools import wraps
from collections import defaultdict
import re
from datetime import datetime, timedelta
import csv
import secrets
from functools import wraps
from io import StringIO
from flask_login import current_user
from flask import (
    Flask, abort, render_template, request, redirect, url_for, flash, jsonify,
    session
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
load_dotenv()
from flask_wtf.csrf import CSRFProtect


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

TAXONOMY = {
    "otpf_domains": [
        "Activities of Daily Living (ADLs)",
        "Instrumental Activities of Daily Living (IADLs)",
        "Health Management",
        "Rest and Sleep",
        "Education",
        "Work",
        "Play",
        "Leisure",
        "Social Participation",
        "Client Factors",
        "Performance Skills",
        "Performance Patterns",
        "Context and Environment"
    ],
    "fors": [
        "Biomechanical Frame of Reference",
        "Rehabilitative Frame of Reference",
        "Cognitive-Behavioral Frame of Reference",
        "Developmental Frame of Reference",
        "Sensory Integration Frame of Reference",
        "Motor Control/Motor Learning Frame of Reference",
        "Neurodevelopmental Treatment (NDT) Frame of Reference",
        "Psychodynamic Frame of Reference",
        "Human Occupation Model (MOHO)",
        "Model of Human Occupation (MOHO)",
        "Ecology of Human Performance (EHP)",
        "Person-Environment-Occupation-Performance (PEOP) Model",
        "Canadian Model of Occupational Performance (CMOP)",
        "Kawa Model",
        "Occupational Adaptation Model"
    ],
    "conditions": [
        "Stroke (CVA)",
        "Traumatic Brain Injury (TBI)",
        "Spinal Cord Injury (SCI)",
        "Cerebral Palsy",
        "Autism Spectrum Disorder",
        "Developmental Delays",
        "Down Syndrome",
        "Multiple Sclerosis",
        "Parkinson's Disease",
        "Alzheimer's Disease/Dementia",
        "Arthritis",
        "Amputations",
        "Burns",
        "Chronic Pain",
        "Mental Health Disorders (e.g., Depression, Anxiety, Schizophrenia)",
        "Hand Injuries",
        "Carpal Tunnel Syndrome",
        "Tendon Injuries",
        "Visual Perceptual Deficits",
        "Sensory Processing Disorder",
        "Learning Disabilities",
        "Attention Deficit Hyperactivity Disorder (ADHD)",
        "Post-surgical Rehabilitation",
        "Work-related Injuries",
        "Geriatric Conditions",
        "Pediatric Conditions",
        "Oncology-related Conditions"
    ]
}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") or "Atom-De-Legend"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'portal.db') + '?timeout=30'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['PAYSTACK_SEC_KEY'] = os.getenv("PAYSTACK_SEC_KEY")
app.config['PAYSTACK_PUB_KEY'] = os.getenv("PAYSTACK_PUB_KEY")
app.config['PAYSTACK_WEBHOOK_SECRET'] = os.getenv("PAYSTACK_WEBHOOK_SECRET")

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
moment = Moment(app)
csrf = CSRFProtect(app)


# models.py
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email    = db.Column(db.String(120), unique=True)
    invite_code_used = db.Column(db.String(36))
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(32), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Media(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    thumbnail = db.Column(db.String(200))
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(80), nullable=True)
    otpf_domain = db.Column(db.String(50))
    for_name = db.Column(db.String(50))
    target_condition = db.Column(db.String(50))
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    view_count = db.Column(db.Integer, default=0)
    uploader = db.relationship('User', backref='media')
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)

class WatchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    media_id = db.Column(db.Integer, db.ForeignKey('media.id'))
    progress_percent = db.Column(db.Integer, default=0)
    completed = db.Column(db.Boolean, default=False)
    watched_at = db.Column(db.DateTime, default=datetime.utcnow)

class Plan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    amount_pesewas = db.Column(db.Integer, nullable=False)  # 1000 = GHS 10
    interval_days = db.Column(db.Integer, nullable=False, default=30)
    is_active = db.Column(db.Boolean, default=True)

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('plan.id'), nullable=False)
    ref = db.Column(db.String(100), nullable=False, unique=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

    user = db.relationship('User', backref=db.backref('subscriptions', lazy=True))
    plan = db.relationship('Plan')



# --- CSRF Protection Setup ---
# def generate_csrf_token():
#     """Generates a random token for CSRF protection."""
#     if '_csrf_token' not in session:
#         session['_csrf_token'] = secrets.token_hex(16) # 16 bytes = 32 hex chars
#     return session['_csrf_token']

# def csrf_required(f):
#     """
#     Decorator to check CSRF token on POST requests.
#     Apply this to routes that handle form submissions (POST methods).
#     """
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if request.method == 'POST':
#             # Check for the token in form data
#             submitted_token = request.form.get('_csrf_token')
#             session_token = session.get('_csrf_token')

#             if not submitted_token or submitted_token != session_token:
#                 flash('Invalid CSRF token. Please try again.', 'danger')
#                 # For security, redirect to the referring page or home
#                 # You might want to log this attempt.
#                 return redirect(request.referrer or url_for('index'))
#         return f(*args, **kwargs)
#     return decorated_function

# # Add the CSRF token to all templates contextually
# @app.context_processor
# def inject_csrf_token():
#     return dict(csrf_token=generate_csrf_token)

# @app.context_processor
# def inject_version():
#     return dict(app_version=APP_VERSION)

@app.context_processor
def inject_global_data():
    """
    Injects global data into all templates.
    This includes app version, current UTC time, and subscription status.
    """
    # Initialize has_sub to False for unauthenticated users or if current_user is not available
    has_sub = False
    if current_user.is_authenticated:
        has_sub = has_active_subscription(current_user)

    return {
        'app_version': APP_VERSION,  # Assuming APP_VERSION is defined globally or from config
        'utc_now': datetime.now(timezone.utc),
        'has_active_subscription': has_active_subscription, # Make the function itself available
        'current_user': current_user, # Flask-Login usually injects this, but explicit is fine
        'user_has_active_subscription': has_sub # A boolean flag for simpler checks in templates
    }


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# @app.context_processor
# def inject_utc_now():
#     return {'utc_now': datetime.now(timezone.utc)}

# @app.before_app_first_request
# def create_tables():
#     db.create_all()
#     # seed demo users
#     if not User.query.filter_by(username='therapist').first():
#         t = User(username='therapist', role='therapist')
#         t.set_password('pass')
#         db.session.add(t)
#     if not User.query.filter_by(username='client').first():
#         c = User(username='client', role='client')
#         c.set_password('pass')
#         db.session.add(c)
#     db.session.commit()


PAYSTACK_HEADERS = {"Authorization": f"Bearer {app.config['PAYSTACK_SEC_KEY']}"}

# def subscription_required(fn):
#     @wraps(fn)
#     def _wrap(*a, **kw):
#         if (not current_user.is_authenticated or
#             not current_user.subscription or
#             current_user.subscription.current_period_end < datetime.utcnow()):
#             flash("Please pick a plan to unlock TherapTube 📺", "warning")
#             return redirect(url_for("pricing"))
#         return fn(*a, **kw)
#     return _wrap

@app.route("/pricing")
def pricing():
    plans = Plan.query.filter_by(is_active=True).all()
    current_utc_year = datetime.now(timezone.utc).year
    return render_template("pricing.html",
                            plans=plans,
                            current_year=current_utc_year,
                            taxonomy=TAXONOMY,
                            pub_key=app.config["PAYSTACK_PUB_KEY"])



# @app.post("/paystack/verify")
# @login_required
# def paystack_verify():
#     data = request.get_json(force=True)
#     ref  = data["ref"]; plan_id = int(data["plan_id"])

#     # 1. verify with Paystack
#     r = requests.get(f"https://api.paystack.co/transaction/verify/{ref}",
#                         headers=PAYSTACK_HEADERS, timeout=10)
#     js = r.json()
#     if not (js.get("status") and js["data"]["status"] == "success"):
#         return {"ok": False}, 400

#     # 2. mark / extend subscription
#     plan = Plan.query.get_or_404(plan_id)
#     sub  = current_user.subscription
#     from datetime import datetime, timedelta
#     now  = datetime.utcnow()

#     if sub and sub.current_period_end > now:      # extend
#         sub.current_period_end += timedelta(days=plan.interval_days)
#     else:                                         # new sub
#         sub = Subscription(user=current_user,
#                             plan=plan,
#                             current_period_end = now + timedelta(days=plan.interval_days))
#         db.session.add(sub)
#     sub.status       = "active"
#     sub.last_tx_ref  = ref
#     db.session.commit()
#     return {"ok": True}


@app.post("/ps_webhook")
def paystack_webhook():
    raw  = request.get_data()
    sign = request.headers.get("x-paystack-signature","")
    secret = app.config["PAYSTACK_WEBHOOK_SECRET"].encode()
    if hmac.new(secret, raw, hashlib.sha512).hexdigest() != sign:
        abort(400)

    event = json.loads(raw)
    if event["event"] == "charge.success":
        ref = event["data"]["reference"]
        _handle_charge_success(ref)
    return {"status": "ok"}

def _handle_charge_success(ref):
    """
    Handle successful charge event from Paystack webhook.
    """
    # 1. Get the subscription by reference
    sub = Subscription.query.filter_by(last_tx_ref=ref).first()
    if not sub:
        print(f"⚠️ No subscription found for ref {ref}")
        return

    # 2. Update the subscription status
    sub.status = "active"
    db.session.commit()

    print(f"✅ Subscription {sub.id} activated for user {sub.user.username} with ref {ref}")



# def has_active_subscription(user):
#     latest = Subscription.query.filter_by(user_id=user.id).order_by(Subscription.timestamp.desc()).first()
#     if not latest:
#         return False
#     return latest.expires_at >= datetime.utcnow()

def has_active_subscription(user):
    if not user.is_authenticated or user.role != 'client':
        return False
    latest = Subscription.query.filter_by(user_id=user.id).order_by(Subscription.timestamp.desc()).first()
    if not latest:
        return False
    return latest.expires_at >= datetime.utcnow()


# @app.route("/paystack/verify", methods=["POST"])
# @login_required
# @csrf_required
# def verify_payment():
#     data = request.get_json()
#     ref = data.get("ref")
#     plan_id = data.get("plan_id")

#     plan = Plan.query.get(plan_id)
#     if not plan:
#         return jsonify({"error": "Invalid plan."}), 400

#     # Verify with Paystack
#     headers = {
#         "Authorization": f"Bearer {app.config['PAYSTACK_SEC_KEY']}"
#     }
#     url = f"https://api.paystack.co/transaction/verify/{ref}"
#     res = requests.get(url, headers=headers)
#     response = res.json()

#     if response.get("status") and response["data"]["status"] == "success":
#         # Store subscription
#         sub = Subscription(
#             user_id=current_user.id,
#             plan_id=plan.id,
#             ref=ref,
#             expires_at=datetime.utcnow() + timedelta(days=plan.interval_days)
#         )
#         db.session.add(sub)
#         db.session.commit()
#         return jsonify({"success": True})

#     return jsonify({"error": "Verification failed."}), 400


@app.route("/paystack/verify", methods=["POST"])
@login_required
def verify_payment():
    data = request.get_json()
    ref = data.get("ref")
    plan_id = data.get("plan_id")

    plan = Plan.query.get(plan_id)
    if not plan:
        return jsonify({"error": "Invalid plan."}), 400

    # Verify with Paystack
    headers = {
        "Authorization": f"Bearer {app.config['PAYSTACK_SEC_KEY']}" # <-- CORRECTED KEY NAME HERE
    }
    url = f"https://api.paystack.co/transaction/verify/{ref}"
    
    try:
        res = requests.get(url, headers=headers, timeout=10) # Added timeout for good practice
        res.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        response = res.json()
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Paystack API request failed: {e}")
        return jsonify({"error": "Failed to connect to payment gateway."}), 500
    except json.JSONDecodeError as e:
        print(f"ERROR: Paystack API response not valid JSON: {res.text} - {e}")
        return jsonify({"error": "Invalid response from payment gateway."}), 500


    if response.get("status") and response["data"]["status"] == "success":
        # Store subscription
        sub = Subscription(
            user_id=current_user.id,
            plan_id=plan.id,
            ref=ref,
            expires_at=datetime.utcnow() + timedelta(days=plan.interval_days)
        )
        db.session.add(sub)
        db.session.commit()
        return jsonify({"success": True})

    # If Paystack verification status is not success
    error_message = response.get("message", "Payment verification failed.")
    return jsonify({"error": error_message}), 400


def subscription_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # --- NEW LOGIC: Allow therapists to bypass subscription check ---
        if current_user.is_authenticated and current_user.role == 'therapist':
            return f(*args, **kwargs) # Therapists can proceed
        # --- END NEW LOGIC ---

        # Existing logic for clients and other roles: check for active subscription
        # This will also handle unauthenticated users if has_active_subscription
        # returns False for them. Make sure has_active_subscription handles None/anonymous user.
        if not has_active_subscription(current_user):
            flash("You must subscribe to access this page.", "warning")
            return redirect(url_for("pricing"))
        return f(*args, **kwargs)
    return wrapper





# def make_thumbnail(video_path: str, thumb_path: str):
#     """
#     Grab the first frame at t=1 s and save as 320 px‑wide JPG.
#     """
#     try:
#         clip = VideoFileClip(video_path).subclip(1, 2)   # 1 → 2 s slice
#         frame = clip.get_frame(0)                        # numpy array
#         clip.close()

#         img = Image.fromarray(frame)
#         img.thumbnail((320, 320))                        # keep aspect, max 320 px
#         img.save(thumb_path, "JPEG", quality=80)
#     except Exception as e:
#         print("❗ thumbnail error:", e)


# --- NEW make_thumbnail_ffmpeg function ---
def make_thumbnail_ffmpeg(video_path: str, thumb_path: str, time_point="00:00:01"):
    """
    Generates a thumbnail using ffmpeg directly from a video file.
    Args:
        video_path (str): The full path to the input video file.
        thumb_path (str): The full path where the thumbnail JPEG should be saved.
        time_point (str): The timestamp in the video to extract the frame from (e.g., "00:00:01" for 1 second).
    """
    try:
        # Ensure the directory for the thumbnail exists
        os.makedirs(os.path.dirname(thumb_path), exist_ok=True)

        # ffmpeg command to extract a single frame
        # -ss: seek to the specified time
        # -i: input file
        # -vframes 1: extract only one frame
        # -q:v 2: video quality (2 is good, 1 is best, 31 is worst)
        # -vf scale=320:-1: resize to 320px width, maintaining aspect ratio
        # -y: overwrite output files without asking
        command = [
            'ffmpeg',
            '-ss', time_point,
            '-i', video_path,
            '-vframes', '1',
            '-q:v', '2',
            '-vf', 'scale=320:-1',
            '-y',
            thumb_path
        ]
        # Run the command and check for errors
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"DEBUG: FFmpeg thumbnail generated: {thumb_path}")
    except subprocess.CalledProcessError as e:
        print(f"❗ FFmpeg thumbnail error for {video_path}: {e}")
        print(f"FFmpeg stdout: {e.stdout.decode('utf-8')}")
        print(f"FFmpeg stderr: {e.stderr.decode('utf-8')}")
        raise # Re-raise to ensure Flask sees the error
    except Exception as e:
        print(f"❗ General thumbnail error for {video_path}: {e}")
        raise # Re-raise to ensure Flask sees the error


# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if current_user.is_authenticated:
#         return redirect(url_for('index'))

#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         email    = request.form['email']
#         token    = request.form['invite_token'].strip()

#         if User.query.filter_by(username=username).first():
#             flash('Username already exists')
#             return redirect(url_for('register'))

#         new_user = User(username=username, email=email)
#         new_user.set_password(password)

#         # If invite token matches, elevate to therapist
#         if token and token == os.environ.get("THERAPIST_TOKEN"):
#             new_user.role = 'therapist'
#             new_user.invite_code_used = token
#         else:
#             new_user.role = 'client'

#         db.session.add(new_user)
#         db.session.commit()
#         login_user(new_user)
#         flash('Registration successful. Welcome!')
#         return redirect(url_for('admin_dashboard' if new_user.role == 'therapist' else 'index'))

#     return render_template('register.html', taxonomy=TAXONOMY,)

# @app.route('/register', methods=['GET', 'POST'])
# @csrf_required
# def register():
#     if current_user.is_authenticated:
#         return redirect(url_for('index'))

#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         email    = request.form['email']
#         token    = request.form['invite_token'].strip()

#         if User.query.filter_by(username=username).first():
#             flash('Username already exists', 'danger') # Added 'danger' category for styling
#             return redirect(url_for('register'))

#         new_user = User(username=username, email=email)
#         new_user.set_password(password)

#         # If invite token matches, elevate to therapist
#         if token and token == os.environ.get("THERAPIST_TOKEN"):
#             new_user.role = 'therapist'
#             new_user.invite_code_used = token
#         else:
#             new_user.role = 'client'

#         db.session.add(new_user)
#         db.session.commit()

#         if new_user.role == 'client':
#             # For clients, do NOT automatically log them in.
#             # Redirect them to the pricing page to choose a plan.
#             flash('Registration successful! Please choose a subscription plan to access content.', 'info')
#             return redirect(url_for('pricing'))
#         else: # For 'therapist' role, log them in directly
#             login_user(new_user)
#             flash('Registration successful. Welcome, Therapist!', 'success')
#             return redirect(url_for('admin_dashboard'))

#     return render_template('register.html', taxonomy=TAXONOMY)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email    = request.form['email']
        token    = request.form['invite_token'].strip()

        # Basic validation for password and confirmation (assuming you have this in your frontend/form)
        # If you want to add password mismatch check, you can uncomment/add this:
        # if 'confirm_password' in request.form and request.form['password'] != request.form['confirm_password']:
        #     flash('Passwords do not match.', 'danger')
        #     return render_template('register.html', taxonomy=TAXONOMY, username=username, email=email, invite_token=token)

        # Check for existing username/email
        errors = []
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            for error in errors:
                flash(error, 'danger')
            # Render the template again, preserving user input
            return render_template('register.html', taxonomy=TAXONOMY,
                                    username=username, email=email, invite_token=token)


        new_user = User(username=username, email=email)
        new_user.set_password(password)

        # If invite token matches, elevate to therapist
        if token and token == os.environ.get("THERAPIST_TOKEN"):
            new_user.role = 'therapist'
            new_user.invite_code_used = token
        else:
            new_user.role = 'client'

        db.session.add(new_user)
        db.session.commit()

        if new_user.role == 'client':
            # For clients, do NOT automatically log them in.
            # Redirect them to the pricing page to choose a plan.
            flash('Registration successful! Please choose a subscription plan to access content.', 'info')
            return redirect(url_for('pricing'))
        else: # For 'therapist' role, log them in directly
            login_user(new_user)
            flash('Registration successful. Welcome, Therapist!', 'success')
            # <--- THE KEY CHANGE HERE: Redirect therapist to their dedicated dashboard
            return redirect(url_for('therapist_dashboard'))

    return render_template('register.html', taxonomy=TAXONOMY)




# @app.route('/')
# def index():
#     media = Media.query.order_by(Media.upload_time.desc()).all()
#     current_utc_year = datetime.now(timezone.utc).year
#     return render_template('index.html', media=media, taxonomy=TAXONOMY, current_year=current_utc_year)

# @app.route('/')
# def index():
#     current_utc_year = datetime.now(timezone.utc).year
#     if current_user.is_authenticated and current_user.role == 'client' and not has_active_subscription(current_user):
#         flash("Your subscription has expired or is not active. Please subscribe to continue.", "warning")
#         return redirect(url_for('pricing'))

#     media = Media.query.order_by(Media.upload_time.desc()).all()
#     return render_template('index.html', media=media, taxonomy=TAXONOMY, current_year=current_utc_year)


@app.route('/')
def index():
    current_utc_year = datetime.now(timezone.utc).year
    return render_template('index.html' , current_year=current_utc_year, taxonomy=TAXONOMY, 
                            media=Media.query.order_by(Media.upload_time.desc()).all())


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         user = User.query.filter_by(username=request.form['username']).first()
#         if user and user.check_password(request.form['password']):
#             login_user(user)
#             return redirect(url_for('index'))
#         flash('Invalid credentials')
#     return render_template('login.html', taxonomy=TAXONOMY)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user) # Log in the user first

            # Redirect based on user role
            if user.role == 'client':
                if not has_active_subscription(user):
                    flash("Your subscription has expired or is not active. Please subscribe to continue.", "warning")
                    return redirect(url_for('pricing'))
                else:
                    flash('Login successful. Welcome back!', 'success')
                    return redirect(url_for('index')) # Clients go to the main index (content view)
            else: # user.role == 'therapist'
                flash('Login successful. Welcome back, Therapist!', 'success')
                return redirect(url_for('therapist_dashboard')) # <--- UPDATED: Therapists go to their new dashboard
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html', taxonomy=TAXONOMY)


@app.cli.command("gen-invite")
def gen_invite():
    import uuid
    token = uuid.uuid4().hex[:8]
    print(f"Therapist invite token: {token}")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# @app.route('/upload', methods=['GET', 'POST'])
# @login_required
# def upload():
#     if current_user.role != 'therapist':
#         flash('Only therapists can upload.')
#         return redirect(url_for('index'))
#     if request.method == 'POST':
#         f = request.files['file']
#         if f and f.filename:
#             filename = secure_filename(f.filename)
#             os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
#             f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
#             media = Media(
#                 filename=filename,
#                 title=request.form['title'],
#                 description=request.form['description'],
#                 category=request.form['category'],
#                 otpf_domain=request.form['otpf_domain'],
#                 for_name=request.form['for_name'],
#                 target_condition=request.form['target_condition'],
#                 uploader_id=current_user.id)
#             db.session.add(media)
#             db.session.commit()
#             flash('Uploaded successfully.')
#             return redirect(url_for('index'))
#     return render_template('upload.html', taxonomy=TAXONOMY)


@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'therapist':
        abort(403)

    all_media     = Media.query.order_by(Media.upload_time.desc()).all()
    total_uploads = Media.query.count()
    total_views   = db.session.query(db.func.sum(Media.view_count)).scalar() or 0
    total_clients= User.query.filter_by(role='client').count()
    total_therapists = User.query.filter_by(role='therapist').count()
    top10         = Media.query.order_by(Media.view_count.desc()).limit(10).all()
    current_utc_year = datetime.now(timezone.utc).year
    token= os.getenv("THERAPIST_TOKEN", "atom-de-legend")
    

    # Chart 1: Top media
    chart_labels  = [m.title[:20] + ('…' if len(m.title) > 20 else '') for m in top10]
    chart_views   = [m.view_count for m in top10]

    # Chart 2: Views per condition (pie chart)
    condition_views = defaultdict(int)
    for media in all_media:
        condition_views[media.target_condition] += media.view_count or 0
    condition_labels = list(condition_views.keys())
    condition_data   = list(condition_views.values())

    return render_template('admin_dashboard.html',
        media=all_media,
        total_uploads=total_uploads,
        total_views=total_views,
        chart_labels=chart_labels,
        chart_views=chart_views,
        condition_labels=condition_labels,
        condition_data=condition_data,
        top10=top10,
        token=token,
        total_clients=total_clients,
        total_therapists=total_therapists,
        taxonomy=TAXONOMY,
        current_year=current_utc_year
    )


# @app.route('/media/<int:media_id>/edit', methods=['GET', 'POST'])
# @login_required
# @csrf_required
# def edit_media(media_id):
#     media = Media.query.get_or_404(media_id)

#     # Only allow the uploader or therapist role to edit
#     if current_user.id != media.uploader_id and current_user.role != 'therapist':
#         flash("You don't have permission to edit this media.")
#         return redirect(url_for('admin_dashboard'))

#     if request.method == 'POST':
#         media.title = request.form['title']
#         media.description = request.form['description']
#         media.category = request.form['category']
#         media.otpf_domain = request.form['otpf_domain']
#         media.for_name = request.form['for_name']
#         media.target_condition = request.form['target_condition']
#         db.session.commit()
#         flash('Media updated successfully.')
#         return redirect(url_for('admin_dashboard'))

#     return render_template('edit_media.html', media=media, taxonomy=TAXONOMY)


# @app.route('/media/<int:media_id>/delete', methods=['POST'])
# @login_required
# @csrf_required
# def delete_media(media_id):
#     media = Media.query.get_or_404(media_id)

#     # Only uploader or therapist can delete
#     if current_user.id != media.uploader_id and current_user.role != 'therapist':
#         flash("You don't have permission to delete this media.")
#         return redirect(url_for('admin_dashboard'))

#     try:
#         # Remove media file from disk
#         os.remove(os.path.join(app.config['UPLOAD_FOLDER'], media.filename))
#     except Exception as e:
#         print(f"Error deleting file: {e}")

#     db.session.delete(media)
#     db.session.commit()
#     flash('Media deleted successfully.')
#     return redirect(url_for('admin_dashboard'))


@app.route('/media/<int:media_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_media(media_id):
    media = Media.query.get_or_404(media_id)

    # Only allow the uploader or therapist role to edit
    if current_user.id != media.uploader_id and current_user.role != 'therapist':
        flash("You don't have permission to edit this media.", 'danger') # Added category
        return redirect(url_for('therapist_dashboard')) # <--- UPDATED: Redirect to therapist dashboard

    if request.method == 'POST':
        media.title = request.form['title']
        media.description = request.form['description']
        media.category = request.form.get('category')
        media.otpf_domain = request.form['otpf_domain']
        media.for_name=request.form.get('for_name')
        media.target_condition = request.form.get('target_condition')
        db.session.commit()
        flash('Media updated successfully.', 'success') # Added category
        return redirect(url_for('therapist_dashboard')) # <--- UPDATED: Redirect to therapist dashboard

    return render_template('edit_media.html', media=media, taxonomy=TAXONOMY)


# app.py (Modified delete_media route)
@app.route('/media/<int:media_id>/delete', methods=['POST'])
@login_required
def delete_media(media_id):
    media = Media.query.get_or_404(media_id)

    # Only uploader or therapist can delete
    if current_user.id != media.uploader_id and current_user.role != 'therapist':
        flash("You don't have permission to delete this media.", 'danger') # Added category
        return redirect(url_for('therapist_dashboard')) # <--- UPDATED: Redirect to therapist dashboard

    try:
        # Remove media file from disk
        # Ensure thumbnail is also deleted if it's a separate file
        if media.thumbnail and media.thumbnail != media.filename:
            thumb_path = os.path.join(app.config['UPLOAD_FOLDER'], 'thumbs', media.thumbnail)
            if os.path.exists(thumb_path):
                os.remove(thumb_path)
                print(f"DEBUG: Thumbnail removed: {thumb_path}")

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], media.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"DEBUG: Media file removed: {file_path}")
        else:
            print(f"WARNING: Media file not found on disk: {file_path}")

    except Exception as e:
        print(f"ERROR: Error deleting media files for {media.filename}: {e}")
        flash(f"Error deleting associated files: {e}", 'danger')
        # Even if file deletion fails, we should still try to remove DB record

    db.session.delete(media)
    db.session.commit()
    flash('Media deleted successfully.', 'success')
    return redirect(url_for('therapist_dashboard'))






# @app.route('/upload', methods=['GET', 'POST'])
# @login_required
# def upload():
#     if current_user.role != 'therapist':
#         flash('Only therapists can upload.')
#         return redirect(url_for('index'))

#     if request.method == 'POST':
#         f = request.files['file']
#         if f and f.filename:
#             # ---------- give every file a unique UUID name ----------
#             ext = os.path.splitext(f.filename)[1].lower()         # .mp4 / .jpg …
#             filename = f"{uuid.uuid4().hex}{ext}"
#             save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
#             f.save(save_path)

#             # ---------- build a thumbnail if it’s a video ----------
#             video_exts = ('.mp4', '.mov', '.mkv', '.avi', '.webm')
#             if ext in video_exts:
#                 thumb_name = f"{os.path.splitext(filename)[0]}.jpg"
#                 thumb_path = os.path.join(app.config['UPLOAD_FOLDER'],
#                                         'thumbs', thumb_name)
#                 make_thumbnail(save_path, thumb_path)
#             else:                               # images use themselves
#                 thumb_name = filename

#             # ---------- save DB record ----------
#             media = Media(
#                 filename=filename,
#                 thumbnail=thumb_name,
#                 title=request.form['title'],
#                 description=request.form['description'],
#                 category=request.form['category'],
#                 otpf_domain=request.form['otpf_domain'],
#                 for_name=request.form['for_name'],
#                 target_condition=request.form['target_condition'],
#                 uploader_id=current_user.id
#             )
#             db.session.add(media)
#             db.session.commit()

#             flash('Uploaded successfully.')
#             return redirect(url_for('index'))

#     return render_template('upload.html', taxonomy=TAXONOMY)


# @app.route('/upload', methods=['GET', 'POST'])
# @login_required
# def upload():
#     if current_user.role != 'therapist':
#         flash('Only therapists can upload.')
#         return redirect(url_for('index'))

#     if request.method == 'POST':
#         f = request.files['file']
#         if f and f.filename:
#             ext = os.path.splitext(f.filename)[1].lower()
#             original_filename = f"{uuid.uuid4().hex}{ext}"
#             original_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
#             os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
#             f.save(original_path)

#             # Convert video if it's not already in .mp4
#             video_exts = ('.mp4', '.mov', '.mkv', '.avi', '.webm')
#             if ext in video_exts:
#                 # Always convert to .mp4 for consistency
#                 converted_filename = f"{uuid.uuid4().hex}.mp4"
#                 converted_path = os.path.join(app.config['UPLOAD_FOLDER'], converted_filename)

#                 subprocess.run([
#                     'ffmpeg', '-i', original_path,
#                     '-vcodec', 'libx264', '-acodec', 'aac',
#                     '-strict', 'experimental', '-y', converted_path
#                 ])

#                 os.remove(original_path)  # optional: remove original upload

#                 # Generate thumbnail
#                 thumb_name = f"{os.path.splitext(converted_filename)[0]}.jpg"
#                 thumb_path = os.path.join(app.config['UPLOAD_FOLDER'], 'thumbs', thumb_name)
#                 make_thumbnail(converted_path, thumb_path)

#                 final_filename = converted_filename
#             else:
#                 # It's an image or already .mp4 — no conversion needed
#                 final_filename = original_filename
#                 thumb_name = final_filename

#             # Save to DB
#             media = Media(
#                 filename=final_filename,
#                 thumbnail=thumb_name,
#                 title=request.form['title'],
#                 description=request.form['description'],
#                 category=request.form['category'],
#                 otpf_domain=request.form['otpf_domain'],
#                 for_name=request.form['for_name'],
#                 target_condition=request.form['target_condition'],
#                 uploader_id=current_user.id
#             )
#             db.session.add(media)
#             db.session.commit()

#             flash('Uploaded and converted successfully.')
#             return redirect(url_for('index'))

#     return render_template('upload.html', taxonomy=TAXONOMY)


# @app.route('/upload', methods=['GET', 'POST'])
# @login_required
# @csrf_required
# def upload():
#     if current_user.role != 'therapist':
#         flash('Only therapists can upload.')
#         return redirect(url_for('index'))

#     if request.method == 'POST':
#         f = request.files['file']
#         if f and f.filename:
#             ext = os.path.splitext(f.filename)[1].lower()
#             original_filename = f"{uuid.uuid4().hex}{ext}"
#             original_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)

#             # Ensure the main upload folder exists
#             os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
#             f.save(original_path)

#             final_filename = None
#             thumb_name = None

#             video_exts = ('.mp4', '.mov', '.mkv', '.avi', '.webm')

#             if ext in video_exts:
#                 # Convert video to .mp4 for consistency and browser compatibility
#                 converted_filename = f"{uuid.uuid4().hex}.mp4"
#                 converted_path = os.path.join(app.config['UPLOAD_FOLDER'], converted_filename)

#                 print(f"DEBUG: Converting '{original_path}' to '{converted_path}'")
#                 try:
#                     subprocess.run([
#                         'ffmpeg', '-i', original_path,
#                         '-vcodec', 'libx264', '-acodec', 'aac',
#                         '-strict', 'experimental', '-y', converted_path
#                     ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#                     print("DEBUG: FFmpeg video conversion successful.")
#                 except subprocess.CalledProcessError as e:
#                     print(f"ERROR: FFmpeg conversion failed for {original_filename}: {e}")
#                     print(f"FFmpeg stdout: {e.stdout.decode('utf-8')}")
#                     print(f"FFmpeg stderr: {e.stderr.decode('utf-8')}")
#                     flash("Video conversion failed. Please try again with a different video file.", "error")
#                     # Clean up the original file if conversion fails
#                     if os.path.exists(original_path):
#                         os.remove(original_path)
#                     return redirect(url_for('upload'))
#                 except Exception as e:
#                     print(f"ERROR: General error during conversion for {original_filename}: {e}")
#                     flash("An unexpected error occurred during video conversion.", "error")
#                     if os.path.exists(original_path):
#                         os.remove(original_path)
#                     return redirect(url_for('upload'))


#                 # Remove original upload after successful conversion
#                 if os.path.exists(original_path):
#                     os.remove(original_path)
#                     print(f"DEBUG: Removed original file: {original_path}")

#                 final_filename = converted_filename

#                 # Generate thumbnail using the new ffmpeg-based function
#                 thumb_name = f"{os.path.splitext(final_filename)[0]}.jpg"
#                 thumb_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'thumbs')
#                 thumb_path = os.path.join(thumb_folder, thumb_name)

#                 try:
#                     make_thumbnail_ffmpeg(converted_path, thumb_path)
#                 except Exception as e:
#                     print(f"ERROR: Thumbnail generation failed for {final_filename}: {e}")
#                     flash("Thumbnail generation failed. Video uploaded but may not display a thumbnail.", "warning")
#                     # Continue even if thumbnail fails, but log it

#             else:
#                 # If it's not a video (e.g., an image), store it directly
#                 final_filename = original_filename
#                 # For images, the thumbnail is the image itself.
#                 # If you need to generate proper thumbnails for images (e.g., resize),
#                 # you'd add PIL.Image processing here.
#                 thumb_name = final_filename

#             # Save to DB
#             media = Media(
#                 filename=final_filename,
#                 thumbnail=thumb_name,
#                 title=request.form['title'],
#                 description=request.form['description'],
#                 category=request.form['category'],
#                 otpf_domain=request.form['otpf_domain'],
#                 for_name=request.form['for_name'],
#                 target_condition=request.form['target_condition'],
#                 uploader_id=current_user.id
#             )
#             db.session.add(media)
#             db.session.commit()

#             flash('Media uploaded successfully.')
#             return redirect(url_for('index'))
#         else:
#             flash('No file selected for upload.', 'warning')
#             return redirect(url_for('upload'))

#     return render_template('upload.html', taxonomy=TAXONOMY)


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    # Ensure only therapists can upload
    if current_user.role != 'therapist':
        flash('Only therapists can upload.', 'danger') # Added 'danger' category for consistency
        return redirect(url_for('index'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part in the request.', 'warning')
            return redirect(request.url) # Redirect back to the upload page

        f = request.files['file']
        if f.filename == '':
            flash('No selected file.', 'warning')
            return redirect(request.url)

        if f and f.filename:
            ext = os.path.splitext(f.filename)[1].lower()
            original_filename = f"{uuid.uuid4().hex}{ext}"
            original_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)

            # Ensure the main upload folder exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            f.save(original_path)

            final_filename = None
            thumb_name = None

            video_exts = ('.mp4', '.mov', '.mkv', '.avi', '.webm')

            if ext in video_exts:
                # Convert video to .mp4 for consistency and browser compatibility
                converted_filename = f"{uuid.uuid4().hex}.mp4"
                converted_path = os.path.join(app.config['UPLOAD_FOLDER'], converted_filename)

                print(f"DEBUG: Converting '{original_path}' to '{converted_path}'")
                try:
                    subprocess.run([
                        'ffmpeg', '-i', original_path,
                        '-vcodec', 'libx264', '-acodec', 'aac',
                        '-strict', 'experimental', '-y', converted_path
                    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    print("DEBUG: FFmpeg video conversion successful.")
                except subprocess.CalledProcessError as e:
                    print(f"ERROR: FFmpeg conversion failed for {original_filename}: {e}")
                    print(f"FFmpeg stdout: {e.stdout.decode('utf-8')}")
                    print(f"FFmpeg stderr: {e.stderr.decode('utf-8')}")
                    flash("Video conversion failed. Please try again with a different video file.", "danger") # Changed to 'danger'
                    # Clean up the original file if conversion fails
                    if os.path.exists(original_path):
                        os.remove(original_path)
                    return redirect(url_for('upload'))
                except Exception as e:
                    print(f"ERROR: General error during conversion for {original_filename}: {e}")
                    flash("An unexpected error occurred during video conversion.", "danger") # Changed to 'danger'
                    if os.path.exists(original_path):
                        os.remove(original_path)
                    return redirect(url_for('upload'))

                # Remove original upload after successful conversion
                if os.path.exists(original_path):
                    os.remove(original_path)
                    print(f"DEBUG: Removed original file: {original_path}")

                final_filename = converted_filename

                # Generate thumbnail using the new ffmpeg-based function
                thumb_name = f"{os.path.splitext(final_filename)[0]}.jpg"
                thumb_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'thumbs')
                os.makedirs(thumb_folder, exist_ok=True) # Ensure thumbs folder exists
                thumb_path = os.path.join(thumb_folder, thumb_name)

                try:
                    # make_thumbnail_ffmpeg function must be defined elsewhere in app.py
                    make_thumbnail_ffmpeg(converted_path, thumb_path)
                except Exception as e:
                    print(f"ERROR: Thumbnail generation failed for {final_filename}: {e}")
                    flash("Thumbnail generation failed. Video uploaded but may not display a thumbnail.", "warning")
                    # Continue even if thumbnail fails, but log it

            else:
                # If it's not a video (e.g., an image), store it directly
                final_filename = original_filename
                # For images, the thumbnail is the image itself.
                # If you need to generate proper thumbnails for images (e.g., resize),
                # you'd add PIL.Image processing here.
                thumb_name = final_filename

            # Save to DB
            media = Media(
                filename=final_filename,
                thumbnail=thumb_name,
                title=request.form['title'],
                description=request.form['description'],
                category=request.form['category'],
                otpf_domain=request.form['otpf_domain'],
                for_name=request.form['for_name'],
                target_condition=request.form['target_condition'],
                uploader_id=current_user.id
            )
            db.session.add(media)
            db.session.commit()

            flash('Media uploaded successfully.', 'success') # Added 'success' category
            return redirect(url_for('therapist_dashboard')) # <--- UPDATED: Redirect to therapist dashboard
        else:
            flash('No file selected for upload.', 'warning')
            return redirect(url_for('upload'))

    return render_template('upload.html', taxonomy=TAXONOMY)



# @app.route('/search')
# def search():
#     q = request.args.get('q', '')
#     condition = request.args.get('condition', '')
#     otpf_domain = request.args.get('otpf_domain', '')
#     query = Media.query
#     if q:
#         query = query.filter(
#             (Media.title.ilike(f'%{q}%')) |
#             (Media.description.ilike(f'%{q}%')) |
#             (Media.category.ilike(f'%{q}%'))
#         )
#     if condition:
#         query = query.filter_by(target_condition=condition)
#     if otpf_domain:
#         query = query.filter_by(otpf_domain=otpf_domain)
#     results = query.all()
#     return render_template('search.html', media=results, query=q, taxonomy=TAXONOMY)

@app.route('/search')
@login_required # Ensure user is logged in
@subscription_required # Ensure user has an active subscription (if client)
def search():
    # The subscription_required decorator will handle redirection for unsubscribed clients.
    # For therapists, the decorator will simply pass through.

    q = request.args.get('q', '')
    condition = request.args.get('condition', '')
    otpf_domain = request.args.get('otpf_domain', '')
    query = Media.query

    if q:
        query = query.filter(
            (Media.title.ilike(f'%{q}%')) |
            (Media.description.ilike(f'%{q}%')) |
            (Media.category.ilike(f'%{q}%'))
        )
    if condition:
        query = query.filter_by(target_condition=condition)
    if otpf_domain:
        query = query.filter_by(otpf_domain=otpf_domain)

    results = query.all()
    return render_template('search.html', media=results, query=q, taxonomy=TAXONOMY)

# @app.route('/media/<int:media_id>')
# def watch(media_id):
#     m = Media.query.get_or_404(media_id)
#     if current_user.is_authenticated:
#         wh = WatchHistory(user_id=current_user.id, media_id=m.id)
#         db.session.add(wh)
#         db.session.commit()
#     return render_template('watch.html', media=m, taxonomy=TAXONOMY)

# @app.route('/media/<int:media_id>')
# def watch(media_id):
#     m = Media.query.get_or_404(media_id)
#     current_utc_year = datetime.now(timezone.utc).year

#     if current_user.is_authenticated:
#         # Save to history
#         wh = WatchHistory(user_id=current_user.id, media_id=m.id)
#         db.session.add(wh)

#         # Increment view count
#         m.view_count = m.view_count + 1 if m.view_count else 1

#         db.session.commit()
    
#     # Get up to 6 related items
#     related = Media.query.filter(Media.id != media_id)\
#                         .order_by(Media.upload_time.desc())\
#                         .limit(6).all()

#     return render_template('watch.html', media=m, taxonomy=TAXONOMY, related=related, current_year=current_utc_year)


@app.route('/media/<int:media_id>')
@login_required # User must be logged in
@subscription_required # User must have an active subscription (if client)
def watch(media_id):
    # The decorators handle redirection for unauthenticated or unsubscribed clients.
    m = Media.query.get_or_404(media_id)
    current_utc_year = datetime.now(timezone.utc).year

    # These actions (saving history, incrementing view count) should only happen
    # if the user is authenticated and authorized to watch.
    # The decorators above ensure this.
    wh = WatchHistory(user_id=current_user.id, media_id=m.id)
    db.session.add(wh)

    # Increment view count
    m.view_count = m.view_count + 1 if m.view_count else 1

    db.session.commit()

    # Get up to 6 related items
    related = Media.query.filter(Media.id != media_id)\
                            .order_by(Media.upload_time.desc())\
                            .limit(6).all()

    return render_template('watch.html', media=m, taxonomy=TAXONOMY, related=related, current_year=current_utc_year)



# @app.route('/recent')
# @login_required
# def recent():
#     current_utc_year = datetime.now(timezone.utc).year
#     history = (
#         WatchHistory.query.filter_by(user_id=current_user.id)
#         .order_by(WatchHistory.watched_at.desc())
#         .limit(10)
#         .all()
#     )
#     media_ids = [h.media_id for h in history]
#     media = Media.query.filter(Media.id.in_(media_ids)).all()
#     return render_template('recent.html', media=media, taxonomy=TAXONOMY, 
#                         history=history, current_year=current_utc_year)

@app.route('/recent')
@login_required # User must be logged in
@subscription_required # User must have an active subscription (if client)
def recent():
    # The decorators handle redirection for unauthenticated or unsubscribed clients.
    current_utc_year = datetime.now(timezone.utc).year
    history = (
        WatchHistory.query.filter_by(user_id=current_user.id)
        .order_by(WatchHistory.watched_at.desc())
        .limit(10)
        .all()
    )
    media_ids = [h.media_id for h in history]
    # Fetch media objects based on IDs from history
    # Using .in_() requires a list of IDs.
    # Ensure the order is maintained if important, otherwise query.all() is fine.
    media = Media.query.filter(Media.id.in_(media_ids)).all()

    # Create a dictionary for easy lookup if you need to display history in order
    media_map = {m.id: m for m in media}
    ordered_media = [media_map[h.media_id] for h in history if h.media_id in media_map]


    return render_template('recent.html', media=ordered_media, taxonomy=TAXONOMY,
                                history=history, current_year=current_utc_year)

# @app.route('/stream/<path:fname>')
# def stream(fname):
#     """
#     Serve video with HTTP Range support so the browser can seek.
#     """
#     file_path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
#     if not os.path.exists(file_path):
#         return "Not found", 404

#     range_header = request.headers.get('Range', None)
#     if not range_header:
#         return send_file(file_path)

#     import re
#     byte1, byte2 = 0, None
#     m = re.search(r'(\d+)-(\d*)', range_header)
#     if m:
#         g = m.groups()
#         byte1 = int(g[0])
#         if g[1]:
#             byte2 = int(g[1])

#     file_size = os.path.getsize(file_path)
#     if byte2 is None or byte2 >= file_size:
#         byte2 = file_size - 1
#     length = byte2 - byte1 + 1

#     with open(file_path, 'rb') as f:
#         f.seek(byte1)
#         data = f.read(length)

#     rv = Response(data,
#                 206,
#                 mimetype='video/mp4',
#                 content_type='video/mp4',
#                 direct_passthrough=True)
#     rv.headers.add('Content-Range', f'bytes {byte1}-{byte2}/{file_size}')
#     rv.headers.add('Accept-Ranges', 'bytes')
#     return rv


@app.route('/stream/<path:fname>')
@login_required # User must be logged in to stream content
@subscription_required # User must have an active subscription (if client) to stream
def stream(fname):
    """
    Serve video with HTTP Range support so the browser can seek.
    """
    # The decorators handle redirection for unauthenticated or unsubscribed clients.

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
    if not os.path.exists(file_path):
        return "Not found", 404

    range_header = request.headers.get('Range', None)
    if not range_header:
        return send_file(file_path)

    import re # Ensure re is imported
    byte1, byte2 = 0, None
    m = re.search(r'(\d+)-(\d*)', range_header)
    if m:
        g = m.groups()
        byte1 = int(g[0])
        if g[1]:
            byte2 = int(g[1])

    file_size = os.path.getsize(file_path)
    if byte2 is None or byte2 >= file_size:
        byte2 = file_size - 1
    length = byte2 - byte1 + 1

    with open(file_path, 'rb') as f:
        f.seek(byte1)
        data = f.read(length)

    rv = Response(data,
                    206,
                    mimetype='video/mp4',
                    content_type='video/mp4',
                    direct_passthrough=True)
    rv.headers.add('Content-Range', f'bytes {byte1}-{byte2}/{file_size}')
    rv.headers.add('Accept-Ranges', 'bytes')
    return rv


# mark a video as completed
# @app.route('/complete/<int:media_id>', methods=['POST'])
# @login_required
# def mark_complete(media_id):
#     record = (
#         WatchHistory.query
#         .filter_by(user_id=current_user.id, media_id=media_id)
#         .first()
#     )
#     if not record:
#         record = WatchHistory(user_id=current_user.id, media_id=media_id)
#         db.session.add(record)

#     record.progress_percent = 100
#     record.completed = True
#     record.watched_at = datetime.utcnow()
#     db.session.commit()
#     flash("Marked as completed ✓")
#     return redirect(url_for('watch', media_id=media_id))


# mark a video as completed
@app.route('/complete/<int:media_id>', methods=['POST'])
@login_required # User must be logged in to mark as complete
@subscription_required # User must have an active subscription (if client) to mark as complete
def mark_complete(media_id):
    # The decorators handle redirection for unauthenticated or unsubscribed clients.

    record = (
        WatchHistory.query
        .filter_by(user_id=current_user.id, media_id=media_id)
        .first()
    )
    if not record:
        record = WatchHistory(user_id=current_user.id, media_id=media_id)
        db.session.add(record)

    record.progress_percent = 100
    record.completed = True
    record.watched_at = datetime.utcnow()
    db.session.commit()
    flash("Marked as completed ✓", 'success') # Added category
    return redirect(url_for('watch', media_id=media_id))

# client progress dashboard
# @app.route('/progress')
# @login_required
# def progress():
#     current_utc_year = datetime.now(timezone.utc).year
#     records = (
#         WatchHistory.query
#         .filter_by(user_id=current_user.id)
#         .join(Media, WatchHistory.media_id == Media.id)
#         .add_columns(Media.title, Media.target_condition,
#                      WatchHistory.progress_percent, WatchHistory.completed,
#                      WatchHistory.watched_at, Media.id.label("m_id"))
#         .order_by(WatchHistory.watched_at.desc())
#         .all()
#     )
#     return render_template('progress.html', rows=records, taxonomy=TAXONOMY, current_year=current_utc_year)


@app.route('/progress')
@login_required # User must be logged in
@subscription_required # User must have an active subscription (if client) to view progress
def progress():
    # The decorators handle redirection for unauthenticated or unsubscribed clients.
    current_utc_year = datetime.now(timezone.utc).year
    records = (
        WatchHistory.query
        .filter_by(user_id=current_user.id)
        .join(Media, WatchHistory.media_id == Media.id)
        .add_columns(Media.title, Media.target_condition,
                        WatchHistory.progress_percent, WatchHistory.completed,
                        WatchHistory.watched_at, Media.id.label("m_id"))
        .order_by(WatchHistory.watched_at.desc())
        .all()
    )
    return render_template('progress.html', rows=records, taxonomy=TAXONOMY, current_year=current_utc_year)


# @app.route('/progress/report.csv')
# @login_required
# def progress_report():
#     import csv
#     from io import StringIO
#     si = StringIO()
#     cw = csv.writer(si)
#     cw.writerow(["Media ID", "Title", "Condition",
#                  "Progress %", "Completed", "Last Watched"])
#     qs = (
#         WatchHistory.query
#         .filter_by(user_id=current_user.id)
#         .join(Media, WatchHistory.media_id == Media.id)
#         .add_columns(Media.title, Media.target_condition,
#                      WatchHistory.progress_percent, WatchHistory.completed,
#                      WatchHistory.watched_at, Media.id.label("m_id"))
#     )
#     for r in qs:
#         cw.writerow([r.m_id, r.title, r.target_condition,
#                      r.progress_percent, r.completed, r.watched_at])
#     from flask import make_response
#     output = make_response(si.getvalue())
#     output.headers["Content-Disposition"] = "attachment; filename=progress.csv"
#     output.headers["Content-type"] = "text/csv"
#     return output


@app.route('/progress/report.csv')
@login_required # User must be logged in
@subscription_required # User must have an active subscription (if client) to download report
def progress_report():
    # The decorators handle redirection for unauthenticated or unsubscribed clients.
    import csv # Ensure csv is imported
    from io import StringIO # Ensure StringIO is imported
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["Media ID", "Title", "Condition",
                        "Progress %", "Completed", "Last Watched"])
    qs = (
        WatchHistory.query
        .filter_by(user_id=current_user.id)
        .join(Media, WatchHistory.media_id == Media.id)
        .add_columns(Media.title, Media.target_condition,
                        WatchHistory.progress_percent, WatchHistory.completed,
                        WatchHistory.watched_at, Media.id.label("m_id"))
    )
    for r in qs:
        cw.writerow([r.m_id, r.title, r.target_condition,
                        r.progress_percent, r.completed, r.watched_at])
    from flask import make_response # Ensure make_response is imported
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=progress.csv"
    output.headers["Content-type"] = "text/csv"
    return output


@app.route('/therapist_dashboard')
@login_required
def therapist_dashboard():
    # Ensure only therapists can access this dashboard
    if current_user.role != 'therapist':
        flash('Access denied. You do not have therapist privileges.', 'danger')
        # Redirect to the general index page or a forbidden page
        return redirect(url_for('index'))

    # Fetch all media for the therapist to view (similar to old index for therapists)
    all_media = Media.query.order_by(Media.upload_time.desc()).all()
    current_utc_year = datetime.now(timezone.utc).year # Ensure datetime and timezone are imported

    return render_template('therapist_dashboard.html',
                            media=all_media,
                            taxonomy=TAXONOMY, # Assuming TAXONOMY is needed for filters/categories
                            current_year=current_utc_year)


@app.route('/client_dashboard')
@login_required
def client_dashboard():
    if current_user.role != 'client':
        flash('Access denied. You do not have client privileges.', 'danger')
        return redirect(url_for('index')) # Redirect to index or a general error page

    all_media = Media.query.order_by(Media.upload_time.desc()).all() # Fetch all media
    current_utc_year = datetime.now(timezone.utc).year

    # This part determines if the client sees content or paywall
    if has_active_subscription(current_user):
        return render_template('client_dashboard.html', media=all_media, has_subscription=True, taxonomy=TAXONOMY, current_year=current_utc_year)
    else:
        return render_template('client_dashboard.html', media=[], has_subscription=False, current_year=current_utc_year)


@app.route('/my_subscription')
@login_required # Only logged-in users can see their subscription details
def my_subscription():
    current_utc_year = datetime.now(timezone.utc).year
    if current_user.role != 'client':
        flash("You are not authorized to view this page.", 'danger')
        # Redirect to a relevant dashboard for non-clients
        if current_user.role == 'therapist':
            return redirect(url_for('therapist_dashboard'))
        elif current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('index')) # Fallback for other roles

    # Fetch the most recent subscription for the current user
    # Order by timestamp descending to get the latest one if multiple exist
    latest_subscription = Subscription.query.filter_by(user_id=current_user.id)\
                                            .order_by(Subscription.timestamp.desc())\
                                            .first()

    return render_template('my_subscription.html',
                            subscription=latest_subscription, taxonomy=TAXONOMY, current_year=current_utc_year, datetime=datetime)


# 📄 About Page
@app.route("/about")
def about():
    current_utc_year = datetime.now(timezone.utc).year
    return render_template("about.html", taxonomy=TAXONOMY, current_year=current_utc_year)

# 📄 Privacy Policy Page
@app.route("/privacy")
def privacy():
    current_utc_year = datetime.now(timezone.utc).year
    return render_template("privacy.html", taxonomy=TAXONOMY, current_year=current_utc_year)

# 📄 Terms of Use Page
@app.route("/terms")
def terms():
    current_utc_year = datetime.now(timezone.utc).year
    return render_template("terms.html", taxonomy=TAXONOMY, current_year=current_utc_year)

# 📄 Cookie Policy Page
@app.route("/cookies")
def cookies():
    current_utc_year = datetime.now(timezone.utc).year
    return render_template("cookies.html", taxonomy=TAXONOMY, current_year=current_utc_year)

@app.route('/accept-cookies', methods=['POST'])
def accept_cookies():
    response = redirect(request.referrer or url_for('index'))
    response.set_cookie('cookies_accepted', 'true', max_age=60*60*24*365)
    return response

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
         # ✅ Seed demo users if not already in database
        if not User.query.filter_by(username='therapist').first():
            t = User(username='therapist', role='therapist')
            t.set_password('pass')
            db.session.add(t)

        if not User.query.filter_by(username='client').first():
            c = User(username='client', role='client')
            c.set_password('pass')
            db.session.add(c)

        db.session.commit()
        
        if not Plan.query.first():
            starter = Plan(name="Starter", amount_pesewas=500, interval_days=7)
            pro = Plan(name="Pro", amount_pesewas=2000, interval_days=30)
            ultimate = Plan(name="Ultimate", amount_pesewas=5000, interval_days=90)
            db.session.add_all([starter, pro, ultimate])
            db.session.commit()
            print("✅ Plans table initialized.")
    app.run(debug=True)
