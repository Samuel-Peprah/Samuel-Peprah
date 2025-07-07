
import os
from datetime import datetime, timezone
from flask import Flask, abort, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from moviepy.editor import VideoFileClip
import uuid
from collections import defaultdict
from PIL import Image
from flask_moment import Moment
from flask import Response, send_file
from config import APP_VERSION
import subprocess
from dotenv import load_dotenv
load_dotenv()
import requests, hmac, hashlib, json
from functools import wraps



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
app.secret_key = os.getenv("SECRET_KEY", "Atom-De-Legend")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'portal.db')
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['PAYSTACK_SEC_KEY'] = os.getenv("PAYSTACK_SEC_KEY")
app.config['PAYSTACK_PUB_KEY'] = os.getenv("PAYSTACK_PUB_KEY")
app.config['PAYSTACK_WEBHOOK_SECRET'] = os.getenv("PAYSTACK_WEBHOOK_SECRET")


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
moment = Moment(app)
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
    name = db.Column(db.String(50), nullable=False)  # e.g. "Basic", "Pro", "Premium"
    amount_pesewas = db.Column(db.Integer, nullable=False)   # 199900 == GHS 1 999.00
    interval_days = db.Column(db.Integer, default=30)        # 30, 90, 365 …
    is_active     = db.Column(db.Boolean, default=True)

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    plan_id = db.Column(db.Integer, db.ForeignKey("plan.id"))
    status  = db.Column(db.String, default="active")    # active | expired | canceled
    current_period_end = db.Column(db.DateTime)
    last_tx_ref = db.Column(db.String)                      # paystack reference

    user = db.relationship("User", backref="subscription", uselist=False)
    plan = db.relationship("Plan")



@app.context_processor
def inject_version():
    return dict(app_version=APP_VERSION)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def inject_utc_now():
    return {'utc_now': datetime.now(timezone.utc)}

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

def subscription_required(fn):
    @wraps(fn)
    def _wrap(*a, **kw):
        if (not current_user.is_authenticated or
            not current_user.subscription or
            current_user.subscription.current_period_end < datetime.utcnow()):
            flash("Please pick a plan to unlock TherapTube 📺", "warning")
            return redirect(url_for("pricing"))
        return fn(*a, **kw)
    return _wrap

@app.route("/pricing")
def pricing():
    plans = Plan.query.filter_by(is_active=True).all()
    return render_template("pricing.html",
                            plans=plans,
                            pub_key=app.config["PAYSTACK_PUB_KEY"])



@app.post("/paystack/verify")
@login_required
def paystack_verify():
    data = request.get_json(force=True)
    ref  = data["ref"]; plan_id = int(data["plan_id"])

    # 1. verify with Paystack
    r = requests.get(f"https://api.paystack.co/transaction/verify/{ref}",
                        headers=PAYSTACK_HEADERS, timeout=10)
    js = r.json()
    if not (js.get("status") and js["data"]["status"] == "success"):
        return {"ok": False}, 400

    # 2. mark / extend subscription
    plan = Plan.query.get_or_404(plan_id)
    sub  = current_user.subscription
    from datetime import datetime, timedelta
    now  = datetime.utcnow()

    if sub and sub.current_period_end > now:      # extend
        sub.current_period_end += timedelta(days=plan.interval_days)
    else:                                         # new sub
        sub = Subscription(user=current_user,
                            plan=plan,
                            current_period_end = now + timedelta(days=plan.interval_days))
        db.session.add(sub)
    sub.status       = "active"
    sub.last_tx_ref  = ref
    db.session.commit()
    return {"ok": True}


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




def make_thumbnail(video_path: str, thumb_path: str):
    """
    Grab the first frame at t=1 s and save as 320 px‑wide JPG.
    """
    try:
        clip = VideoFileClip(video_path).subclip(1, 2)   # 1 → 2 s slice
        frame = clip.get_frame(0)                        # numpy array
        clip.close()

        img = Image.fromarray(frame)
        img.thumbnail((320, 320))                        # keep aspect, max 320 px
        img.save(thumb_path, "JPEG", quality=80)
    except Exception as e:
        print("❗ thumbnail error:", e)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email    = request.form['email']
        token    = request.form['invite_token'].strip()

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

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
        login_user(new_user)
        flash('Registration successful. Welcome!')
        return redirect(url_for('admin_dashboard' if new_user.role == 'therapist' else 'index'))

    return render_template('register.html', taxonomy=TAXONOMY,)


@app.route('/')
def index():
    media = Media.query.order_by(Media.upload_time.desc()).all()
    current_utc_year = datetime.now(timezone.utc).year
    return render_template('index.html', media=media, taxonomy=TAXONOMY, current_year=current_utc_year)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials')
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
    top10         = Media.query.order_by(Media.view_count.desc()).limit(10).all()
    current_utc_year = datetime.now(timezone.utc).year

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
        taxonomy=TAXONOMY,
        current_year=current_utc_year
    )


@app.route('/media/<int:media_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_media(media_id):
    media = Media.query.get_or_404(media_id)

    # Only allow the uploader or therapist role to edit
    if current_user.id != media.uploader_id and current_user.role != 'therapist':
        flash("You don't have permission to edit this media.")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        media.title = request.form['title']
        media.description = request.form['description']
        media.category = request.form['category']
        media.otpf_domain = request.form['otpf_domain']
        media.for_name = request.form['for_name']
        media.target_condition = request.form['target_condition']
        db.session.commit()
        flash('Media updated successfully.')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_media.html', media=media, taxonomy=TAXONOMY)


@app.route('/media/<int:media_id>/delete', methods=['POST'])
@login_required
def delete_media(media_id):
    media = Media.query.get_or_404(media_id)

    # Only uploader or therapist can delete
    if current_user.id != media.uploader_id and current_user.role != 'therapist':
        flash("You don't have permission to delete this media.")
        return redirect(url_for('admin_dashboard'))

    try:
        # Remove media file from disk
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], media.filename))
    except Exception as e:
        print(f"Error deleting file: {e}")

    db.session.delete(media)
    db.session.commit()
    flash('Media deleted successfully.')
    return redirect(url_for('admin_dashboard'))



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



import subprocess

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if current_user.role != 'therapist':
        flash('Only therapists can upload.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        f = request.files['file']
        if f and f.filename:
            ext = os.path.splitext(f.filename)[1].lower()
            original_filename = f"{uuid.uuid4().hex}{ext}"
            original_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            f.save(original_path)

            # Convert video if it's not already in .mp4
            video_exts = ('.mp4', '.mov', '.mkv', '.avi', '.webm')
            if ext in video_exts:
                # Always convert to .mp4 for consistency
                converted_filename = f"{uuid.uuid4().hex}.mp4"
                converted_path = os.path.join(app.config['UPLOAD_FOLDER'], converted_filename)

                subprocess.run([
                    'ffmpeg', '-i', original_path,
                    '-vcodec', 'libx264', '-acodec', 'aac',
                    '-strict', 'experimental', '-y', converted_path
                ])

                os.remove(original_path)  # optional: remove original upload

                # Generate thumbnail
                thumb_name = f"{os.path.splitext(converted_filename)[0]}.jpg"
                thumb_path = os.path.join(app.config['UPLOAD_FOLDER'], 'thumbs', thumb_name)
                make_thumbnail(converted_path, thumb_path)

                final_filename = converted_filename
            else:
                # It's an image or already .mp4 — no conversion needed
                final_filename = original_filename
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

            flash('Uploaded and converted successfully.')
            return redirect(url_for('index'))

    return render_template('upload.html', taxonomy=TAXONOMY)



@app.route('/search')
def search():
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

@app.route('/media/<int:media_id>')
def watch(media_id):
    m = Media.query.get_or_404(media_id)
    current_utc_year = datetime.now(timezone.utc).year

    if current_user.is_authenticated:
        # Save to history
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


@app.route('/recent')
@login_required
def recent():
    current_utc_year = datetime.now(timezone.utc).year
    history = (
        WatchHistory.query.filter_by(user_id=current_user.id)
        .order_by(WatchHistory.watched_at.desc())
        .limit(10)
        .all()
    )
    media_ids = [h.media_id for h in history]
    media = Media.query.filter(Media.id.in_(media_ids)).all()
    return render_template('recent.html', media=media, taxonomy=TAXONOMY, 
                        history=history, current_year=current_utc_year)

@app.route('/stream/<path:fname>')
def stream(fname):
    """
    Serve video with HTTP Range support so the browser can seek.
    """
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
    if not os.path.exists(file_path):
        return "Not found", 404

    range_header = request.headers.get('Range', None)
    if not range_header:
        return send_file(file_path)

    import re
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
@app.route('/complete/<int:media_id>', methods=['POST'])
@login_required
def mark_complete(media_id):
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
    flash("Marked as completed ✓")
    return redirect(url_for('watch', media_id=media_id))

# client progress dashboard
@app.route('/progress')
@login_required
def progress():
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


@app.route('/progress/report.csv')
@login_required
def progress_report():
    import csv
    from io import StringIO
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
    from flask import make_response
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=progress.csv"
    output.headers["Content-type"] = "text/csv"
    return output




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
    app.run(debug=True)
