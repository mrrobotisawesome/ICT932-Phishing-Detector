from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from functools import wraps
import pyotp
import qrcode
import io
import base64
import re
from datetime import datetime
import os

basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
os.makedirs(instance_path, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dasdasiuyvriwystjbrvwthjedfsvhgfbshgfhsdgfhsgdhfvgshbdgfshg'
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(instance_path, 'project.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    otp_secret = db.Column(db.String(32), nullable=False)

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_content = db.Column(db.Text, nullable=False)
    risk_level = db.Column(db.String(50), nullable=False)
    findings = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('analyses', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Admin access is required to view this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def analyze_email(content):
    score = 0
    findings = []
    
    urgent_keywords = ['urgent', 'important', 'action required', 'account suspended', 'verify immediately', 'password expires']
    for keyword in urgent_keywords:
        if re.search(r'\b' + keyword + r'\b', content, re.IGNORECASE):
            score += 2
            findings.append(f"Detected urgent keyword: '{keyword}'")

    generic_greetings = ['dear customer', 'dear user', 'dear account holder']
    for greeting in generic_greetings:
        if content.lower().strip().startswith(greeting):
            score += 1
            findings.append("Detected generic greeting which is common in phishing.")

    links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
    if links:
        findings.append(f"Found {len(links)} link(s). Always verify links before clicking.")
        score += len(links)
        for link in links:
            if re.search(r'\.(zip|mov|exe|biz|info)\b', link):
                score += 3
                findings.append(f"Suspicious TLD found in link: {link}")

    if not findings:
        findings.append("No immediate red flags detected.")

    if score >= 5:
        risk_level = "Malicious"
    elif score >= 2:
        risk_level = "Suspicious"
    else:
        risk_level = "Safe"
        
    return {"risk_level": risk_level, "findings": findings}

@app.route('/')
@login_required
def index():
    user_analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.timestamp.desc()).all()
    return render_template('index.html', user_analyses=user_analyses, results=None)

@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    email_content = request.form.get('email_content')
    if not email_content or len(email_content) > 10000:
        flash('Email content is required and must be less than 10,000 characters.', 'danger')
        return redirect(url_for('index'))
    
    results = analyze_email(email_content)
    
    new_analysis = Analysis(
        email_content=email_content,
        risk_level=results['risk_level'],
        findings=', '.join(results['findings']),
        user_id=current_user.id
    )
    db.session.add(new_analysis)
    db.session.commit()
    
    user_analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.timestamp.desc()).all()
    return render_template('index.html', user_analyses=user_analyses, results=results)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['username_for_2fa'] = user.username
            return redirect(url_for('verify_2fa'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'warning')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        otp_secret = pyotp.random_base32()
        new_user = User(username=username, password=hashed_password, otp_secret=otp_secret)
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('setup_2fa'))
    return render_template('register.html')
    
@app.route('/setup_2fa')
@login_required
def setup_2fa():
    otp_provisioning_uri = pyotp.totp.TOTP(current_user.otp_secret).provisioning_uri(
        name=current_user.username,
        issuer_name="PhishGuard"
    )
    
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(otp_provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code_data = base64.b64encode(buffered.getvalue()).decode("utf-8")
    
    return render_template('setup_2fa.html', qr_code_data=qr_code_data, secret_key=current_user.otp_secret)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    username = session.get('username_for_2fa')
    if not username:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token')
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(token):
            session.pop('username_for_2fa', None)
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid 2FA token.', 'danger')

    return render_template('verify_2fa.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    all_analyses = Analysis.query.order_by(Analysis.timestamp.desc()).all()
    return render_template('admin_dashboard.html', all_analyses=all_analyses)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_password = bcrypt.generate_password_hash('AdminPassword123').decode('utf-8')
            admin_otp_secret = pyotp.random_base32()
            admin_user = User(username='admin', password=admin_password, role='admin', otp_secret=admin_otp_secret)
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created with username 'admin' and password 'AdminPassword123'")
            print(f"Admin OTP secret for 2FA setup: {admin_otp_secret}")
    app.run(debug=True)