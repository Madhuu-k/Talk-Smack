import re, os
from datetime import datetime
from flask import Flask, flash, request, render_template, redirect, url_for
from flask_socketio import SocketIO, send
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ----------------------
# APP CONFIG
# ----------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey1234'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'

# ----------------------
# INIT
# ----------------------
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ----------------------
# DATABASE MODELS
# ----------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    dob = db.Column(db.String(20), nullable=False, default='01-01-2000')
    profile_pic = db.Column(db.String(200), default='default.png', nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(50))
    content = db.Column(db.String(700))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

migrate = Migrate(app, db)

UPLOAD_FOLDER = 'static/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Create tables if not exist
with app.app_context():
    db.create_all()

# ----------------------
# LOGIN MANAGER HOOK
# ----------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------------
# ROUTES
# ----------------------
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        dob = request.form.get('dob')
        profile_pic = request.files.get('profile_pic')

        # Username already exists
        if User.query.filter_by(username=username).first():
            flash("⚠️ Username already exists!")
            return redirect(url_for('register'))

        # Email validation
        if not re.match(r"^[a-zA-Z0-9._%+-]+@gmail\.com$", email):
            flash("⚠️ Email must be a valid Gmail address!")
            return redirect(url_for('register'))

        # Email already exists
        if User.query.filter_by(email=email).first():
            flash("⚠️ Email already in use!")
            return redirect(url_for('register'))

        # Passwords must match
        if password != confirm_password:
            flash("⚠️ Passwords do not match!")
            return redirect(url_for('register'))
        
        # Handle profile picture upload
        if profile_pic and allowed_file(profile_pic.filename):
            filename = secure_filename(profile_pic.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_pic.save(filepath)
        else:
            filename = 'default.png'

        # Save new user
        hashed_pw = generate_password_hash(password)
        new_user =  User(username=username, password=hashed_pw, email=email,
                          dob=dob if dob else '01-01-2000', profile_pic=filename)
        db.session.add(new_user)
        db.session.commit()
        flash("✅ Registered successfully! Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('chat'))
        else:
            flash("❌ Invalid credentials!")
            return redirect(url_for('login'))

    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    messages = Message.query.order_by(Message.timestamp.asc()).all()
    messages_with_pics = []
    for m in messages:
        user = User.query.filter_by(username=m.sender).first()
        messages_with_pics.append({
            "sender": m.sender,
            "content": m.content,
            "timestamp": m.timestamp.strftime("%H:%M"),
            "profile_pic": user.profile_pic if user else "default.png"
        })
    return render_template('chat.html', messages=messages_with_pics)

# ----------------------
# SOCKET EVENTS
# ----------------------
@socketio.on('message')
def handle_message(msg):
    if current_user.is_authenticated:
        new_message = Message(sender=current_user.username, content=msg)
        db.session.add(new_message)
        db.session.commit()
        send({
            "username" : current_user.username,
            "profile_pic" : current_user.profile_pic,
            "content" : msg,
            "timestamp" : new_message.timestamp.strftime("%H:%M")
        }, broadcast=True)

# ----------------------
# MAIN
# ----------------------
if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
