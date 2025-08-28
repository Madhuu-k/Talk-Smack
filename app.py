from flask import Flask, request, render_template, redirect, url_for, session
from flask_socketio import SocketIO, send
from flask_sqlalchemy import SQLAlchemy   # <-- use flask_sqlalchemy, not plain sqlalchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey1234'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'

# INIT
db = SQLAlchemy(app) 
socketio = SocketIO(app, cors_allowed_origins="*")   # use lowercase var, don’t overwrite class

# LOGIN MANAGER
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# DATABASE MODELS
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)   # keep longer length

class Message(db.Model):    
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(50))
    content = db.Column(db.String(700))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# LOGIN MANAGER HOOK
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ROUTES
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            return 'Username already exists!'
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()   # simple auth
        if user:
            login_user(user)
            return redirect(url_for('chat'))
        else:
            return 'Invalid Credentials!'
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
    return render_template('chat.html', messages=messages)

# SOCKET EVENTS
@socketio.on('message')
def handle_message(msg):
    if current_user.is_authenticated:
        new_message = Message(sender=current_user.username, content=msg)
        db.session.add(new_message)
        db.session.commit()
        send(f"{current_user.username}: {msg}", broadcast=True)  # broadcast to all clients

# MAIN
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
