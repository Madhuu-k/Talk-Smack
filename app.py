import os, re
from datetime import datetime
from flask import Flask, flash, request, render_template, redirect, url_for, jsonify
from flask_socketio import SocketIO, send, join_room, emit
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ----------------------
# APP CONFIG
# ----------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey1234'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ----------------------
# INIT
# ----------------------
db = SQLAlchemy(app)
migrate = Migrate(app, db)
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=True)   # for groups
    is_group = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    content = db.Column(db.String(700))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship("User", backref="messages", lazy=True)

class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default="pending")  # accepted, pending, blocked
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", foreign_keys=[user_id])
    friend = db.relationship("User", foreign_keys=[friend_id])


# ----------------------
# HELPER FUNCTIONS
# ----------------------

def get_user_friends():
    friends = db.session.query(Friend, User).join(
        User,
        (User.id == Friend.friend_id) | (User.id == Friend.user_id)
    ).filter(
        Friend.status == "accepted",
        ((Friend.user_id == current_user.id) | (Friend.friend_id == current_user.id)),
        User.id != current_user.id
    ).all()

    return [friend[1] for friend in friends]


def get_or_create_chat_room(user1_id, user2_id):
    """Get existing chat room between two users or create new one"""
    # Look for existing room with both users
    existing_room = db.session.query(ChatRoom).join(ChatMembership).filter(
        ChatRoom.is_group == False,
        ChatMembership.user_id.in_([user1_id, user2_id])
    ).group_by(ChatRoom.id).having(db.func.count(ChatMembership.user_id) == 2).first()
    
    if existing_room:
        return existing_room
    
    # Create new room
    new_room = ChatRoom(is_group=False)
    db.session.add(new_room)
    db.session.flush()
    
    # Add both users to room
    membership1 = ChatMembership(user_id=user1_id, room_id=new_room.id)
    membership2 = ChatMembership(user_id=user2_id, room_id=new_room.id)
    db.session.add(membership1)
    db.session.add(membership2)
    db.session.commit()
    
    return new_room


# ----------------------
# FILE UPLOAD CONFIG
# ----------------------
UPLOAD_FOLDER = 'static/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

        # Username already exists
        if User.query.filter_by(username=username).first():
            flash("Username already in use, please select another one")
            return redirect(url_for('register'))

        # Email already exists
        if User.query.filter_by(email=email).first():
            flash("This email is already in use , please select a new one")
            return redirect(url_for('register'))

        # Passwords must match
        if password != confirm_password:
            flash("Passwords don't match, reenter the password")
            return redirect(url_for('register'))

        # Save new user 
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw, email=email)
        db.session.add(new_user)
        db.session.commit()
        flash("Registered successfully! Please log in.")
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

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/friend_requests')
@login_required
def friend_requests():
    requests = Friend.query.filter_by(friend_id=current_user.id, status="pending").all()
    friends = get_user_friends()
    return render_template('friend_requests.html', requests=requests, friends=friends)

@app.route('/add_friend')
@login_required
def add_friend():
    friends = get_user_friends()
    return render_template('add_friend.html', friends=friends)

@app.route('/search_users')
@login_required
def search_users():
    query = request.args.get('query', '').strip()
    if not query:
        return jsonify([])
    
    # Search users excluding current user
    users = User.query.filter(
        ((User.username.ilike(f'%{query}%')) | (User.email.ilike(f'%{query}%'))),
        User.id != current_user.id
    ).limit(10).all()
    
    # Get existing friend requests/friendships
    existing_relations = db.session.query(Friend).filter(
        ((Friend.user_id == current_user.id) | (Friend.friend_id == current_user.id))
    ).all()

    related_user_ids = set()
    for relation in existing_relations:
        if relation.user_id == current_user.id:
            related_user_ids.add(relation.friend_id)
        else:
            related_user_ids.add(relation.user_id)

    results = []
    for user in users:
        status = "none"
        if user.id in related_user_ids:
            relation = next((r for r in existing_relations
                             if r.user_id in [current_user.id, user.id] and
                             r.friend_id in [current_user.id, user.id]), None)
            if relation:
                status = relation.status

        results.append({
            'id' : user.id,
            'username' : user.username,
            'email' : user.email,
            'initials' : user.username[:2].upper(),
            'status' : status
        })

    return jsonify(results)

@app.route('/send_request/<int:user_id>', methods=['POST'])
@login_required
def send_request(user_id):
    if user_id == current_user.id:
        return jsonify({'success': False, 'message': 'You cannot add yourself.'})

    existing = Friend.query.filter_by(user_id=current_user.id, friend_id=user_id).first()
    if existing:
        return jsonify({'success': False, 'message': 'Request already sent or already friends.'})

    new_friend = Friend(user_id=current_user.id, friend_id=user_id, status="pending")
    db.session.add(new_friend)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Friend request sent!'})


@app.route('/respond_request/<int:request_id>/<action>', methods=['POST'])
@login_required
def respond_request(request_id, action):
    request_obj = Friend.query.get(request_id)
    if not request_obj or request_obj.friend_id != current_user.id:
        return jsonify({'success': False, 'message': 'Invalid request.'})

    if action == "accept":
        request_obj.status = "accepted"
        db.session.commit()
        return jsonify({'success': True, 'message': 'Friend request accepted.'})
    elif action == "reject":
        db.session.delete(request_obj)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Friend request rejected.'})
    
    return jsonify({'success': False, 'message': 'Invalid action.'})


@app.route('/chat')
@login_required
def chat():
    friends = get_user_friends()
    return render_template('chat.html', friends=friends)

@app.route('/reset_password')
def resetPassword():
    return render_template('reset_password.html')


@app.route('/chat/<int:friend_id>')
@login_required
def chat_with_friend(friend_id):
    friendship = Friend.query.filter(
        Friend.status == "accepted",
        ((Friend.user_id == current_user.id) & (Friend.friend_id == friend_id)) |
        ((Friend.user_id == friend_id) & (Friend.friend_id == current_user.id))
    ).first()

    if not friendship:
        flash("You can only chat with friends")
        return redirect(url_for('chat'))
    
    friend = User.query.get_or_404(friend_id)
    room = get_or_create_chat_room(current_user.id, friend_id)
    friends = get_user_friends()
    
    # Get chat messages
    messages = Message.query.filter_by(room_id=room.id).order_by(Message.timestamp).all()
    
    return render_template('chat_room.html', 
                         friend=friend, 
                         room=room, 
                         messages=messages,
                         friends=friends)


@app.route('/get_messages/<int:room_id>')
@login_required
def get_messages(room_id):
    membership = ChatMembership.query.filter_by(
        user_id = current_user.id,
        room_id = room_id
    ).first()

    if not membership:
        return jsonify({'error' : 'Access Denied'}), 403
    
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp).all()
    return jsonify([{
        'id': msg.id,
        'sender_id': msg.sender_id,
        'sender_username': msg.sender.username,
        'content': msg.content,
        'timestamp': msg.timestamp.strftime('%H:%M')
    } for msg in messages])

# ----------------------
# SOCKET EVENTS
# ----------------------
@socketio.on('message')
def handle_message(data):
    room_id = data['room_id']
    msg = data['message']

    # verify membership - access
    membership = ChatMembership.query.filter_by(
        user_id = current_user.id,
        room_id = room_id
    ).first()

    if not membership: return

    new_message = Message(sender_id=current_user.id, room_id=room_id, content=msg)
    db.session.add(new_message)
    db.session.commit()

    emit('message', {
        "id": new_message.id,
        "sender_id": current_user.id,
        "username": current_user.username,
        "content": msg,
        "timestamp": new_message.timestamp.strftime("%H:%M")
    }, room=str(room_id))

@socketio.on('join')
def handle_join(data):
    room_id = data['room']

    membership = ChatMembership.query.filter_by(
        user_id = current_user.id,
        room_id = room_id
    ).first()

    if membership:
        join_room(str(room_id))

# ----------------------
# MAIN
# ----------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()   # Create tables if not exists
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
