from flask import Flask, render_template, request, redirect, url_for, flash, make_response
import hashlib
import uuid
import os

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'this_is_a_strong_key_dont_diss_it'

# --- Helper Functions ---

def ensure_file_exists(file_path):
    """Create the file if it doesn't exist."""
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            pass  # Just create the file

def generate_user_id():
    """Generate a unique user ID."""
    return str(uuid.uuid4())

def user_exists(username, file_path='users.txt'):
    """Check if a username already exists."""
    ensure_file_exists(file_path)
    with open(file_path, 'r') as f:
        for line in f:
            stored_user_id, stored_username, _ = line.strip().split(',')
            if stored_username == username:
                return True
    return False

def add_user_to_file(username, password, file_path='users.txt'):
    """Add a new user if the username doesn't already exist."""
    ensure_file_exists(file_path)
    if user_exists(username, file_path):
        return False  # Username is already taken
    
    user_id = generate_user_id()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()  # Hash the password
    with open(file_path, 'a') as f:
        f.write(f"{user_id},{username},{hashed_password}\n")
    return True

def check_user_in_file(username, password, file_path='users.txt'):
    """Check if the username and password are correct."""
    ensure_file_exists(file_path)
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open(file_path, 'r') as f:
        for line in f:
            stored_user_id, stored_username, stored_hashed_password = line.strip().split(',')
            if stored_username == username and stored_hashed_password == hashed_password:
                return True
    return False

def send_friend_request(username, friend_name, file_path='friend_requests.txt'):
    """Send a friend request to another user."""
    ensure_file_exists(file_path)
    with open(file_path, 'a') as f:
        f.write(f"{username},{friend_name}\n")

def get_pending_requests(username, file_path='friend_requests.txt'):
    """Get a list of pending friend requests for the user."""
    ensure_file_exists(file_path)
    requests = []
    with open(file_path, 'r') as f:
        for line in f:
            sender, receiver = line.strip().split(',')
            if receiver == username:
                requests.append(sender)
    return requests

def accept_friend_request(username, friend_name, friends_file='friends.txt', requests_file='friend_requests.txt'):
    """Accept a friend request and add both users as friends."""
    ensure_file_exists(friends_file)
    ensure_file_exists(requests_file)
    
    # Add the friendship
    with open(friends_file, 'a') as f:
        f.write(f"{username},{friend_name}\n")
        f.write(f"{friend_name},{username}\n")
    
    # Remove the friend request
    with open(requests_file, 'r') as f:
        lines = f.readlines()
    with open(requests_file, 'w') as f:
        for line in lines:
            if line.strip() != f"{friend_name},{username}":
                f.write(line)

def get_friends(username, file_path='friends.txt'):
    """Get a list of friends for the user."""
    ensure_file_exists(file_path)
    friends = []
    with open(file_path, 'r') as f:
        for line in f:
            stored_username, stored_friend_name = line.strip().split(',')
            if stored_username == username:
                friends.append(stored_friend_name)
    return list(set(friends))  # Remove duplicates

def store_message(sender, receiver, message, file_path='messages.txt'):
    """Store a message between two users."""
    ensure_file_exists(file_path)
    with open(file_path, 'a') as f:
        f.write(f"{sender},{receiver},{message}\n")

def get_messages(sender, receiver, file_path='messages.txt'):
    """Get messages between two users."""
    ensure_file_exists(file_path)
    messages = []
    with open(file_path, 'r') as f:
        for line in f:
            msg_sender, msg_receiver, msg_text = line.strip().split(',')
            if (msg_sender == sender and msg_receiver == receiver) or (msg_sender == receiver and msg_receiver == sender):
                messages.append({"sender": msg_sender, "text": msg_text})
    return messages

# --- Flask Routes ---

@app.route('/')
def index():
    return render_template('login/login.html')

@app.route('/add_friend', methods=['GET', 'POST'])
def add_friend():
    if request.method == 'POST':
        friend_name = request.form.get('friend_name')
        username = request.cookies.get('username')
        
        if not username:
            flash('You need to log in first.')
            return redirect(url_for('login'))
        
        send_friend_request(username, friend_name)
        flash('Friend request sent!')
        return redirect(url_for('friends'))
    
    return render_template('add_friend/add_friend.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if add_user_to_file(username, password):
            flash("Signup successful!")
            return redirect(url_for('login'))
        else:
            flash("Signup unsuccessful. User may already exist.")
            return redirect(url_for('signup'))
    return render_template('signup/signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if check_user_in_file(username, password):
            flash('Login successful!')
            resp = make_response(redirect(url_for('friends')))
            resp.set_cookie('username', username)
            return resp
        else:
            flash('Invalid credentials, please try again.')
            return redirect(url_for('login'))
    return render_template('login/login.html')

@app.route('/friends', methods=['GET'])
def friends():
    username = request.cookies.get('username')
    if not username:
        flash('You need to log in first.')
        return redirect(url_for('login'))
    
    friends_list = get_friends(username)
    pending_requests = get_pending_requests(username)
    return render_template('friends/friends.html', friends=friends_list, requests=pending_requests)

@app.route('/send_request', methods=['POST'])
def send_request():
    username = request.cookies.get('username')
    if not username:
        flash('You need to log in first.')
        return redirect(url_for('login'))
    
    friend_name = request.form.get('friend_name')
    send_friend_request(username, friend_name)
    flash('Friend request sent!')
    return redirect(url_for('friends'))

@app.route('/accept_request/<friend_name>', methods=['POST'])
def accept_request(friend_name):
    username = request.cookies.get('username')
    if not username:
        flash('You need to log in first.')
        return redirect(url_for('login'))
    
    accept_friend_request(username, friend_name)
    flash('Friend request accepted!')
    return redirect(url_for('friends'))

@app.route('/view_messages/<receiver>', methods=['GET', 'POST'])
def view_messages(receiver):
    sender = request.cookies.get('username')
    if not sender:
        flash('You need to log in first.')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        message = request.form.get('message')
        if message:
            store_message(sender, receiver, message)
            flash('Message sent!')
        return redirect(url_for('view_messages', receiver=receiver))
    
    messages = get_messages(sender, receiver)
    return render_template('view_messages.html', messages=messages, receiver=receiver)

if __name__ == '__main__':
    app.run(debug=True)
