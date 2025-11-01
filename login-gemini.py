import os
from flask import Flask, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

# --- 1. APP AND CONFIGURATION SETUP ---

app = Flask(__name__)

# IMPORTANT: A secret key is essential for securing session data (cookies).
# In a real-world app, load this from an environment variable.
app.config['SECRET_KEY'] = os.urandom(24).hex() 

# Simple in-memory storage for users. Key is the username, value is the user object.
# In a real application, this would be a database (like PostgreSQL, MySQL, or MongoDB).
USERS = {} 
# Example structure:
# {
#     'testuser': {
#         'id': 'uuid-123',
#         'password_hash': 'sha256:...'
#     }
# }

# --- 2. HELPER FUNCTIONS ---

def get_current_user():
    """Retrieves the user dictionary from the session if they are logged in."""
    user_id = session.get('user_id')
    if user_id:
        # Find user by ID (simulate database lookup)
        for user_data in USERS.values():
            if user_data['id'] == user_id:
                return user_data
    return None

def login_required(f):
    """A simple decorator to protect routes."""
    def wrapper(*args, **kwargs):
        if not get_current_user():
            # If not logged in, return a 401 Unauthorized JSON response
            return jsonify({'message': 'Authentication required. Please log in.'}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__ # Needed for Flask to register the route correctly
    return wrapper

# --- 3. API ROUTES ---

@app.route('/register', methods=['POST'])
def register():
    """Handles new user registration."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required.'}), 400

    if username in USERS:
        return jsonify({'message': 'Username already exists.'}), 409

    # Generate a secure password hash
    hashed_password = generate_password_hash(password)
    
    # Simulate UUID for user ID
    user_id = os.urandom(16).hex()

    # Store user data
    USERS[username] = {
        'id': user_id,
        'password_hash': hashed_password,
        'username': username
    }

    return jsonify({'message': 'User registered successfully!', 'user_id': user_id}), 201

@app.route('/login', methods=['POST'])
def login():
    """Handles user login and session creation."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = USERS.get(username)

    if user and check_password_hash(user['password_hash'], password):
        # Authentication successful. Set the session cookie.
        session['user_id'] = user['id']
        return jsonify({'message': 'Login successful!', 'username': user['username']}), 200
    else:
        # Authentication failed
        return jsonify({'message': 'Invalid username or password.'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    """Logs out the user by clearing the session."""
    if 'user_id' in session:
        session.pop('user_id')
        return jsonify({'message': 'Logout successful!'}), 200
    return jsonify({'message': 'You were not logged in.'}), 400

@app.route('/protected', methods=['GET'])
@login_required
def protected():
    """A route only accessible to logged-in users."""
    current_user = get_current_user()
    return jsonify({
        'message': f"Welcome, {current_user['username']}! You accessed the protected resource.",
        'user_id': current_user['id'],
        'status': 'access granted'
    }), 200

@app.route('/status', methods=['GET'])
def status():
    """Checks the current login status."""
    user = get_current_user()
    if user:
        return jsonify({
            'logged_in': True,
            'username': user['username'],
            'user_id': user['id']
        }), 200
    else:
        return jsonify({'logged_in': False, 'message': 'Not logged in.'}), 200


if __name__ == '__main__':
    # When running locally, Flask is started here.
    # In the immersive environment, the Flask app is typically run by a web server.
    print("API initialized. Use /register, /login, and /protected routes.")
    app.run(debug=True)
