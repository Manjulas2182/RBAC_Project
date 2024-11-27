# import all necessary modules
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

# Initialize the Flask app
app = Flask(__name__)

# Load the configuration
app.config.from_object('config.Config')

# Initialize the database
db = SQLAlchemy(app)

# Initialize the JWT Manager for authentication
jwt = JWTManager(app)

#create User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"<User {self.username}, Role: {self.role}>"

# Registration route
@app.route('/reg', methods=['POST'])
def register():
    try:
        username = request.json.get('username', None)
        password = request.json.get('password', None)
        role = request.json.get('role', None)

        if not role:
            return jsonify({"msg": "Role is required"}), 400

        if not username or not password:
            return jsonify({"msg": "Username and password are required"}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({"msg": "Username already exists"}), 400

        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password, role=role)

        db.session.add(new_user)
        db.session.commit()

        return jsonify({"msg": "User registered successfully"}), 201
    except Exception as e:
        db.session.rollback()  # Rollback if any exception occurs
        return jsonify({"msg": "An error occurred while registering the user", "error": str(e)}), 500

# Login route
@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.json.get('username').strip()
        password = request.json.get('password').strip()

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            return jsonify({"msg": "Invalid username or password"}), 401

        access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(hours=2))
        return jsonify(access_token=access_token), 200
    except Exception as e:
        return jsonify({"msg": "An error occurred during login", "error": str(e)}), 500

# Logout route
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        return jsonify({"msg": "Successfully logged out. Token discarded."}), 200
    except Exception as e:
        return jsonify({"msg": "An error occurred during logout", "error": str(e)}), 500

# Protected Route only for Admin
@app.route('/admin', methods=['GET'])
@jwt_required()
def admin():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user:
            return jsonify(msg="User not found"), 404

        if user.role == 'admin':
            return jsonify(msg="Welcome, Admin! You have access to this route."), 200
        return jsonify(msg="You are not authorized to access this route."), 403
    except Exception as e:
        return jsonify({"msg": "An error occurred while accessing the admin route", "error": str(e)}), 500

# Protected Route only for Moderator
@app.route('/moderator', methods=['GET'])
@jwt_required()
def moderator():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return jsonify(msg="User not found"), 404

        if user.role == 'moderator':
            return jsonify(msg="Welcome, Moderator! You have access to this route."), 200
        return jsonify(msg="You are not authorized to access this route."), 403
    except Exception as e:
        return jsonify({"msg": "An error occurred while accessing the moderator route", "error": str(e)}), 500

# Protected Route only for User
@app.route('/user', methods=['GET'])
@jwt_required()
def user():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user:
            return jsonify(msg="User not found"), 404

        if user.role == 'user':
            return jsonify(msg="Welcome, user! You have access to this route."), 200
        return jsonify(msg="You are not authorized to access this route."), 403
    except Exception as e:
        return jsonify({"msg": "An error occurred while accessing the user route", "error": str(e)}), 500

# Refresh Token Route
@app.route('/refresh', methods=['POST'])
@jwt_required()
def refresh():
    try:
        current_user_id = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user_id)
        return jsonify(access_token=new_access_token), 200
    except Exception as e:
        return jsonify({"msg": "An error occurred while refreshing the token", "error": str(e)}), 500

# Create all tables in the database
with app.app_context():
    db.create_all()  # This creates the tables as defined in the models

# Error handlers for HTTP errors
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"msg": "Resource not found"}), 404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"msg": "Internal Server Error"}), 500

# Start the Flask app
if __name__ == "__main__":
    app.run(debug=True)
