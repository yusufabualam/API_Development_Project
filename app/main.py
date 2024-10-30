from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from flask_restful import Api

DATABASE_URL = 'sqlite:///appdb.db'

app = Flask(__name__)

app.config['SECRET_KEY'] ='123456'
app.config["SQLALCHEMY_DATABASE_URI"]=DATABASE_URL

# JWT Configuration
app.config["JWT_SECRET_KEY"] = "yusuf12345"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
jwt = JWTManager(app)

db=SQLAlchemy(app)
api=Api(app)

# Define database models
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Sign-Up Endpoint
@app.route("/signup", methods=['POST'])
def signup():
    data = request.get_json()
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Email is already registered."}), 400
    hashed_password = generate_password_hash(data['password'])
    new_user = User(name=data['name'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully."}), 201

# Sign-In Endpoint with Token Generation
@app.route("/signin", methods=['POST'])
def signin():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        return jsonify({"message": "Login successful.", "access_token": access_token, "refresh_token": refresh_token}), 200
    return jsonify({"message": "Invalid credentials."}), 401

# Refresh Token Endpoint
@app.route("/refresh-token", methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    refresh_token = create_refresh_token(identity=current_user)
    return jsonify({"message": "Token refreshed successfully.", "access_token": access_token, "refresh_token": refresh_token}), 200

with app.app_context():
    db.create_all()
app.run(host='127.0.0.1', port=8080, debug=True)