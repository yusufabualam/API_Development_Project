from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from bson.objectid import ObjectId
import os
from config import Config
from dotenv import load_dotenv 

load_dotenv()

app = Flask(__name__)

# Load configuration from config.py
app.config.from_object(Config)
mongo = PyMongo(app)

# JWT Configuration
jwt = JWTManager(app)

@app.route('/')
def home():
    return  "<h1>Welcome to the Flask API!</h1>"

# Sign-Up Endpoint
@app.route("/signup", methods=['POST'])
def signup():
    data = request.get_json()
    if mongo.db.users.find_one({"email": data['email']}):
        return jsonify({"message": "Email is already registered."}), 400
    hashed_password = generate_password_hash(data['password'])
    new_user = {
        "name": data['name'],
        "email": data['email'],
        "password": hashed_password
    }
    mongo.db.users.insert_one(new_user)
    return jsonify({"message": "User registered successfully."}), 201

# Sign-In Endpoint with Token Generation
@app.route("/signin", methods=['POST'])
def signin():
    data = request.get_json()
    user = mongo.db.users.find_one({"email": data['email']})
    if user and check_password_hash(user['password'], data['password']):
        access_token = create_access_token(identity=str(user['_id']))
        refresh_token = create_refresh_token(identity=str(user['_id']))
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

# Create and Read Organizations
@app.route("/organization", methods=['GET', 'POST'])
@jwt_required()
def handle_organizations():
    if request.method == 'GET':
        organizations = mongo.db.organizations.find()
        response = [{
            "organization_id": str(org['_id']),
            "name": org['name'],
            "description": org.get('description', ''),
            "organization_members": [{
                "name": member['name'],
                "email": member['email'],
                "access_level": member['access_level']
            } for member in org.get('members', [])]
        } for org in organizations]
        return jsonify(response), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        new_org = {
            "name": data['name'],
            "description": data.get('description', ''),
            "members": []
        }
        org_id = mongo.db.organizations.insert_one(new_org).inserted_id
        creator_id = get_jwt_identity()
        
        # Add creator as an admin in the organization
        creator = mongo.db.users.find_one({"_id": ObjectId(creator_id)})
        if creator:
            mongo.db.organizations.update_one(
                {"_id": org_id},
                {"$push": {"members": {
                    "user_id": creator_id,
                    "name": creator['name'],
                    "email": creator['email'],
                    "access_level": "admin"
                }}}
            )
        
        return jsonify({
            "organization_id": str(org_id),
            "name": new_org['name'],
            "description": new_org['description'],
        }), 201

# Invite User to Organization
@app.route("/organization/<organization_id>/invite", methods=['POST'])
@jwt_required()
def invite_user(organization_id):
    data = request.get_json()
    user_to_invite = mongo.db.users.find_one({"email": data['user_email']})
    
    if not user_to_invite:
        return jsonify({"message": "User not found."}), 404
    
    user_id = str(user_to_invite['_id'])
    existing_member = mongo.db.organizations.find_one(
        {"_id": ObjectId(organization_id), "members.user_id": user_id}
    )
    if existing_member:
        return jsonify({"message": "User is already a member of the organization."}), 400
    
    # Add new member to the organization
    mongo.db.organizations.update_one(
        {"_id": ObjectId(organization_id)},
        {"$push": {"members": {
            "user_id": user_id,
            "name": user_to_invite['name'],
            "email": user_to_invite['email'],
            "access_level": "user"
        }}}
    )

    return jsonify({"message": "User invited successfully."}), 200

# CRUD for Single Organization
@app.route('/organization/<organization_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def handle_organization(organization_id):
    # Check if organization exists
    organization = mongo.db.organizations.find_one({"_id": ObjectId(organization_id)})
    if not organization:
        return jsonify({"message": "Organization not found."}), 404

    current_user_id = get_jwt_identity()

    # Check if user is a member of the organization
    membership = next((member for member in organization.get("members", []) if member["user_id"] == current_user_id), None)
    if not membership:
        return jsonify({"message": "Access denied. You are not a member of this organization."}), 403

    if request.method == 'GET':
        # Retrieve and return organization details with members
        organization_members = [{
            "name": member["name"],
            "email": member["email"],
            "access_level": member["access_level"]
        } for member in organization.get("members", [])]

        return jsonify({
            "organization_id": str(organization["_id"]),
            "name": organization["name"],
            "description": organization.get("description", ""),
            "organization_members": organization_members
        }), 200
    
    elif request.method == 'PUT':
        # Check if user has admin access
        if membership["access_level"] != "admin":
            return jsonify({"message": "Access denied. You do not have permission to update this organization."}), 403

        data = request.get_json()
        updated_data = {
            "name": data['name'],
            "description": data['description']
        }
        mongo.db.organizations.update_one({"_id": ObjectId(organization_id)}, {"$set": updated_data})
        
        return jsonify({
            "organization_id": str(organization["_id"]),
            "name": updated_data["name"],
            "description": updated_data["description"]
        }), 200

    elif request.method == 'DELETE':
        # Check if user has admin access
        if membership["access_level"] != "admin":
            return jsonify({"message": "Access denied. You do not have permission to delete this organization."}), 403
        
        mongo.db.organizations.delete_one({"_id": ObjectId(organization_id)})
        return jsonify({"message": "Organization deleted successfully."}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))