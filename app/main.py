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

class Organization(db.Model):
    __tablename__ = "organizations"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    members = db.relationship("OrganizationMember", back_populates="organization")

class OrganizationMember(db.Model):
    __tablename__ = "organization_members"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    access_level = db.Column(db.String(50), nullable=False, default="user")
    user = db.relationship("User")
    organization = db.relationship("Organization", back_populates="members")

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

# Create and Read Organizations
@app.route("/organization", methods=['GET', 'POST'])
@jwt_required()
def handle_organizations():
    if request.method == 'GET':
        organizations = Organization.query.all()
        response = [{
            "organization_id": org.id,
            "name": org.name,
            "description": org.description,
            "organization_members": [{
                "name": member.user.name,
                "email": member.user.email,
                "access_level": member.access_level
            } for member in org.members]
        } for org in organizations]
        return jsonify(response), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        new_org = Organization(name=data['name'], description=data['description'])
        db.session.add(new_org)
        db.session.commit()
        creator_id = get_jwt_identity()
        # Add creator as an admin in the organization
        creator_member = OrganizationMember(user_id=creator_id, organization_id=new_org.id, access_level="admin")
        db.session.add(creator_member)
        db.session.commit()
        return jsonify({
            "organization_id": new_org.id,
            "name": new_org.name,
            "description": new_org.description,
        }), 201

# Invite User to Organization
@app.route("/organization/<int:organization_id>/invite", methods=['POST'])
@jwt_required()
def invite_user(organization_id):
    data = request.get_json()
    user_to_invite = User.query.filter_by(email=data['user_email']).first()
    
    if not user_to_invite:
        return jsonify({"message": "User not found."}), 404

    existing_member = OrganizationMember.query.filter_by(user_id=user_to_invite.id, organization_id=organization_id).first()
    if existing_member:
        return jsonify({"message": "User is already a member of the organization."}), 400
    
    new_member = OrganizationMember(user_id=user_to_invite.id, organization_id=organization_id, access_level="user")
    db.session.add(new_member)
    db.session.commit()

    return jsonify({"message": "User invited successfully."}), 200

# CRUD for Single Organization
@app.route('/organization/<int:organization_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def handle_organization(organization_id):
    organization = Organization.query.get_or_404(organization_id)
    current_user_id = get_jwt_identity()
    
    # Check if user is a member of the organization
    membership = OrganizationMember.query.filter_by(user_id=current_user_id, organization_id=organization_id).first()
    if not membership:
        return jsonify({"message": "Access denied. You are not a member of this organization."}), 403
    
    if request.method == 'GET':
        # Retrieve and return organization details with members
        members = OrganizationMember.query.filter_by(organization_id=organization_id).all()
        organization_members = [{
            "name": member.user.name,
            "email": member.user.email,
            "access_level": member.access_level
        } for member in members]
        
        return jsonify({
            "organization_id": organization.id,
            "name": organization.name,
            "description": organization.description,
            "organization_members": organization_members
        }), 200
    
    elif request.method == 'PUT':
        # Check if user has admin access
        if membership.access_level != "admin":
            return jsonify({"message": "Access denied. You do not have permission to update this organization."}), 403
        
        data = request.get_json()
        organization.name = data['name']
        organization.description = data['description']
        db.session.commit()
        return jsonify({
            "organization_id": organization.id,
            "name": organization.name,
            "description": organization.description,
        }), 200
    
    elif request.method == 'DELETE':
        # Check if user has admin access
        if membership.access_level != "admin":
            return jsonify({"message": "Access denied. You do not have permission to delete this organization."}), 403
        
        OrganizationMember.query.filter_by(organization_id=organization_id).delete()
        db.session.delete(organization)
        db.session.commit()
        return jsonify({"message": "Organization deleted successfully."}), 200

with app.app_context():
    db.create_all()
app.run(host='127.0.0.1', port=8080, debug=True)