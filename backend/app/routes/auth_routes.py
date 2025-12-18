import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, create_refresh_token, 
    get_jwt_identity, jwt_required, get_jwt
)
from app import db
from app.models import User, BlacklistedToken, MFASession
from app.utils.auth_utils import (
    validate_password,
    validate_email,
    validate_username,
    register_user,
)
from app.utils.security_utils import log_audit_event, require_mfa
from app.utils.mfa_utils import create_mfa_session

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user using Firebase Firestore."""
    try:
        # Check if request has JSON content
        if not request.is_json:
            logger.warning("Registration request missing JSON content type")
            return jsonify({"error": "Content-Type must be application/json"}), 400
        
        data = request.get_json()
        
        if not data:
            logger.warning("Registration request with empty data")
            return jsonify({"error": "No input data provided"}), 400
        
        logger.info(f"Registration request received: {list(data.keys())}")
        
        # Use the Firebase-based registration function
        response_data, status_code = register_user(data)
        
        logger.info(f"Registration response status: {status_code}")
        
        # Return the response (both success and error cases)
        return jsonify(response_data), status_code
            
    except Exception as e:
        logger.error(f"Unexpected error in register route: {str(e)}", exc_info=True)
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        # Return more detailed error in development
        error_message = str(e)
        if current_app.config.get('DEBUG'):
            return jsonify({
                "error": f"Registration failed: {error_message}",
                "traceback": traceback.format_exc()
            }), 500
        return jsonify({"error": f"Registration failed: {error_message}"}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Login a user via Firestore."""
    from app.firebase import get_firestore
    from werkzeug.security import check_password_hash
    
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "No input data provided"}), 400
    
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    try:
        db = get_firestore()
        users_ref = db.collection('users')
        
        # Find user by email
        user_query = users_ref.where('email', '==', email).get()
        
        if not user_query:
            logger.warning(f"Login failed: user not found for {email}")
            return jsonify({"error": "Invalid email or password"}), 401
        
        user_doc = user_query[0]
        user_data = user_doc.to_dict()
        
        # Verify password
        if not check_password_hash(user_data['password'], password):
            logger.warning(f"Login failed: invalid password for {email}")
            return jsonify({"error": "Invalid email or password"}), 401
        
        # Generate access token
        access_token = create_access_token(
            identity=user_doc.id,
            additional_claims={"role": user_data.get('role', 'user')}
        )
        
        # Log successful login
        log_audit_event(
            user_id=user_doc.id,
            action='login',
            details='User logged in successfully',
            status='success'
        )
        
        logger.info(f"Login successful for {email}")
        return jsonify({
            "message": "Login successful",
            "token": access_token,
            "access_token": access_token,
            "user": {
                "id": user_doc.id,
                "email": user_data.get('email'),
                "firstName": user_data.get('firstName', ''),
                "lastName": user_data.get('lastName', ''),
                "role": user_data.get('role', 'user'),
                "mfa_enabled": user_data.get('mfa_enabled', False)
            }
        }), 200
    
    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        return jsonify({"error": "Login failed"}), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh an access token."""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        if not user.is_active:
            return jsonify({"error": "Account is deactivated"}), 403
        
        # Create new access token
        access_token = create_access_token(
            identity=current_user_id,
            additional_claims={"role": user.role}
        )
        
        return jsonify({"access_token": access_token}), 200
    
    except Exception as e:
        logger.error(f"Error refreshing token: {e}")
        return jsonify({"error": "Token refresh failed"}), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout a user by blacklisting their current token."""
    try:
        jwt_token = get_jwt()
        jti = jwt_token['jti']
        
        # Add token to blacklist
        blacklisted_token = BlacklistedToken(token=jti)
        db.session.add(blacklisted_token)
        db.session.commit()
        
        return jsonify({"message": "Successfully logged out"}), 200
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during logout: {e}")
        return jsonify({"error": "Logout failed"}), 500

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_user_profile():
    """Get the current user's profile from Firestore."""
    from app.firebase import get_firestore
    
    try:
        current_user_id = get_jwt_identity()
        db = get_firestore()
        
        user_doc = db.collection('users').document(current_user_id).get()
        
        if not user_doc.exists:
            logger.warning(f"User profile not found for {current_user_id}")
            return jsonify({"error": "User not found"}), 404
        
        user_data = user_doc.to_dict()
        return jsonify({
            "user": {
                "id": user_doc.id,
                "email": user_data.get('email'),
                "firstName": user_data.get('firstName', ''),
                "lastName": user_data.get('lastName', ''),
                "role": user_data.get('role', 'user'),
                "mfa_enabled": user_data.get('mfa_enabled', False)
            }
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching user profile: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to retrieve user profile"}), 500


@auth_bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    """Test endpoint for JWT protection."""
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    role = claims.get('role', 'user')
    
    return jsonify(
        logged_in_as=current_user_id,
        role=role,
        message="This is a protected endpoint"
    ), 200
