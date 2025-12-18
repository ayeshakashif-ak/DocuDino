import logging
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.firebase import get_firestore
from app.utils.auth_utils import validate_password, role_required
from app.utils.security_utils import log_audit_event, require_mfa

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
user_bp = Blueprint('user', __name__)

@user_bp.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    """User dashboard endpoint."""
    current_user_id = get_jwt_identity()
    db = get_firestore()
    
    try:
        # Get user document
        user_doc = db.collection('users').document(current_user_id).get()
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404
        
        user_data = user_doc.to_dict()
        return jsonify({"user": user_data}), 200
    
    except Exception as e:
        logger.error(f"Error in dashboard: {e}")
        return jsonify({"error": "Failed to load dashboard data"}), 500

@user_bp.route('/profile', methods=['PUT'])
@jwt_required()
@require_mfa
def update_profile():
    """Update user profile."""
    current_user_id = get_jwt_identity()
    data = request.get_json()
    db = get_firestore()
    
    if not data:
        return jsonify({"error": "No input data provided"}), 400
    
    try:
        # Get user document
        user_ref = db.collection('users').document(current_user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404
        
        user_data = user_doc.to_dict()
        
        # Log the profile update attempt
        log_audit_event(
            action="profile_update_initiated",
            user_id=current_user_id,
            details={"changed_fields": list(data.keys())}
        )
        
        update_data = {}
        
        # Update fields if they exist in the request
        if 'email' in data:
            # Check if email already exists for another user
            existing_user = db.collection('users').where('email', '==', data['email']).limit(1).get()
            if existing_user and existing_user[0].id != current_user_id:
                log_audit_event(
                    action="profile_update",
                    user_id=current_user_id,
                    status="failure",
                    details={"reason": "Email already in use", "attempted_email": data['email']}
                )
                return jsonify({"error": "Email already in use"}), 409
            old_email = user_data['email']
            update_data['email'] = data['email']
            log_audit_event(
                action="email_changed",
                user_id=current_user_id,
                details={"old_email": old_email, "new_email": data['email']}
            )
        
        if 'username' in data:
            # Check if username already exists for another user
            existing_user = db.collection('users').where('username', '==', data['username']).limit(1).get()
            if existing_user and existing_user[0].id != current_user_id:
                log_audit_event(
                    action="profile_update",
                    user_id=current_user_id,
                    status="failure",
                    details={"reason": "Username already in use", "attempted_username": data['username']}
                )
                return jsonify({"error": "Username already in use"}), 409
            old_username = user_data['username']
            update_data['username'] = data['username']
            log_audit_event(
                action="username_changed",
                user_id=current_user_id,
                details={"old_username": old_username, "new_username": data['username']}
            )
        
        if 'password' in data:
            # Validate password
            password_validation = validate_password(data['password'])
            if not password_validation['valid']:
                log_audit_event(
                    action="password_change",
                    user_id=current_user_id,
                    status="failure",
                    details={"reason": "Invalid password format"}
                )
                return jsonify({"error": password_validation['message']}), 400
            
            # Verify current password if provided
            if 'current_password' in data:
                if not user_data['password'] == data['current_password']:  # In production, use proper password hashing
                    log_audit_event(
                        action="password_change",
                        user_id=current_user_id,
                        status="failure",
                        details={"reason": "Invalid current password"}
                    )
                    return jsonify({"error": "Current password is incorrect"}), 401
            else:
                log_audit_event(
                    action="password_change",
                    user_id=current_user_id,
                    status="failure",
                    details={"reason": "Current password not provided"}
                )
                return jsonify({"error": "Current password is required to change password"}), 400
            
            update_data['password'] = data['password']  # In production, hash the password
            log_audit_event(
                action="password_changed",
                user_id=current_user_id
            )
        
        # Update user document
        user_ref.update(update_data)
        
        log_audit_event(
            action="profile_updated",
            user_id=current_user_id,
            status="success"
        )
        
        # Get updated user data
        updated_user = user_ref.get().to_dict()
        return jsonify({"message": "Profile updated successfully", "user": updated_user}), 200
    
    except Exception as e:
        logger.error(f"Error updating profile: {e}")
        
        log_audit_event(
            action="profile_update",
            user_id=current_user_id,
            status="failure",
            details={"error": str(e)}
        )
        
        return jsonify({"error": "Failed to update profile"}), 500

@user_bp.route('/all', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_all_users():
    """Get all users (admin only)."""
    db = get_firestore()
    
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Get paginated users
        users_ref = db.collection('users')
        total = len(list(users_ref.get()))
        start_at = (page - 1) * per_page
        users = [doc.to_dict() for doc in users_ref.limit(per_page).offset(start_at).get()]
        
        return jsonify({
            "users": users,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
            "page": page
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return jsonify({"error": "Failed to retrieve users"}), 500

@user_bp.route('/<string:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Get a specific user."""
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    role = claims.get('role', 'user')
    db = get_firestore()
    
    # Only allow users to view their own profile unless they're admin
    if current_user_id != user_id and role != 'admin':
        return jsonify({"error": "Unauthorized access"}), 403
    
    try:
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({"user": user_doc.to_dict()}), 200
    
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        return jsonify({"error": "Failed to retrieve user"}), 500
