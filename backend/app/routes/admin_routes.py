import logging
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.firebase import get_firestore
from app.utils.auth_utils import role_required
from app.utils.security_utils import log_audit_event, require_mfa
from app.models import RoleEnum

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
admin_bp = Blueprint('admin', __name__)

def get_firestore_client():
    """Get Firestore client instance."""
    return get_firestore()

@admin_bp.route('/dashboard', methods=['GET'])
@jwt_required()
@role_required('admin')
def admin_dashboard():
    """Admin dashboard with system statistics."""
    try:
        db = get_firestore_client()
        
        # Get users collection
        users_ref = db.collection('users')
        users = users_ref.get()
        
        # Initialize counters
        total_users = 0
        active_users = 0
        admin_count = 0
        user_count = 0
        verifier_count = 0
        
        # Count statistics
        for user in users:
            user_data = user.to_dict()
            total_users += 1
            if user_data.get('is_active', True):
                active_users += 1
            if user_data.get('role') == RoleEnum.ADMIN.value:
                admin_count += 1
            elif user_data.get('role') == RoleEnum.USER.value:
                user_count += 1
            elif user_data.get('role') == RoleEnum.VERIFIER.value:
                verifier_count += 1
        
        return jsonify({
            "user_stats": {
                "total": total_users,
                "active": active_users,
                "inactive": total_users - active_users
            },
            "role_distribution": {
                "admin": admin_count,
                "user": user_count,
                "verifier": verifier_count
            }
        }), 200
    
    except Exception as e:
        logger.error(f"Error in admin dashboard: {e}")
        return jsonify({"error": "Failed to load admin dashboard data"}), 500

@admin_bp.route('/users/<string:user_id>', methods=['PUT'])
@jwt_required()
@role_required('admin')
@require_mfa
def update_user(user_id):
    """Update user details (admin only)."""
    data = request.get_json()
    current_admin_id = get_jwt_identity()
    
    if not data:
        return jsonify({"error": "No input data provided"}), 400
    
    try:
        db = get_firestore_client()
        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            log_audit_event(
                user_id=current_admin_id,
                action="admin_update_user",
                resource_type="user",
                resource_id=user_id,
                status="failure",
                details="User not found"
            )
            return jsonify({"error": "User not found"}), 404
        
        user_data = user_doc.to_dict()
        
        # Log the admin action
        log_audit_event(
            user_id=current_admin_id,
            action="admin_update_user_initiated",
            resource_type="user",
            resource_id=user_id,
            details={"changed_fields": list(data.keys())}
        )
        
        # Update fields if they exist in the request
        updates = {}
        
        if 'email' in data:
            # Check if email already exists for another user
            email_query = db.collection('users').where('email', '==', data['email']).limit(1).get()
            if email_query and email_query[0].id != user_id:
                log_audit_event(
                    user_id=current_admin_id,
                    action="admin_update_user",
                    resource_type="user",
                    resource_id=user_id,
                    status="failure",
                    details={"reason": "Email already in use", "attempted_email": data['email']}
                )
                return jsonify({"error": "Email already in use"}), 409
            updates['email'] = data['email']
        
        if 'username' in data:
            # Check if username already exists for another user
            username_query = db.collection('users').where('username', '==', data['username']).limit(1).get()
            if username_query and username_query[0].id != user_id:
                log_audit_event(
                    user_id=current_admin_id,
                    action="admin_update_user",
                    resource_type="user",
                    resource_id=user_id,
                    status="failure",
                    details={"reason": "Username already in use", "attempted_username": data['username']}
                )
                return jsonify({"error": "Username already in use"}), 409
            updates['username'] = data['username']
        
        if 'role' in data:
            # Validate role
            if data['role'] not in [role.value for role in RoleEnum]:
                log_audit_event(
                    user_id=current_admin_id,
                    action="admin_update_user",
                    resource_type="user",
                    resource_id=user_id,
                    status="failure",
                    details={"reason": "Invalid role", "attempted_role": data['role']}
                )
                return jsonify({"error": "Invalid role"}), 400
            updates['role'] = data['role']
        
        if 'is_active' in data:
            updates['is_active'] = bool(data['is_active'])
        
        # Apply updates
        if updates:
            user_ref.update(updates)
        
        log_audit_event(
            user_id=current_admin_id,
            action="admin_update_user_success",
            resource_type="user",
            resource_id=user_id
        )
        
        # Get updated user data
        updated_user = user_ref.get().to_dict()
        return jsonify({"message": "User updated successfully", "user": updated_user}), 200
    
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        
        log_audit_event(
            user_id=current_admin_id,
            action="admin_update_user",
            resource_type="user",
            resource_id=user_id,
            status="failure",
            details={"error": str(e)}
        )
        
        return jsonify({"error": "Failed to update user"}), 500

@admin_bp.route('/users/<string:user_id>', methods=['DELETE'])
@jwt_required()
@role_required('admin')
@require_mfa
def delete_user(user_id):
    """Delete a user (admin only)."""
    current_admin_id = get_jwt_identity()
    
    try:
        db = get_firestore_client()
        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            log_audit_event(
                user_id=current_admin_id,
                action="admin_delete_user",
                resource_type="user",
                resource_id=user_id,
                status="failure",
                details="User not found"
            )
            return jsonify({"error": "User not found"}), 404
        
        # Check if admin is trying to delete themselves
        if user_id == current_admin_id:
            log_audit_event(
                user_id=current_admin_id,
                action="admin_delete_user",
                resource_type="user",
                resource_id=user_id,
                status="failure",
                details="Cannot delete self"
            )
            return jsonify({"error": "Cannot delete your own account"}), 403
        
        user_data = user_doc.to_dict()
        
        # Log the delete attempt
        log_audit_event(
            user_id=current_admin_id,
            action="admin_delete_user_initiated",
            resource_type="user",
            resource_id=user_id,
            details={"username": user_data['username'], "email": user_data['email'], "role": user_data['role']}
        )
        
        # Delete user
        user_ref.delete()
        
        # Log successful deletion
        log_audit_event(
            user_id=current_admin_id,
            action="admin_delete_user_success",
            resource_type="user",
            resource_id=user_id
        )
        
        return jsonify({"message": "User deleted successfully"}), 200
    
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        
        log_audit_event(
            user_id=current_admin_id,
            action="admin_delete_user",
            resource_type="user",
            resource_id=user_id,
            status="failure",
            details={"error": str(e)}
        )
        
        return jsonify({"error": "Failed to delete user"}), 500
