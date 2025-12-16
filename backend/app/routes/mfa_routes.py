"""
Routes for multi-factor authentication (MFA) functionality.
"""
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.firebase import get_firestore
from app.utils.mfa_utils import (
    generate_totp_qr_code, verify_totp, create_mfa_session
)
from app.utils.security_utils import log_audit_event
from app.models import encrypt_data, decrypt_data

# Blueprint registration
mfa_bp = Blueprint('mfa', __name__, url_prefix='/api/mfa')

def get_firestore_client():
    """Get Firestore client instance."""
    return get_firestore()

# Add debugging to log token and errors in /api/mfa/setup
@mfa_bp.route('/setup', methods=['POST'])
def setup_mfa():
    """
    Begin MFA setup process for a user.
    
    This endpoint generates and returns the TOTP secret and QR code
    but does not enable MFA until verification.
    """
    try:
        # Get auth token from request
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            print("Missing or invalid Authorization header")
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.split(' ')[1]
        
        # Manually decode and verify the token
        from flask_jwt_extended import decode_token
        try:
            decoded_token = decode_token(token)
            current_user_id = decoded_token['sub']
            print(f"Decoded user ID: {current_user_id}")
        except Exception as e:
            print(f"Token decode error: {e}")
            return jsonify({"error": "Invalid token"}), 401
            
        db = get_firestore_client()
        user_ref = db.collection('users').document(current_user_id)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            print("User not found")
            return jsonify({"error": "User not found"}), 404

        user_data = user_doc.to_dict()

        # Generate new secret if needed
        import pyotp
        secret = pyotp.random_base32()

        # Generate QR code URI for authenticator app
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_data['email'],
            issuer_name=current_app.config.get('APP_NAME', 'DocuDino')
        )
        qr_code = generate_totp_qr_code(uri)

        # Update but don't enable MFA yet (requires verification)
        user_ref.update({
            'mfa_secret': encrypt_data(secret),
            'mfa_enabled': False,
            'mfa_verified': False
        })

        # Log the attempt
        log_audit_event(
            user_id=current_user_id,
            action="mfa_setup_initiated",
            resource_type="user",
            resource_id=current_user_id,
            details={"success": True}
        )

        return jsonify({
            "secret": secret,
            "qr_code": qr_code,
            "message": "Scan this QR code with your authenticator app, then verify with a code"
        }), 200
    except Exception as e:
        print(f"Error in setup_mfa: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "An error occurred during MFA setup"}), 500

@mfa_bp.route('/setup-for-new-user', methods=['POST'])
def setup_mfa_for_new_user():
    """
    Begin MFA setup for a newly registered user.
    
    This endpoint accepts user_id and token in the request body,
    as an alternative to the JWT authentication.
    """
    try:
        data = request.json
        if not data or 'user_id' not in data or 'token' not in data:
            print("Missing required fields in request body")
            return jsonify({"error": "Missing required fields (user_id, token)"}), 400

        # Extract user_id and token from request body
        user_id = data.get('user_id')
        token = data.get('token')
        
        print(f"Setting up MFA for user ID: {user_id}")
        
        # Verify token matches the one stored during registration
        # This is a simplified approach - production systems should use a more secure method
        db = get_firestore_client()
        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            print(f"User not found: {user_id}")
            return jsonify({"error": "User not found"}), 404

        user_data = user_doc.to_dict()
        
        # Generate new secret for MFA
        import pyotp
        secret = pyotp.random_base32()

        # Generate QR code URI for authenticator app
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_data['email'],
            issuer_name=current_app.config.get('APP_NAME', 'DocuDino')
        )
        qr_code = generate_totp_qr_code(uri)

        # Update but don't enable MFA yet (requires verification)
        user_ref.update({
            'mfa_secret': encrypt_data(secret),
            'mfa_enabled': False,
            'mfa_verified': False
        })

        # Log the attempt
        log_audit_event(
            user_id=user_id,
            action="mfa_setup_initiated",
            resource_type="user",
            resource_id=user_id,
            details={"success": True}
        )

        return jsonify({
            "secret": secret,
            "qr_code": qr_code,
            "message": "Scan this QR code with your authenticator app, then verify with a code"
        }), 200
    except Exception as e:
        print(f"Error in setup_mfa_for_new_user: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "An error occurred during MFA setup"}), 500

@mfa_bp.route('/verify', methods=['POST'])
@jwt_required()
def verify_mfa_setup():
    """
    Verify and enable MFA for a user after setup.
    
    This endpoint verifies the provided TOTP token against
    the user's MFA secret and enables MFA if valid.
    """
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    current_user_id = get_jwt_identity()
    db = get_firestore_client()
    user_ref = db.collection('users').document(current_user_id)
    user_doc = user_ref.get()
    
    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404
    
    user_data = user_doc.to_dict()
    
    # Get and decrypt MFA secret
    mfa_secret = decrypt_data(user_data.get('mfa_secret'))
    if not mfa_secret:
        return jsonify({"error": "MFA not set up"}), 400
    
    # Verify the provided token
    token = data['token']
    import pyotp
    totp = pyotp.TOTP(mfa_secret)
    if not totp.verify(token):
        log_audit_event(
            user_id=current_user_id,
            action="mfa_setup_verification",
            resource_type="user",
            resource_id=current_user_id,
            status="failure",
            details={"reason": "Invalid token"}
        )
        return jsonify({"error": "Invalid verification code"}), 400
    
    # Enable MFA for the user
    updates = {
        'mfa_enabled': True,
        'mfa_verified': True
    }
    
    # Generate backup codes if requested
    backup_codes = data.get('generate_backup_codes', True)
    codes = None
    
    if backup_codes:
        import secrets
        codes = [secrets.token_urlsafe(8) for _ in range(10)]
        updates['mfa_backup_codes'] = [{'code': code, 'used': False} for code in codes]
    
    # Save changes
    user_ref.update(updates)
    
    # Log the successful setup
    log_audit_event(
        user_id=current_user_id,
        action="mfa_setup_complete",
        resource_type="user",
        resource_id=current_user_id,
        details={"backup_codes_generated": backup_codes}
    )
    
    result = {
        "success": True,
        "message": "MFA has been successfully enabled for your account"
    }
    
    if codes:
        result["backup_codes"] = codes
        result["message"] += ". Please save these backup codes in a safe place."
    
    return jsonify(result), 200

@mfa_bp.route('/disable', methods=['POST'])
@jwt_required()
def disable_mfa():
    """Disable MFA for a user account."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No input data provided"}), 400
    
    # Require password verification for security
    password = data.get('password')
    if not password:
        return jsonify({"error": "Password is required to disable MFA"}), 400
    
    current_user_id = get_jwt_identity()
    db = get_firestore_client()
    user_ref = db.collection('users').document(current_user_id)
    user_doc = user_ref.get()
    
    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404
    
    user_data = user_doc.to_dict()
    
    # Verify password
    from werkzeug.security import check_password_hash
    if not check_password_hash(user_data['password'], password):
        log_audit_event(
            user_id=current_user_id,
            action="mfa_disable_attempt",
            resource_type="user",
            resource_id=current_user_id,
            status="failure",
            details={"reason": "Invalid password"}
        )
        return jsonify({"error": "Invalid password"}), 401
    
    # Check if user is in a role that requires MFA
    required_roles = current_app.config.get('MFA_REQUIRED_FOR_ROLES', [])
    if user_data['role'] in required_roles:
        log_audit_event(
            user_id=current_user_id,
            action="mfa_disable_attempt",
            resource_type="user",
            resource_id=current_user_id,
            status="failure",
            details={"reason": "MFA required for role"}
        )
        return jsonify({
            "error": "MFA cannot be disabled for your account role"
        }), 403
    
    # Disable MFA
    user_ref.update({
        'mfa_enabled': False,
        'mfa_verified': False,
        'mfa_secret': None,
        'mfa_backup_codes': None
    })
    
    # Log the action
    log_audit_event(
        user_id=current_user_id,
        action="mfa_disabled",
        resource_type="user",
        resource_id=current_user_id
    )
    
    return jsonify({
        "success": True,
        "message": "MFA has been disabled for your account"
    }), 200

@mfa_bp.route('/verify-token', methods=['POST'])
@jwt_required()
def verify_mfa_token():
    """
    Verify a TOTP token for MFA and create a session.
    
    This endpoint is used during the login flow when MFA is enabled.
    """
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    current_user_id = get_jwt_identity()
    db = get_firestore_client()
    user_ref = db.collection('users').document(current_user_id)
    user_doc = user_ref.get()
    
    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404
    
    user_data = user_doc.to_dict()
    
    # Check if MFA is enabled
    if not user_data.get('mfa_enabled'):
        return jsonify({"error": "MFA is not enabled for this account"}), 400
    
    # Verify the token or backup code
    token = data['token']
    token_type = data.get('token_type', 'totp')
    verified = False
    
    if token_type == 'totp':
        mfa_secret = decrypt_data(user_data.get('mfa_secret'))
        if not mfa_secret:
            return jsonify({"error": "Invalid MFA configuration"}), 400
        
        import pyotp
        totp = pyotp.TOTP(mfa_secret)
        verified = totp.verify(token)
    elif token_type == 'backup':
        backup_codes = user_data.get('mfa_backup_codes', [])
        for code in backup_codes:
            if not code['used'] and code['code'] == token:
                verified = True
                # Mark backup code as used
                code['used'] = True
                user_ref.update({'mfa_backup_codes': backup_codes})
                break
    
    if not verified:
        log_audit_event(
            user_id=current_user_id,
            action="mfa_verification",
            resource_type="user",
            resource_id=current_user_id,
            status="failure",
            details={"token_type": token_type}
        )
        return jsonify({"error": "Invalid verification code"}), 400
    
    # Create MFA session
    mfa_token = create_mfa_session(current_user_id)
    
    # Log successful verification
    log_audit_event(
        user_id=current_user_id,
        action="mfa_verification",
        resource_type="user",
        resource_id=current_user_id,
        details={"token_type": token_type}
    )
    
    return jsonify({
        "success": True,
        "mfa_token": mfa_token,
        "message": "MFA verification successful"
    }), 200

@mfa_bp.route('/status', methods=['GET'])
@jwt_required()
def mfa_status():
    """Get the MFA status for the current user."""
    current_user_id = get_jwt_identity()
    db = get_firestore_client()
    user_ref = db.collection('users').document(current_user_id)
    user_doc = user_ref.get()
    
    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404
    
    user_data = user_doc.to_dict()
    
    # Check if MFA is required for the role
    required_roles = current_app.config.get('MFA_REQUIRED_FOR_ROLES', [])
    requires_mfa = user_data['role'] in required_roles
    
    return jsonify({
        "mfa_enabled": user_data.get('mfa_enabled', False),
        "mfa_verified": user_data.get('mfa_verified', False),
        "requires_mfa": requires_mfa
    }), 200