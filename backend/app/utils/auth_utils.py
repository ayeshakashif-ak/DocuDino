import re
import logging
from functools import wraps
from flask import jsonify, current_app
from flask_jwt_extended import get_jwt
from datetime import datetime, timedelta
from app.firebase import get_firestore
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import bcrypt
import secrets

# Configure logging
logger = logging.getLogger(__name__)

def validate_password(password):
    """
    Validate password strength.
    
    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    
    Returns:
    - dict: {"valid": bool, "message": str}
    """
    # Check length
    if len(password) < 8:
        return {"valid": False, "message": "Password must be at least 8 characters long"}
    
    # Check for uppercase letter
    if not re.search(r'[A-Z]', password):
        return {"valid": False, "message": "Password must contain at least one uppercase letter"}
    
    # Check for lowercase letter
    if not re.search(r'[a-z]', password):
        return {"valid": False, "message": "Password must contain at least one lowercase letter"}
    
    # Check for number
    if not re.search(r'[0-9]', password):
        return {"valid": False, "message": "Password must contain at least one number"}
    
    # Check for special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return {"valid": False, "message": "Password must contain at least one special character"}
    
    return {"valid": True, "message": "Password is strong"}

def validate_email(email):
    """Validate email format."""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

def validate_username(username):
    """
    Validate username format.
    
    Requirements:
    - 3-64 characters
    - Only letters, numbers, and underscores
    """
    username_pattern = r'^[a-zA-Z0-9_]{3,64}$'
    return bool(re.match(username_pattern, username))

def role_required(required_roles):
    """
    Decorator to check if user has required role.
    
    Args:
        required_roles: String or list of strings representing required roles
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from flask_jwt_extended import verify_jwt_in_request
            
            # First verify the JWT is present and valid
            try:
                verify_jwt_in_request()
                
                # Now it's safe to get the claims
                claims = get_jwt()
                user_role = claims.get('role', 'user')
                
                # Convert required_roles to list if it's a string
                roles = [required_roles] if isinstance(required_roles, str) else required_roles
                
                # Check if user has required role
                if user_role not in roles:
                    logger.warning(f"Role access denied. User role: {user_role}, Required roles: {roles}")
                    return jsonify({"error": "Insufficient permissions"}), 403
                
                return fn(*args, **kwargs)
            except Exception as e:
                logger.error(f"JWT verification error: {str(e)}")
                return jsonify({"error": "Authentication required"}), 401
                
        return wrapper
    return decorator

def hash_password(password):
    """Hash a password using bcrypt with salt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password, hashed_password):
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def generate_secure_token(length=32):
    """Generate a cryptographically secure token."""
    return secrets.token_urlsafe(length)

def sanitize_input(input_str):
    """Sanitize user input to prevent XSS and injection attacks."""
    if not input_str:
        return None
    # Remove potentially dangerous characters
    return re.sub(r'[<>"\']', '', input_str)

def generate_token(user_id, role):
    """Generate JWT token using Flask-JWT-Extended.
    
    Note: This function must be called within a Flask application context.
    """
    from flask_jwt_extended import create_access_token
    from flask import has_app_context
    
    # Log what we're doing
    logger.debug(f"Generating JWT token for user: {user_id} with role: {role}")
    
    # Check if we're in an application context
    if not has_app_context():
        error_msg = "generate_token must be called within a Flask application context"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
    
    # Create additional claims
    additional_claims = {
        'role': role
    }
    
    try:
        # Create the access token using Flask-JWT-Extended
        access_token = create_access_token(
            identity=user_id,
            additional_claims=additional_claims
        )
        
        logger.debug("JWT token generated successfully")
        return access_token
    except Exception as e:
        logger.error(f"Error generating token: {str(e)}", exc_info=True)
        raise RuntimeError(f"Failed to generate token: {str(e)}") from e

def register_user(data):
    """
    Register a new user.
    
    Args:
        data: Dictionary containing user registration data
        
    Returns:
        Tuple of (response_data, status_code)
    """
    try:
        from app.models import RoleEnum
        from app.utils.security_utils import log_audit_event
        
        logger.info(f"Registration attempt with data: {data}")
        
        # Validate input
        if not data:
            logger.warning("No data provided in registration request")
            return {'error': 'No data provided'}, 400
            
        # Check for required fields
        required_fields = ['email', 'password', 'firstName', 'lastName']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            logger.warning(f"Missing required fields: {missing_fields}")
            return {'error': f'Missing required fields: {", ".join(missing_fields)}'}, 400
        
        # Validate email
        if not data['email']:
            logger.warning("Empty email provided")
            return {'error': 'Email cannot be empty'}, 400
        if not validate_email(data['email']):
            logger.warning(f"Invalid email format: {data['email']}")
            return {'error': 'Invalid email format'}, 400
        
        # Validate password
        if not data['password']:
            logger.warning("Empty password provided")
            return {'error': 'Password cannot be empty'}, 400
        password_validation = validate_password(data['password'])
        if not password_validation['valid']:
            logger.warning(f"Invalid password: {password_validation['message']}")
            return {'error': password_validation['message']}, 400
        
        try:
            # Get Firestore connection
            try:
                db = get_firestore()
                if db is None:
                    raise Exception("Firestore client is None - Firebase not initialized")
            except Exception as firebase_error:
                logger.error(f"Firebase connection error: {str(firebase_error)}", exc_info=True)
                return {'error': f'Database connection failed: {str(firebase_error)}'}, 500
            
            users_ref = db.collection('users')
            
            # Check email
            email_query = users_ref.where('email', '==', data['email']).get()
            if len(email_query) > 0:
                logger.warning(f"Email already registered: {data['email']}")
                return {'error': 'Email is already registered'}, 400
            
            # Create user document
            user_data = {
                'email': data['email'],
                'password': generate_password_hash(data['password']),  # Use Werkzeug's hash
                'firstName': data['firstName'],
                'lastName': data['lastName'],
                'role': RoleEnum.USER.value,
                'is_active': True,
                'mfa_enabled': False,
                'mfa_verified': False,
                'created_at': datetime.utcnow(),  # Use UTC datetime (Firestore accepts this)
                'login_attempts': 0,
                'security_questions': [],
                'session_tokens': []
            }
            
            # Add user to Firestore
            user_ref = users_ref.document()
            user_ref.set(user_data)
            logger.info(f"User created successfully with ID: {user_ref.id}")
            
            # Log successful registration
            try:
                log_audit_event(
                    user_id=user_ref.id,
                    action='register',
                    resource_type='user',
                    resource_id=user_ref.id,
                    details='User registered successfully',
                    status='success'
                )
            except Exception as log_error:
                # Don't fail the entire registration if just logging fails
                logger.error(f"Error logging registration event: {str(log_error)}")
            
            # Generate token
            try:
                token = generate_token(user_ref.id, user_data['role'])
            except Exception as token_error:
                logger.error(f"Error generating token: {str(token_error)}", exc_info=True)
                # Still return success but without token - user can login to get token
                return {
                    'message': 'User registered successfully, but token generation failed. Please login.',
                    'error': 'Token generation failed',
                    'user': {
                        'id': user_ref.id,
                        'email': user_data['email'],
                        'firstName': user_data['firstName'],
                        'lastName': user_data['lastName'],
                        'role': user_data['role'],
                        'mfa_enabled': user_data['mfa_enabled']
                    }
                }, 201
            
            return {
                'message': 'User registered successfully',
                'token': token,
                'user': {
                    'id': user_ref.id,
                    'email': user_data['email'],
                    'firstName': user_data['firstName'],
                    'lastName': user_data['lastName'],
                    'role': user_data['role'],
                    'mfa_enabled': user_data['mfa_enabled']
                }
            }, 201
            
        except Exception as e:
            logger.error(f"Firestore error during registration: {str(e)}", exc_info=True)
            error_msg = str(e)
            # Provide more specific error message
            if 'permission' in error_msg.lower() or 'denied' in error_msg.lower():
                return {'error': 'Firebase permission error. Please check your service account credentials.'}, 500
            elif 'not found' in error_msg.lower() or 'file' in error_msg.lower():
                return {'error': 'Firebase configuration error. Service account file not found.'}, 500
            else:
                return {'error': f'Database error during registration: {error_msg}'}, 500
            
    except Exception as e:
        logger.error(f"Unexpected error during registration: {str(e)}", exc_info=True)
        return {'error': f'An unexpected error occurred during registration: {str(e)}'}, 500

def login_user(data):
    """
    Login user and return JWT token or MFA session token if MFA is required.
    
    Args:
        data: Dictionary containing login credentials
        
    Returns:
        Tuple of (response_data, status_code)
    """
    try:
        from app.utils.security_utils import log_audit_event
        from app.utils.mfa_utils import create_mfa_session
        from config import MAX_LOGIN_ATTEMPTS, LOCKOUT_DURATION
        
        logger.info(f"Login attempt for email: {data.get('email')}")
        
        if not data:
            logger.warning("No data provided in login request")
            return {'error': 'No data provided'}, 400
            
        if not all(k in data for k in ('email', 'password')):
            logger.warning("Missing email or password in login request")
            return {'error': 'Missing email or password'}, 400
        
        try:
            db = get_firestore()
            logger.info("Firestore connection established")
            
            # Find user by email
            users_ref = db.collection('users')
            logger.debug(f"Looking up user with email: {data['email']}")
            user_query = users_ref.where('email', '==', data['email']).get()
            
            if len(user_query) == 0:
                logger.warning(f"User not found for email: {data['email']}")
                return {'error': 'Invalid email or password'}, 401
            
            user_doc = user_query[0]
            user_data = user_doc.to_dict()
            logger.debug(f"User found with ID: {user_doc.id}")
            
            # Check if account is locked
            if user_data.get('account_locked_until'):
                lock_time = user_data['account_locked_until']
                now = datetime.utcnow()
                
                try:
                    # Convert lock_time to naive datetime if it has timezone info
                    if hasattr(lock_time, 'tzinfo') and lock_time.tzinfo is not None:
                        # Convert to naive datetime by replacing tzinfo with None
                        lock_time = lock_time.replace(tzinfo=None)
                    
                    # Now both are naive datetimes, safe to compare
                    if now < lock_time:
                        logger.warning(f"Account locked for user: {data['email']}")
                        return {
                            'error': 'Account is locked. Please try again later.'
                        }, 403
                except Exception as lock_error:
                    logger.error(f"Error comparing lock time: {str(lock_error)}")
                    # Continue with login process if we can't determine if account is locked
            
            # Check password
            logger.debug(f"Verifying password for user: {data['email']}")
            logger.debug(f"Stored password hash type: {type(user_data['password'])}")
            logger.debug(f"Stored password hash value: {user_data['password'][:20]}...")
            
            try:
                password_valid = check_password_hash(user_data['password'], data['password'])
                logger.debug(f"Password verification result: {password_valid}")
            except Exception as pw_error:
                logger.error(f"Password verification error: {str(pw_error)}")
                return {'error': 'Password verification failed'}, 500
            
            if not password_valid:
                # Increment login attempts
                login_attempts = user_data.get('login_attempts', 0) + 1
                user_doc.reference.update({
                    'login_attempts': login_attempts,
                    'last_login_attempt': datetime.utcnow()
                })
                
                # Lock account if too many attempts
                if login_attempts >= MAX_LOGIN_ATTEMPTS:
                    user_doc.reference.update({
                        'account_locked_until': datetime.utcnow() + LOCKOUT_DURATION
                    })
                    logger.warning(f"Account locked due to too many failed attempts: {data['email']}")
                    return {
                        'error': 'Too many failed attempts. Account locked for 15 minutes.'
                    }, 403
                
                logger.warning(f"Invalid password for user: {data['email']}")
                return {'error': 'Invalid email or password'}, 401
            
            # Reset login attempts on successful login
            update_data = {
                'login_attempts': 0,
                'last_login': datetime.utcnow()
            }
            user_doc.reference.update(update_data)
            logger.debug(f"Login attempts reset for user: {data['email']}")
            
            # Check if MFA is required
            requires_mfa = user_data.get('mfa_enabled', False)
            
            if requires_mfa:
                # Generate MFA session token
                logger.debug("MFA is required, creating MFA session")
                try:
                    mfa_session_token = create_mfa_session(user_doc.id)
                    
                    logger.info(f"MFA required for user: {data['email']}")
                    return {
                        'requires_mfa': True,
                        'mfa_session_token': mfa_session_token,
                        'user_id': user_doc.id,
                        'email': user_data['email']
                    }, 200
                except Exception as mfa_error:
                    logger.error(f"Error creating MFA session: {str(mfa_error)}")
                    import traceback
                    logger.error(f"MFA error traceback: {traceback.format_exc()}")
                    return {'error': 'Error setting up MFA verification'}, 500
            
            # Generate token for non-MFA users
            logger.debug("Generating JWT token")
            token = generate_token(user_doc.id, user_data['role'])
            
            # Log successful login
            try:
                log_audit_event(
                    user_id=user_doc.id,
                    action='login',
                    resource_type='user',
                    resource_id=user_doc.id,
                    details='User logged in successfully',
                    status='success'
                )
            except Exception as audit_error:
                logger.error(f"Error logging audit event: {str(audit_error)}")
                # Continue even if audit logging fails
            
            logger.info(f"Successful login for user: {data['email']}")
            return {
                'token': token,
                'user': {
                    'id': user_doc.id,
                    'email': user_data['email'],
                    'firstName': user_data.get('firstName', ''),
                    'lastName': user_data.get('lastName', ''),
                    'role': user_data['role'],
                    'mfa_enabled': user_data.get('mfa_enabled', False)
                }
            }, 200
            
        except Exception as db_error:
            logger.error(f"Database error during login: {str(db_error)}")
            import traceback
            logger.error(f"Database error traceback: {traceback.format_exc()}")
            return {'error': 'Database error occurred during login'}, 500
            
    except Exception as e:
        import traceback
        logger.error(f"Error during login: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return {'error': 'An unexpected error occurred during login'}, 500

def get_user_info(user_id):
    """
    Get user information by user ID.
    
    Args:
        user_id: User ID
        
    Returns:
        Tuple of (user_data, status_code)
    """
    try:
        db = get_firestore()
        user_doc = db.collection('users').document(user_id).get()
        
        if not user_doc.exists:
            return {"error": "User not found"}, 404
        
        user_data = user_doc.to_dict()
        return {
            "id": user_doc.id,
            "email": user_data['email'],
            "firstName": user_data.get('firstName', ''),
            "lastName": user_data.get('lastName', ''),
            "role": user_data['role'],
            "mfa_enabled": user_data.get('mfa_enabled', False)
        }, 200
    
    except Exception as e:
        logger.error(f"Error getting user info: {e}")
        return {"error": "Failed to get user information"}, 500
