"""
MFA utilities for secure authentication.
"""
import io
import base64
import secrets
from datetime import datetime, timedelta
import pyotp
import qrcode
from flask import current_app
from app.firebase import get_firestore

def generate_totp_secret():
    """Generate a new TOTP secret."""
    return pyotp.random_base32()

def get_totp_uri(secret, email, issuer="AI Identity Verification"):
    """Generate a TOTP URI for QR code."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=issuer
    )

def verify_totp(secret, token):
    """Verify a TOTP token against a secret."""
    if not secret or not token:
        return False
    
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def generate_totp_qr_code(uri):
    """Generate a QR code for the TOTP URI."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert image to base64 for web display
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

def is_valid_backup_code(user_id, code):
    """Check if a backup code is valid for a user."""
    db = get_firestore()
    user_doc = db.collection('users').document(user_id).get()
    if not user_doc.exists:
        return False
        
    user_data = user_doc.to_dict()
    backup_codes = user_data.get('backup_codes', [])
    
    # Check if code exists and hasn't been used
    for backup_code in backup_codes:
        if backup_code['code'] == code and not backup_code.get('used', False):
            # Mark code as used
            backup_codes.remove(backup_code)
            backup_codes.append({'code': code, 'used': True})
            user_doc.reference.update({'backup_codes': backup_codes})
            return True
            
    return False

def create_mfa_session_document(user_id):
    """
    Create an MFA session document for database storage.
    
    Args:
        user_id: User ID to associate with the session
        
    Returns:
        Dictionary containing MFA session data
    """
    expires_delta = current_app.config.get('MFA_TOKEN_VALIDITY', 300)  # Default 5 minutes
    expires_at = datetime.utcnow() + timedelta(seconds=expires_delta)
    token = secrets.token_urlsafe(32)
    
    return {
        'user_id': user_id,
        'token': token,
        'expires_at': expires_at,
        'used': False,
        'created_at': datetime.utcnow()
    }

def create_mfa_session(user_id):
    """Create a temporary MFA session token."""
    db = get_firestore()
    
    # Clean up expired sessions using a simple query first
    now = datetime.utcnow()
    
    # Get all sessions for the user - simpler query without composite index requirements
    user_sessions = db.collection('mfa_sessions').where('user_id', '==', user_id).get()
    
    # Manually filter and delete expired sessions
    for session in user_sessions:
        session_data = session.to_dict()
        if session_data.get('expires_at'):
            # Convert Firestore timestamp to UTC datetime without timezone info
            expires_at = session_data['expires_at']
            # Check if it's a datetime object with tzinfo and convert if needed
            if hasattr(expires_at, 'tzinfo') and expires_at.tzinfo is not None:
                # Convert to naive datetime by replacing with the same time but without tzinfo
                naive_expires_at = datetime(
                    year=expires_at.year,
                    month=expires_at.month,
                    day=expires_at.day,
                    hour=expires_at.hour,
                    minute=expires_at.minute,
                    second=expires_at.second,
                    microsecond=expires_at.microsecond
                )
                if naive_expires_at < now:
                    session.reference.delete()
            else:
                # Already a naive datetime, compare directly
                if expires_at < now:
                    session.reference.delete()
    
    # Create new session using the document creator function
    session_data = create_mfa_session_document(user_id)
    
    # Store in database
    db.collection('mfa_sessions').add(session_data)
    return session_data['token']  # Return just the token, not the entire session data

def verify_mfa_session(token):
    """Verify an MFA session token."""
    if not token:
        return None
    
    db = get_firestore()
    now = datetime.utcnow()
    
    # Find session by token
    sessions = db.collection('mfa_sessions').where('token', '==', token).where('used', '==', False).get()
    
    if not sessions:
        return None
    
    # Since we can't use the composite index with expires_at, we'll filter manually
    valid_session = None
    for session_doc in sessions:
        session_data = session_doc.to_dict()
        expires_at = session_data.get('expires_at')
        
        # Skip if no expires_at
        if not expires_at:
            continue
            
        # Handle timezone-aware datetimes from Firestore
        if hasattr(expires_at, 'tzinfo') and expires_at.tzinfo is not None:
            # Convert to naive datetime by replacing with the same time values
            naive_expires_at = datetime(
                year=expires_at.year,
                month=expires_at.month,
                day=expires_at.day,
                hour=expires_at.hour,
                minute=expires_at.minute,
                second=expires_at.second,
                microsecond=expires_at.microsecond
            )
            # Compare the naive datetimes
            if naive_expires_at > now:
                valid_session = session_doc
                break
        else:
            # Already a naive datetime, compare directly
            if expires_at > now:
                valid_session = session_doc
                break
    
    if not valid_session:
        return None
    
    session_data = valid_session.to_dict()
    
    # Mark session as used
    valid_session.reference.update({'used': True})
    
    return session_data['user_id']