"""
Document schemas for Firestore collections.
"""
import os
import secrets
import pyotp
from datetime import datetime, timedelta
from enum import Enum
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

class RoleEnum(str, Enum):
    ADMIN = 'admin'
    USER = 'user'
    VERIFIER = 'verifier'

# Create encryption key
def get_encryption_key():
    """Get or create encryption key for sensitive data."""
    key = os.environ.get('ENCRYPTION_KEY')
    if not key:
        # In production, this should be set as an environment variable
        # For development, we generate a key and store it
        key = Fernet.generate_key().decode()
        # In a real app, save this key securely
    return key

# Initialize encryption
encryption_key = get_encryption_key()
cipher_suite = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)

def encrypt_data(data):
    """Encrypt sensitive data."""
    if not data:
        return None
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """Decrypt sensitive data."""
    if not encrypted_data:
        return None
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except Exception:
        return None

# Document schemas
USER_SCHEMA = {
    'email': str,
    'password': str,  # Hashed password
    'firstName': str,
    'lastName': str,
    'role': str,  # RoleEnum
    'is_active': bool,
    'mfa_enabled': bool,
    'mfa_verified': bool,
    'mfa_secret': str,  # Encrypted
    'mfa_backup_codes': list,  # List of dicts with 'code' and 'used' fields
    'created_at': datetime,
    'last_login': datetime,
    'login_attempts': int,
    'last_login_attempt': datetime,
    'account_locked_until': datetime,
    'password_changed_at': datetime,
    'security_questions': list,
    'session_tokens': list
}

MFA_SESSION_SCHEMA = {
    'user_id': str,
    'token': str,
    'created_at': datetime,
    'expires_at': datetime,
    'used': bool
}

AUDIT_LOG_SCHEMA = {
    'user_id': str,
    'action': str,
    'resource_type': str,
    'resource_id': str,
    'details': str,
    'ip_address': str,
    'user_agent': str,
    'status': str,
    'created_at': datetime
}

BLACKLISTED_TOKEN_SCHEMA = {
    'token': str,
    'blacklisted_on': datetime
}

# Helper functions for document operations
def create_user_document(data):
    """Create a new user document with proper encryption."""
    document = {}
    for field, field_type in USER_SCHEMA.items():
        if field in data:
            if field in ['mfa_secret']:
                document[field] = encrypt_data(data[field])
            elif field in ['password']:
                document[field] = generate_password_hash(data[field])
            else:
                document[field] = data[field]
    
    # Set default values for required fields
    document.setdefault('role', RoleEnum.USER.value)
    document.setdefault('is_active', True)
    document.setdefault('mfa_enabled', False)
    document.setdefault('mfa_verified', False)
    document.setdefault('created_at', datetime.utcnow())
    document.setdefault('login_attempts', 0)
    document.setdefault('security_questions', [])
    document.setdefault('session_tokens', [])
    
    return document

def create_mfa_session_document(user_id):
    """Create a new MFA session document."""
    expires_delta = timedelta(minutes=5)  # 5 minutes validity
    return {
        'user_id': user_id,
        'token': secrets.token_urlsafe(32),
        'created_at': datetime.utcnow(),
        'expires_at': datetime.utcnow() + expires_delta,
        'used': False
    }

def create_audit_log_document(data):
    """Create a new audit log document."""
    document = {}
    for field, field_type in AUDIT_LOG_SCHEMA.items():
        if field in data:
            document[field] = data[field]
    
    # Set default values
    document.setdefault('status', 'success')
    document.setdefault('created_at', datetime.utcnow())
    
    return document

def create_blacklisted_token_document(token):
    """Create a new blacklisted token document."""
    return {
        'token': token,
        'blacklisted_on': datetime.utcnow()
    }

# SQLAlchemy Models
from app import db

class User(db.Model):
    """User model for SQLAlchemy."""
    __tablename__ = 'users'
    
    id = db.Column(db.String(255), primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(255), unique=True, nullable=True, index=True)
    password = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(255), nullable=True)
    last_name = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(50), nullable=False, default=RoleEnum.USER.value)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    mfa_verified = db.Column(db.Boolean, default=False, nullable=False)
    mfa_secret = db.Column(db.Text, nullable=True)
    mfa_backup_codes = db.Column(db.JSON, nullable=True)  # List of dicts with 'code' and 'used' fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    login_attempts = db.Column(db.Integer, default=0, nullable=False)
    last_login_attempt = db.Column(db.DateTime, nullable=True)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, nullable=True)
    security_questions = db.Column(db.JSON, nullable=True)
    session_tokens = db.Column(db.JSON, nullable=True)
    
    def check_password(self, password):
        """Check if the provided password matches the user's password."""
        return check_password_hash(self.password, password)
    
    def update_last_login(self):
        """Update the last login timestamp."""
        self.last_login = datetime.utcnow()
    
    def requires_mfa(self):
        """Check if MFA is required for this user."""
        from config import get_config
        config = get_config()
        required_roles = config.MFA_REQUIRED_FOR_ROLES if hasattr(config, 'MFA_REQUIRED_FOR_ROLES') else []
        return self.mfa_enabled or self.role in required_roles
    
    def to_dict(self):
        """Convert user model to dictionary."""
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.role,
            'is_active': self.is_active,
            'mfa_enabled': self.mfa_enabled,
            'mfa_verified': self.mfa_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class BlacklistedToken(db.Model):
    """Blacklisted JWT token model."""
    __tablename__ = 'blacklisted_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    blacklisted_on = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class MFASession(db.Model):
    """MFA session model for temporary MFA tokens."""
    __tablename__ = 'mfa_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(255), db.ForeignKey('users.id'), nullable=False, index=True)
    token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    
    def is_expired(self):
        """Check if the session has expired."""
        return datetime.utcnow() > self.expires_at
    
    def mark_used(self):
        """Mark the session as used."""
        self.used = True
        db.session.commit()
