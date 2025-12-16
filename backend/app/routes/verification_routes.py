import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.firebase import get_firestore
from app.utils.auth_utils import role_required
from app.utils.verification_utils import simulate_ai_verification
from app.models import create_verification_profile_document

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
verification_bp = Blueprint('verification', __name__)

def get_firestore_client():
    """Get Firestore client instance."""
    return get_firestore()

@verification_bp.route('/submit', methods=['POST'])
@jwt_required()
def submit_verification():
    """Submit verification profile for the current user."""
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "No input data provided"}), 400
    
    # Validate required fields
    required_fields = ['full_name', 'id_type', 'id_number', 'date_of_birth']
    if not all(field in data for field in required_fields):
        return jsonify({"error": f"Missing required fields. Required: {', '.join(required_fields)}"}), 400
    
    try:
        db = get_firestore_client()
        
        # Check if user already has a verification profile
        verifications_ref = db.collection('verification_profiles')
        existing_profile = verifications_ref.where('user_id', '==', current_user_id).limit(1).get()
        
        if existing_profile:
            profile_doc = existing_profile[0]
            profile_data = profile_doc.to_dict()
            
            # If already verified or pending, don't allow resubmission
            if profile_data.get('verification_status') in ['verified', 'pending']:
                return jsonify({
                    "error": f"You already have a {profile_data['verification_status']} verification profile."
                }), 409
            
            # Update existing profile if rejected
            updates = {
                'verification_status': 'pending',
                'verification_notes': None,
                'verified_at': None
            }
            
            # Add other fields from data
            for field in data:
                if field in profile_data:
                    updates[field] = data[field]
            
            profile_doc.reference.update(updates)
            
            return jsonify({
                "message": "Verification profile resubmitted successfully",
                "profile": profile_doc.to_dict()
            }), 200
        
        # Parse date of birth
        try:
            date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({"error": "Invalid date format for date_of_birth. Use YYYY-MM-DD."}), 400
        
        # Create new verification profile
        profile_data = {
            'user_id': current_user_id,
            'full_name': data['full_name'],
            'id_type': data['id_type'],
            'id_number': data['id_number'],
            'date_of_birth': date_of_birth,
            'verification_status': 'pending'
        }
        
        profile_doc = create_verification_profile_document(profile_data)
        verifications_ref.document().set(profile_doc)
        
        return jsonify({
            "message": "Verification profile submitted successfully",
            "profile": profile_doc
        }), 201
    
    except Exception as e:
        logger.error(f"Error submitting verification profile: {e}")
        return jsonify({"error": "Failed to submit verification profile"}), 500

@verification_bp.route('/status', methods=['GET'])
@jwt_required()
def get_verification_status():
    """Get verification status for the current user."""
    current_user_id = get_jwt_identity()
    
    try:
        db = get_firestore_client()
        verifications_ref = db.collection('verification_profiles')
        profile = verifications_ref.where('user_id', '==', current_user_id).limit(1).get()
        
        if not profile:
            return jsonify({
                "verification_status": "not_submitted",
                "message": "No verification profile found"
            }), 200
        
        profile_data = profile[0].to_dict()
        return jsonify({
            "verification_status": profile_data.get('verification_status'),
            "profile": profile_data
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting verification status: {e}")
        return jsonify({"error": "Failed to retrieve verification status"}), 500

@verification_bp.route('/verify/<string:profile_id>', methods=['POST'])
@jwt_required()
@role_required(['admin', 'verifier'])
def verify_profile(profile_id):
    """Verify a user's profile (admin and verifier only)."""
    data = request.get_json() or {}
    
    # Get decision from request
    decision = data.get('decision')
    if decision not in ['approve', 'reject', 'ai_verify']:
        return jsonify({"error": "Invalid decision. Must be 'approve', 'reject', or 'ai_verify'."}), 400
    
    try:
        db = get_firestore_client()
        profile_ref = db.collection('verification_profiles').document(profile_id)
        profile_doc = profile_ref.get()
        
        if not profile_doc.exists:
            return jsonify({"error": "Verification profile not found"}), 404
        
        profile_data = profile_doc.to_dict()
        if profile_data.get('verification_status') != 'pending':
            return jsonify({"error": f"Profile is already {profile_data['verification_status']}"}), 400
        
        updates = {}
        
        if decision == 'ai_verify':
            # Simulate AI verification
            ai_result = simulate_ai_verification(profile_data)
            updates['verification_status'] = ai_result['status']
            updates['verification_notes'] = ai_result['notes']
        else:
            # Manual verification
            updates['verification_status'] = 'verified' if decision == 'approve' else 'rejected'
            updates['verification_notes'] = data.get('notes')
        
        # Update verification timestamp if approved
        if updates['verification_status'] == 'verified':
            updates['verified_at'] = datetime.utcnow()
        
        profile_ref.update(updates)
        
        return jsonify({
            "message": f"Profile {updates['verification_status']}",
            "profile": profile_doc.to_dict()
        }), 200
    
    except Exception as e:
        logger.error(f"Error verifying profile: {e}")
        return jsonify({"error": "Failed to verify profile"}), 500

@verification_bp.route('/profiles/<string:profile_id>', methods=['GET'])
@jwt_required()
def get_verification_profile(profile_id):
    """Get a specific verification profile."""
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    role = claims.get('role', 'user')
    
    try:
        db = get_firestore_client()
        profile_ref = db.collection('verification_profiles').document(profile_id)
        profile_doc = profile_ref.get()
        
        if not profile_doc.exists:
            return jsonify({"error": "Verification profile not found"}), 404
        
        profile_data = profile_doc.to_dict()
        
        # Only allow users to view their own profile unless they're admin or verifier
        if current_user_id != profile_data['user_id'] and role not in ['admin', 'verifier']:
            return jsonify({"error": "Unauthorized access"}), 403
        
        # Get user data
        user_ref = db.collection('users').document(profile_data['user_id'])
        user_doc = user_ref.get()
        
        response_data = profile_data
        response_data['user'] = user_doc.to_dict() if user_doc.exists else None
        
        return jsonify(response_data), 200
    
    except Exception as e:
        logger.error(f"Error getting verification profile: {e}")
        return jsonify({"error": "Failed to retrieve verification profile"}), 500
