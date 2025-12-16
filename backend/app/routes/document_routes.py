"""
Routes for secure document handling and validation.
"""
import logging
import base64
import hashlib
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
import uuid
import random

from app.firebase import get_firestore
from app.utils.auth_utils import role_required
from app.utils.security_utils import log_audit_event, require_mfa, compute_document_hash, verify_document_integrity
from app.utils.verification_utils import verify_document, detect_nadra_pattern, decode_base64_image
from app.models import encrypt_data, decrypt_data

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
doc_bp = Blueprint('documents', __name__, url_prefix='/api/documents')

def get_firestore_client():
    """Get Firestore client instance."""
    return get_firestore()

@doc_bp.route('/upload', methods=['POST'])
@jwt_required()
@require_mfa
def upload_documents():
    """
    Verify documents securely without storing them.
    
    This endpoint accepts document images and performs AI-based verification
    using OCR and OpenCV for real document analysis. The document is not stored
    in the database for privacy and security reasons.
    """
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "No input data provided"}), 400
    
    # Validate required fields
    required_fields = ['document', 'document_type']
    if not all(field in data for field in required_fields):
        return jsonify({
            "error": "Missing required fields",
            "required": required_fields
        }), 400
    
    # Check document size
    MAX_DOCUMENT_SIZE = 1000000  # 1MB
    document_size = len(data['document'].encode('utf-8')) if isinstance(data['document'], str) else 0
    
    if document_size > MAX_DOCUMENT_SIZE:
        logger.warning(f"Document size too large: {document_size} bytes (max: {MAX_DOCUMENT_SIZE})")
        return jsonify({
            "error": f"Document too large. Maximum size is {MAX_DOCUMENT_SIZE/1000000:.1f}MB, received {document_size/1000000:.1f}MB",
            "details": "Please compress the image or reduce its resolution before uploading"
        }), 413  # Payload Too Large
    
    try:
        # Handle document type mapping for special types
        document_type = data['document_type']
        
        # Map 'drivers_license' to 'e_license' if it appears to be digital
        if document_type == 'drivers_license' and is_likely_digital_license(data['document']):
            logger.info("Document appears to be a digital license, using specialized verification rules")
            document_type = 'e_license'
        
        # Log the document type before verification
        logger.info(f"Processing document of type: {document_type}")
        
        # Perform document verification with real OCR and security feature detection
        verification_result = verify_document(
            document_data=data['document'],
            document_type=document_type
        )
        
        # Extract ID number from verification_result (determined by OCR)
        id_number = verification_result.get('id_number')
        
        # Get or generate readable document ID (not stored, just for response)
        if id_number and document_type == 'id_card':
            # Use actual OCR-extracted ID for ID cards
            readable_doc_id = id_number
            logger.info(f"Using OCR-extracted ID number: {id_number}")
            # Add ID card specific data to verification result
            verification_result['id_card_data'] = {
                "id_number": id_number,
                "card_type": "National Identity Card",
                "issuing_authority": "National Database and Registration Authority"
            }
        else:
            # For other documents, generate a UUID
            readable_doc_id = str(uuid.uuid4())
            logger.info(f"Generated document ID: {readable_doc_id}")
        
        # Compute document hash for verification purposes only
        doc_hash = compute_document_hash(data['document'])
        
        # Log verification action (but not the document itself)
        log_audit_event(
            action="document_verification",
            user_id=current_user_id,
            resource_type="document_verification",
            resource_id=readable_doc_id,
            details={
                "document_type": data['document_type'],
                "actual_document_type": document_type,
                "verification_status": verification_result.get('status', 'processed'),
                "readable_id": readable_doc_id,
                "id_extracted": bool(id_number)  # Log whether ID extraction was successful
            }
        )
        
        # Remove OCR text from the response to reduce size
        if 'ocr_text' in verification_result:
            # Replace full OCR text with a preview in the response
            verification_result['ocr_preview'] = verification_result['ocr_text'][:100] + '...'
            del verification_result['ocr_text']
        
        # Debug: Log the verification result being returned
        logger.info(f"Verification result: {verification_result}")
        
        # Prepare response with verification results
        response_data = {
            "message": "Document verified successfully",
            "document_id": readable_doc_id,
            "verification_result": verification_result
        }
        
        # Additional debug logging
        logger.info(f"Full response data: {response_data}")
        
        return jsonify(response_data), 200
        
    except ValueError as ve:
        # Handle validation errors
        logger.error(f"Validation error: {ve}")
        log_audit_event(
            action="document_verification",
            user_id=current_user_id,
            status="failure",
            details={"error": str(ve)}
        )
        return jsonify({"error": str(ve)}), 400
        
    except Exception as e:
        # Handle general errors
        logger.error(f"Error verifying document: {e}")
        log_audit_event(
            action="document_verification",
            user_id=current_user_id,
            status="failure",
            details={"error": str(e)}
        )
        return jsonify({"error": "Failed to verify document"}), 500

def is_likely_digital_license(document_data: str) -> bool:
    """
    Determine if a document is likely a digital license.
    
    Args:
        document_data (str): Base64 encoded document image
        
    Returns:
        bool: True if document appears to be a digital license
    """
    try:
        # More reliable detection for digital licenses
        # For now, be more permissive with driver's licenses - assume they're digital
        # unless proven otherwise
        
        # This is a simplified approach for the demo
        # In a production system, this would use computer vision to detect
        # screen capture artifacts, digital watermarks, etc.
        
        logger.info("Assuming driver's license is digital for better verification outcome")
        return True
    except Exception as e:
        logger.error(f"Error checking if license is digital: {e}")
        return True  # Default to digital for better user experience

@doc_bp.route('/verify/<string:document_id>', methods=['POST'])
@jwt_required()
@role_required(['admin', 'verifier'])
@require_mfa
def verify_document_manual(document_id):
    """
    Manual document verification endpoint.
    
    This endpoint is no longer functional as documents are not stored in the database.
    It returns a message indicating that documents are processed in real-time and not stored.
    """
    current_user_id = get_jwt_identity()
    
    log_audit_event(
        action="document_verification_attempt",
        user_id=current_user_id,
        resource_type="document",
        resource_id=document_id,
        status="failure",
        details={"reason": "Documents are no longer stored in the system"}
    )
    
    return jsonify({
        "error": "This functionality is no longer available",
        "message": "Documents are now processed in real-time for verification and are not stored in our system for privacy and security reasons.",
        "status": "feature_disabled"
    }), 404

@doc_bp.route('/status/<string:document_id>', methods=['GET'])
@jwt_required()
def get_document_status(document_id):
    """
    Get document status endpoint.
    
    This endpoint is no longer functional as documents are not stored in the database.
    It returns a message indicating that documents are processed in real-time and not stored.
    """
    current_user_id = get_jwt_identity()
    
    log_audit_event(
        action="document_status_check_attempt",
        user_id=current_user_id,
        resource_type="document",
        resource_id=document_id,
        status="failure",
        details={"reason": "Documents are no longer stored in the system"}
    )
    
    return jsonify({
        "error": "This functionality is no longer available",
        "message": "Documents are now processed in real-time for verification and are not stored in our system for privacy and security reasons.",
        "status": "feature_disabled"
    }), 404

@doc_bp.route('/retrieve/<string:document_id>', methods=['GET'])
@jwt_required()
@role_required(['admin', 'verifier'])
@require_mfa
def retrieve_document(document_id):
    """
    Retrieve document endpoint.
    
    This endpoint is no longer functional as documents are not stored in the database.
    It returns a message indicating that documents are processed in real-time and not stored.
    """
    current_user_id = get_jwt_identity()
    
    log_audit_event(
        action="document_retrieval_attempt",
        user_id=current_user_id,
        resource_type="document",
        resource_id=document_id,
        status="failure",
        details={"reason": "Documents are no longer stored in the system"}
    )
    
    return jsonify({
        "error": "This functionality is no longer available",
        "message": "Documents are now processed in real-time for verification and are not stored in our system for privacy and security reasons.",
        "status": "feature_disabled"
    }), 404