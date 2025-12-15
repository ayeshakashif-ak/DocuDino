import firebase_admin
from firebase_admin import credentials, firestore
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get Firebase service account key path from environment variable
# Auto-detect Firebase service account file if not specified
def _find_firebase_credentials():
    """Find Firebase service account JSON file in the backend directory."""
    backend_dir = os.path.dirname(os.path.dirname(__file__))
    
    # Check environment variable first
    env_path = os.getenv('FIREBASE_CREDENTIALS_PATH')
    if env_path and os.path.exists(env_path):
        return env_path
    
    # Look for any firebase service account JSON file
    for file in os.listdir(backend_dir):
        if file.endswith('.json') and 'firebase' in file.lower() and 'adminsdk' in file.lower():
            full_path = os.path.join(backend_dir, file)
            if os.path.exists(full_path):
                return full_path
    
    # Default fallback
    return os.path.join(backend_dir, 'docudino-native-firebase-adminsdk-fbsvc-aaf6e09623.json')

FIREBASE_CREDENTIALS_PATH = _find_firebase_credentials()

# Initialize Firebase Admin SDK
try:
    cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print(f"Error initializing Firebase: {e}")
    raise

def get_firestore():
    """Get Firestore client instance."""
    return db 