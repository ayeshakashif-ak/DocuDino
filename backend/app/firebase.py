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
    try:
        for file in os.listdir(backend_dir):
            if file.endswith('.json') and 'firebase' in file.lower() and 'adminsdk' in file.lower():
                full_path = os.path.join(backend_dir, file)
                if os.path.exists(full_path):
                    return full_path
    except OSError:
        # Directory might not exist or not accessible
        pass
    
    return None

FIREBASE_CREDENTIALS_PATH = _find_firebase_credentials()

# CRITICAL: Firebase is REQUIRED - fail fast if not configured
if not FIREBASE_CREDENTIALS_PATH:
    print("=" * 80)
    print("[ERROR] Firebase credentials file not found!")
    print("=" * 80)
    print("\nFirebase is REQUIRED for this application to work.")
    print("\nTo set up Firebase:")
    print("1. Go to: https://console.firebase.google.com/")
    print("2. Select your project (or create a new one)")
    print("3. Go to: Project Settings → Service Accounts")
    print("4. Click 'Generate New Private Key'")
    print("5. Download the JSON file")
    print("6. Place it in the backend/ directory")
    print("\nThe file should be named: *-firebase-adminsdk-*.json")
    print("\nOr set the FIREBASE_CREDENTIALS_PATH environment variable")
    print("=" * 80)
    raise FileNotFoundError(
        "Firebase credentials file not found. "
        "Please download your Firebase service account JSON file and place it in the backend/ directory. "
        "See instructions above."
    )

if not os.path.exists(FIREBASE_CREDENTIALS_PATH):
    print(f"[ERROR] Firebase credentials file not found at: {FIREBASE_CREDENTIALS_PATH}")
    raise FileNotFoundError(
        f"Firebase credentials file not found at: {FIREBASE_CREDENTIALS_PATH}. "
        "Please check the file path and try again."
    )

# Initialize Firebase Admin SDK - REQUIRED, will fail if there's an error
try:
    cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print(f"[SUCCESS] Firebase initialized successfully with: {FIREBASE_CREDENTIALS_PATH}")
    print(f"[SUCCESS] Connected to Firebase project: {cred.project_id}")
except Exception as e:
    print("=" * 80)
    print(f"[CRITICAL ERROR] Failed to initialize Firebase!")
    print("=" * 80)
    print(f"Error: {e}")
    print("\nPlease check:")
    print("1. The JSON file is valid and not corrupted")
    print("2. The file has proper read permissions")
    print("3. Your Firebase project is active and Firestore API is enabled")
    print("4. The service account has proper permissions")
    print("=" * 80)
    raise

def get_firestore():
    """Get Firestore client instance."""
    if db is None:
        raise RuntimeError("Firebase is not initialized. This should not happen.")
    return db 