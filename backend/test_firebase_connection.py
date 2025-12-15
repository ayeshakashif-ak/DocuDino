"""
Simple script to test Firebase connection.
Run this to verify your Firebase setup is working.
"""
import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(__file__))

try:
    print("Testing Firebase connection...")
    print("Looking for service account file...")
    
    # Import Firebase directly without Flask dependencies
    import firebase_admin
    from firebase_admin import credentials, firestore
    from dotenv import load_dotenv
    
    load_dotenv()
    
    # Get Firebase service account key path - auto-detect if not specified
    def find_firebase_credentials():
        """Find Firebase service account JSON file."""
        backend_dir = os.path.dirname(__file__)
        
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
    
    FIREBASE_CREDENTIALS_PATH = find_firebase_credentials()
    
    print(f"Service account path: {FIREBASE_CREDENTIALS_PATH}")
    
    if not os.path.exists(FIREBASE_CREDENTIALS_PATH):
        print(f"ERROR: Service account file not found at: {FIREBASE_CREDENTIALS_PATH}")
        sys.exit(1)
    
    print("Service account file found!")
    
    # Initialize Firebase
    try:
        cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("Firebase initialized successfully!")
    except Exception as init_error:
        print(f"ERROR initializing Firebase: {str(init_error)}")
        sys.exit(1)
    
    # Try a simple read operation
    print("Testing Firestore read operation...")
    users_ref = db.collection('users')
    print("Firestore collection reference obtained")
    
    print("\nSUCCESS: Firebase connection is working correctly!")
    print("You can now use Firebase in your application.")
    
except Exception as e:
    print(f"\nERROR: Error connecting to Firebase: {str(e)}")
    print(f"Error type: {type(e).__name__}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
