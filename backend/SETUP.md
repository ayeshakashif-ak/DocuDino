# Backend Setup Guide

This guide will help you set up the DocuDino backend after cloning the repository.

## Prerequisites

- Python 3.11 or higher
- pip (Python package manager)
- Firebase account and project

## Step 1: Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

## Step 2: Set Up Firebase

### 2.1 Get Firebase Service Account Key

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Select your project (or create a new one)
3. Click the gear icon ⚙️ → **Project Settings**
4. Go to the **Service Accounts** tab
5. Click **Generate New Private Key**
6. Download the JSON file (it will be named something like `your-project-firebase-adminsdk-xxxxx.json`)

### 2.2 Place the Firebase Credentials File

Place the downloaded JSON file in the `backend/` directory.

The app will automatically detect any file with:
- `.json` extension
- Contains "firebase" and "adminsdk" in the filename

**Example filenames that will work:**
- `docudino-firebase-adminsdk-xxxxx.json`
- `my-project-firebase-adminsdk-abc123.json`
- Any file matching `*-firebase-adminsdk-*.json`

### 2.3 Alternative: Use Environment Variable

You can also set the path via environment variable:

```bash
# Windows (PowerShell)
$env:FIREBASE_CREDENTIALS_PATH="C:\path\to\your\firebase-key.json"

# Linux/Mac
export FIREBASE_CREDENTIALS_PATH="/path/to/your/firebase-key.json"
```

Or create a `.env` file in the `backend/` directory:

```env
FIREBASE_CREDENTIALS_PATH=./path/to/your/firebase-key.json
```

## Step 3: Set Up Frontend Firebase Config

1. Copy the example file:
   ```bash
   cd ../frontend/src/config
   cp firebase.ts.example firebase.ts
   ```

2. Get your Firebase Web App config:
   - Go to [Firebase Console](https://console.firebase.google.com/)
   - Select your project
   - Click the gear icon ⚙️ → **Project Settings**
   - Scroll down to **Your apps** section
   - Click the web icon `</>` to add a web app (if not already added)
   - Copy the config values

3. Edit `frontend/src/config/firebase.ts` and replace the placeholder values:
   ```typescript
   const firebaseConfig = {
     apiKey: "YOUR_ACTUAL_API_KEY",
     authDomain: "your-project.firebaseapp.com",
     projectId: "your-project-id",
     // ... etc
   };
   ```

## Step 4: Configure Environment Variables (Optional)

Create a `.env` file in the `backend/` directory for custom configuration:

```env
# Flask Configuration
FLASK_ENV=development
SESSION_SECRET=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here

# Database (optional - defaults to SQLite)
DATABASE_URL=sqlite:///instance/app.db

# Firebase (optional - auto-detected if not set)
FIREBASE_CREDENTIALS_PATH=./your-firebase-key.json
```

## Step 5: Run the Application

```bash
# From the backend directory
python app.py
# or
python main.py
```

The server will start on `http://0.0.0.0:5002`

## Troubleshooting

### Firebase Not Initializing

**Error:** `Firebase credentials file not found`

**Solution:**
1. Make sure the JSON file is in the `backend/` directory
2. Check the filename contains "firebase" and "adminsdk"
3. Verify the file is not corrupted
4. Try setting `FIREBASE_CREDENTIALS_PATH` environment variable explicitly

**Error:** `Error initializing Firebase: [some error]`

**Solution:**
1. Verify the JSON file is valid (open it and check it's proper JSON)
2. Check that your Firebase project is active
3. Ensure Firestore API is enabled in your Firebase project
4. Make sure the service account has proper permissions

### Database Issues

The app uses SQLite by default for development. The database file will be created automatically at `backend/instance/app.db`.

For production, set the `DATABASE_URL` environment variable to use PostgreSQL or another database.

## Verification

After setup, you should see:
```
✅ Firebase initialized successfully with: backend/your-firebase-key.json
```

If you see warnings, check the setup steps above.

## Next Steps

- Start the frontend: `cd ../frontend && npm install && npm run dev`
- Test registration: Try creating a new account
- Check Firebase Console: Verify data is being stored in Firestore

