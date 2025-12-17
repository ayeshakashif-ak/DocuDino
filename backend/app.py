from app import app
import os

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_ENV", "development") == "development"
    # Binding to 0.0.0.0 allows connections from any IP
    app.run(host="0.0.0.0", port=5002, debug=False)
