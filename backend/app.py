import os
from app import create_app

app = create_app()


@app.route('/')
def index():
    return "Backend is running!"


@app.route('/health')
def health():
    return "OK", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5002)))
