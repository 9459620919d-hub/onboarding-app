import os
import re
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session

load_dotenv()

app = Flask(__name__)

# Secret key used by Flask to cryptographically sign session cookies
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback_dev_secret_key_change_in_prod")

# Configure persistent session duration (30 days)
app.permanent_session_lifetime = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Mock database (in production, use PostgreSQL, SQLite, or SQLAlchemy)
users_db = []


def send_welcome_email(recipient_email, recipient_name):
    """Sends a welcome email via Gmail SMTP using smtplib."""
    gmail_user = os.getenv("GMAIL_USER")
    gmail_pass = os.getenv("GMAIL_APP_PASS")

    if not gmail_user or not gmail_pass:
        print("Warning: Gmail credentials not configured in .env. Skipping email dispatch.")
        return

    msg = EmailMessage()
    msg["Subject"] = "Welcome to Our Platform!"
    msg["From"] = f"Welcome Team <{gmail_user}>"
    msg["To"] = recipient_email

    msg.set_content(f"Hi {recipient_name},\n\nThank you for signing up!")
    msg.add_alternative(
        f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
                <h2 style="color: #2563eb;">Welcome aboard, {recipient_name}!</h2>
                <p>Your account has been created and your session is active.</p>
                <p>You can now access your dashboard anytime.</p>
            </body>
        </html>
        """,
        subtype="html",
    )

    # Connect to Gmail SMTP on Port 465 (SSL)
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(gmail_user, gmail_pass)
        smtp.send_message(msg)


@app.route("/")
def index():
    """Serves the frontend page."""
    return render_template("index.html")


@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    # 1. Server-side validation
    if len(name) < 2:
        return jsonify({"error": "Name must be at least 2 characters."}), 400

    email_regex = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    if not re.match(email_regex, email):
        return jsonify({"error": "Invalid email address format."}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400
    if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password):
        return jsonify({"error": "Password must include both uppercase and lowercase letters."}), 400
    if not re.search(r"[0-9]", password):
        return jsonify({"error": "Password must include at least one digit."}), 400
    if not re.search(r"[^a-zA-Z0-9]", password):
        return jsonify({"error": "Password must include at least one special character."}), 400

    # 2. Check duplicate email
    if any(user["email"] == email for user in users_db):
        return jsonify({"error": "Email is already registered."}), 409

    # 3. Save user record
    new_user = {"id": len(users_db) + 1, "name": name, "email": email}
    users_db.append(new_user)

    # 4. Dispatch welcome email via Gmail SMTP
    try:
        send_welcome_email(email, name)
    except Exception as e:
        print(f"SMTP Error: {e}")

    # 5. Set persistent session
    session.permanent = True
    session["user"] = {"name": new_user["name"], "email": new_user["email"]}

    return jsonify({"message": "User registered successfully", "user": session["user"]})


@app.route("/api/me", methods=["GET"])
def check_session():
    """Checks whether an active session cookie exists."""
    user = session.get("user")
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"user": user})


@app.route("/api/signout", methods=["POST"])
def signout():
    """Clears the session cookie."""
    session.clear()
    return jsonify({"message": "Signed out successfully"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
