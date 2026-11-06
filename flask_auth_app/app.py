import os
import random
import re
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

# Load variables from .env
load_dotenv()

app = Flask(__name__)

# Flask signed cookie secret key
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback_dev_secret_key_change_in_production")

# Persistent 30-day session setup
app.permanent_session_lifetime = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# In-memory storage (replace with persistent database for production)
users_db = []
pending_verifications = {}

# Common disposable / fake email domains to reject
DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "guerrillamail.com", "10minutemail.com",
    "sharklasers.com", "yopmail.com", "trashmail.com", "temp-mail.org",
    "throwawaymail.com", "getairmail.com", "dispostable.com", "fakemailgenerator.com",
    "burnermail.io", "nada.ltd", "mohmal.com", "generator.email",
    "crazymailing.com", "inboxkitten.com", "mytemp.email"
}


def is_valid_original_email(email: str) -> tuple[bool, str]:
    """Validates email format and blocks disposable/temporary email providers."""
    # Strict regex check for standard format
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(email_regex, email):
        return False, "Please provide a valid email address (e.g., name@gmail.com)."

    parts = email.split("@")
    if len(parts) != 2:
        return False, "Invalid email structure."

    domain = parts[1].lower().strip()

    # Block disposable email services
    if domain in DISPOSABLE_DOMAINS:
        return False, "Temporary/disposable emails are not allowed. Please enter your real email address."

    # Minimum domain structure check (must have at least one dot and 2+ char TLD)
    domain_parts = domain.split(".")
    if len(domain_parts) < 2 or len(domain_parts[-1]) < 2:
        return False, "Please provide an email with a valid domain (e.g., @gmail.com, @outlook.com)."

    return True, ""


def send_otp_email(recipient_email, recipient_name, otp_code):
    gmail_user = os.getenv("GMAIL_USER")
    gmail_pass = os.getenv("GMAIL_APP_PASS")

    if not gmail_user or not gmail_pass:
        raise ValueError("GMAIL_USER or GMAIL_APP_PASS is missing in your .env file.")

    # Remove any stray spaces if accidentally pasted into .env
    gmail_user = gmail_user.strip()
    gmail_pass = gmail_pass.strip().replace(" ", "")

    msg = EmailMessage()
    msg["Subject"] = f"Your Verification Code: {otp_code}"
    msg["From"] = f"Security Team <{gmail_user}>"
    msg["To"] = recipient_email

    msg.set_content(
        f"Hi {recipient_name},\n\n"
        f"Your 6-digit verification code is: {otp_code}\n"
        f"This code will expire in 10 minutes.\n\n"
        "If you did not request this code, please ignore this email."
    )
    msg.add_alternative(
        f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; max-width: 500px; margin: 0 auto; padding: 20px;">
                <div style="background: #0f172a; color: white; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
                    <h2 style="margin: 0; color: #38bdf8;">Email Verification</h2>
                </div>
                <div style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 24px; border-radius: 0 0 8px 8px;">
                    <p>Hi <strong>{recipient_name}</strong>,</p>
                    <p>Use the following 6-digit verification code to confirm that this is your genuine email address:</p>
                    <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #0284c7; text-align: center; padding: 18px; background: #e0f2fe; border-radius: 8px; margin: 20px 0;">
                        {otp_code}
                    </div>
                    <p style="color: #64748b; font-size: 13px; text-align: center;">This verification code will expire in 10 minutes.</p>
                </div>
            </body>
        </html>
        """,
        subtype="html",
    )

    # Use direct SSL on Port 465 with a 15-second timeout
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as smtp:
        smtp.login(gmail_user, gmail_pass)
        smtp.send_message(msg)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    # 1. Name validation
    if len(name) < 2:
        return jsonify({"error": "Name must be at least 2 characters long."}), 400
    if not re.match(r"^[A-Za-z\s]+$", name):
        return jsonify({"error": "Name must contain only letters and spaces (no numbers or symbols)."}), 400

    # 2. Strict real email validation
    is_valid_email, email_error = is_valid_original_email(email)
    if not is_valid_email:
        return jsonify({"error": email_error}), 400

    # 3. Strong password validation
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400
    if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password):
        return jsonify({"error": "Password must include both uppercase and lowercase letters."}), 400
    if not re.search(r"[0-9]", password):
        return jsonify({"error": "Password must include at least one number."}), 400
    if not re.search(r"[^a-zA-Z0-9]", password):
        return jsonify({"error": "Password must include at least one special symbol (!@#$%^&*)."}), 400

    # 4. Check if email is already registered
    if any(u["email"] == email for u in users_db):
        return jsonify({"error": "This email address is already registered. Please go to Log In."}), 409

    # 5. Generate secure 6-digit OTP code
    otp_code = f"{random.randint(100000, 999999)}"

    # 6. Attempt sending verification email
    email_sent = False
    dev_mode_active = False
    try:
        send_otp_email(email, name, otp_code)
        email_sent = True
    except (smtplib.SMTPAuthenticationError, smtplib.SMTPServerDisconnected) as e:
        print(f"\n[SMTP AUTH ERROR] Could not log in to Gmail: {e}")
        print(f"--> [DEV MODE ACTIVE] Verification OTP for {email}: {otp_code}\n")
        dev_mode_active = True
    except smtplib.SMTPRecipientsRefused:
        return jsonify({"error": "This email address was rejected by the mail server. Please enter a real email."}), 400
    except Exception as e:
        print(f"\n[SMTP ERROR]: {e}")
        print(f"--> [DEV MODE ACTIVE] Verification OTP for {email}: {otp_code}\n")
        dev_mode_active = True

    # 7. Temporarily cache registration data pending verification (10 minutes)
    pending_verifications[email] = {
        "name": name,
        "password_hash": generate_password_hash(password),
        "otp": otp_code,
        "expires_at": datetime.utcnow() + timedelta(minutes=10),
    }

    if dev_mode_active:
        return jsonify({
            "message": f"[Dev Mode] Mail failed to send. Your OTP code is: {otp_code}",
            "email": email,
            "requires_verification": True,
            "dev_otp": otp_code,
            "warning": "Gmail rejected credentials. Used terminal backup OTP."
        })

    return jsonify({
        "message": f"Verification code sent to {email}. Check your inbox.",
        "email": email,
        "requires_verification": True,
    })


@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    otp_input = data.get("otp", "").strip()

    pending = pending_verifications.get(email)
    if not pending:
        return jsonify({"error": "No pending registration found for this email. Please sign up again."}), 400

    if datetime.utcnow() > pending["expires_at"]:
        pending_verifications.pop(email, None)
        return jsonify({"error": "Verification code has expired. Please sign up again."}), 400

    if pending["otp"] != otp_input:
        return jsonify({"error": "Invalid verification code. Please check your inbox and try again."}), 400

    # Verification successful -> Save verified user
    new_user = {
        "id": len(users_db) + 1,
        "name": pending["name"],
        "email": email,
        "password_hash": pending["password_hash"],
        "verified_at": datetime.utcnow().isoformat(),
    }
    users_db.append(new_user)
    pending_verifications.pop(email, None)

    # Establish long-lived session cookie
    session.permanent = True
    session["user"] = {"name": new_user["name"], "email": new_user["email"]}

    return jsonify({"message": "Email verified successfully!", "user": session["user"]})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Please enter both email and password."}), 400

    # Find verified user
    user = next((u for u in users_db if u["email"] == email), None)
    if not user:
        return jsonify({"error": "No account found with this email. Please sign up first."}), 404

    # Verify password hash
    if not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Incorrect password. Please try again."}), 401

    # Establish session
    session.permanent = True
    session["user"] = {"name": user["name"], "email": user["email"]}

    return jsonify({"message": "Logged in successfully!", "user": session["user"]})


@app.route("/api/resend-otp", methods=["POST"])
def resend_otp():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()

    pending = pending_verifications.get(email)
    if not pending:
        return jsonify({"error": "No pending registration found for this email. Please register again."}), 400

    new_otp = f"{random.randint(100000, 999999)}"
    pending["otp"] = new_otp
    pending["expires_at"] = datetime.utcnow() + timedelta(minutes=10)

    try:
        send_otp_email(email, pending["name"], new_otp)
    except Exception as e:
        print(f"Error resending OTP: {e}")
        print(f"--> [DEV MODE ACTIVE] Resent OTP Code for {email}: {new_otp}\n")
        return jsonify({
            "message": f"[Dev Mode] Resent OTP code: {new_otp}",
            "dev_otp": new_otp
        })

    return jsonify({"message": f"A new verification code was sent to {email}."})


@app.route("/api/me", methods=["GET"])
def check_session():
    user = session.get("user")
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"user": user})


@app.route("/api/signout", methods=["POST"])
def signout():
    session.clear()
    return jsonify({"message": "Signed out successfully"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
