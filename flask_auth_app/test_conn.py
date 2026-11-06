import smtplib
import os
from dotenv import load_dotenv

load_dotenv()

user = os.getenv("GMAIL_USER")
pwd = os.getenv("GMAIL_APP_PASS")
if pwd:
    pwd = pwd.strip().replace(" ", "")

print(f"Testing for email: {user}")

# Test Port 465 (SSL)
print("\n--- Testing Port 465 (SSL) ---")
try:
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as server:
        server.login(user, pwd)
        print("[SUCCESS] Port 465: Connected and logged in successfully!")
except Exception as e:
    print(f"[FAILED] Port 465: {e}")
    if "535" in str(e) or "BadCredentials" in str(e) or "Username and Password not accepted" in str(e) or "SMTPServerDisconnected" in str(type(e)):
        print("-> Hint: Gmail rejected your credentials. Check your email spelling and ensure GMAIL_APP_PASS is a valid 16-character Google App Password (not your regular Gmail password).")

# Test Port 587 (TLS)
print("\n--- Testing Port 587 (TLS) ---")
try:
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(user, pwd)
        print("[SUCCESS] Port 587: Connected and logged in successfully!")
except Exception as e:
    print(f"[FAILED] Port 587: {e}")
