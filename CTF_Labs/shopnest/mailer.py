"""
mailer.py — sends real emails via Gmail SMTP for the ShopNest lab.

Setup:
1. Copy .env.example to .env
2. Fill in GMAIL_ADDRESS + GMAIL_APP_PASSWORD (a Gmail *App Password*,
   not your normal login password — see README for how to generate one)
3. Fill in NOTIFY_EMAIL with the inbox you actually want lab emails
   delivered to (can be the same Gmail address, or any other address
   you own).

If .env isn't configured, the app falls back to just showing the link/OTP
on-page (like before) instead of crashing.
"""

import os
import smtplib
from email.mime.text import MIMEText

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv not installed — .env won't be auto-loaded, but the app
    # still runs fine (email sending just stays disabled unless the
    # GMAIL_ADDRESS / GMAIL_APP_PASSWORD / NOTIFY_EMAIL env vars are set
    # some other way, e.g. exported in your shell).
    print("[mailer] python-dotenv not installed — run: pip install python-dotenv --break-system-packages")

GMAIL_ADDRESS = os.environ.get("GMAIL_ADDRESS", "").strip()
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "").strip()
NOTIFY_EMAIL = os.environ.get("NOTIFY_EMAIL", "").strip()

EMAIL_ENABLED = bool(GMAIL_ADDRESS and GMAIL_APP_PASSWORD and NOTIFY_EMAIL)


def send_email(subject: str, body: str) -> bool:
    """Sends a plain-text email to NOTIFY_EMAIL via Gmail SMTP.
    Returns True if it sent, False if email isn't configured or it failed
    (failures are logged to the console but never crash the app — this is
    a lab, not production infra)."""
    if not EMAIL_ENABLED:
        return False
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = GMAIL_ADDRESS
        msg["To"] = NOTIFY_EMAIL
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_ADDRESS, [NOTIFY_EMAIL], msg.as_string())
        return True
    except Exception as e:
        print(f"[mailer] Failed to send email: {e}")
        return False
