"""
NovaBank Secure Portal - INTENTIONALLY VULNERABLE practice target
For local, authorized bug-bounty / pentest self-training ONLY.
Do not expose this to the internet or any network you don't control.

Run:
    python3 seed.py      # creates db + seeds dummy clients (one time)
    python3 app.py       # starts on http://127.0.0.1:5000
"""

import sqlite3
import random
import string
import hashlib
import time
import os
from flask import (
    Flask, request, session, redirect, url_for, render_template,
    jsonify, g, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "novabank.db")

app = Flask(__name__)
app.secret_key = "novabank-local-practice-secret-key-not-for-prod"

# ----------------------------------------------------------------------
# DB helpers
# ----------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            account_number TEXT,
            balance REAL DEFAULT 0,
            mfa_enabled INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS otp_store (
            user_id INTEGER,
            otp TEXT,
            created_at REAL
        );

        CREATE TABLE IF NOT EXISTS reset_tokens (
            token TEXT,
            user_id INTEGER,
            created_at REAL,
            used INTEGER DEFAULT 0
        );
        """
    )
    db.commit()
    db.close()


# ----------------------------------------------------------------------
# Small utils
# ----------------------------------------------------------------------

def gen_otp():
    return "".join(random.choices(string.digits, k=6))


def gen_account_number():
    return "NB" + "".join(random.choices(string.digits, k=10))


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


# ----------------------------------------------------------------------
# Security headers
# NOTE (intentional vuln): /dashboard and /security are deliberately
# excluded from the X-Frame-Options / CSP frame-ancestors protection
# below, so those two pages can be iframed by a third-party page
# (clickjacking target).
# ----------------------------------------------------------------------

PROTECTED_FROM_FRAMING = {"login", "register", "forgot_password", "reset_password"}


@app.after_request
def set_headers(resp):
    if request.endpoint in PROTECTED_FROM_FRAMING:
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return resp


# ----------------------------------------------------------------------
# Login  (CAPTCHA bug + 2FA "forced browsing" bug live here)
# ----------------------------------------------------------------------

@app.route("/", endpoint="index")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"], endpoint="login")
def login():
    db = get_db()
    show_captcha = session.get("failed_attempts", 0) >= 2

    if request.method == "GET":
        if show_captcha:
            a, b = random.randint(1, 9), random.randint(1, 9)
            session["captcha_solution"] = a + b
            session["captcha_prompt"] = f"{a} + {b}"
        return render_template("login.html", show_captcha=show_captcha,
                                captcha_prompt=session.get("captcha_prompt"),
                                captcha_solution=session.get("captcha_solution"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # ---- CAPTCHA CHECK ----
    if show_captcha:
        submitted = request.form.get("captcha_answer")
        correct = session.get("captcha_solution")
        # BUG: only validates the captcha if a value was actually submitted.
        # Dropping the field entirely (e.g. via Burp/Repeater) skips the check.
        if submitted:
            if str(submitted) != str(correct):
                flash("Incorrect captcha answer.")
                a, b = random.randint(1, 9), random.randint(1, 9)
                session["captcha_solution"] = a + b
                session["captcha_prompt"] = f"{a} + {b}"
                return render_template("login.html", show_captcha=True,
                                        captcha_prompt=session["captcha_prompt"],
                                        captcha_solution=session["captcha_solution"])

    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        session["failed_attempts"] = session.get("failed_attempts", 0) + 1
        flash("Invalid username or password.")
        return redirect(url_for("login"))

    session["failed_attempts"] = 0
    session.pop("captcha_solution", None)

    # BUG (2FA weakness #1 - broken state machine / forced browsing):
    # user_id is set as soon as the password is correct, BEFORE the OTP
    # step has happened. dashboard only checks "is user_id in session",
    # so a user can skip straight to /dashboard without ever completing 2FA.
    session["user_id"] = user["id"]

    if user["mfa_enabled"]:
        session["awaiting_otp_for"] = user["id"]
        otp = gen_otp()
        db.execute("INSERT INTO otp_store (user_id, otp, created_at) VALUES (?,?,?)",
                   (user["id"], otp, time.time()))
        db.commit()
        return redirect(url_for("verify_otp"))

    return redirect(url_for("dashboard"))


# ----------------------------------------------------------------------
# OTP verification (backdoor OTP bug + OTP exposure bug live here)
# ----------------------------------------------------------------------

@app.route("/verify-otp", methods=["GET", "POST"], endpoint="verify_otp")
def verify_otp():
    uid = session.get("awaiting_otp_for")
    if not uid:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("verify_otp.html")

    entered = request.form.get("otp", "").strip()
    db = get_db()
    row = db.execute(
        "SELECT * FROM otp_store WHERE user_id=? ORDER BY created_at DESC LIMIT 1",
        (uid,),
    ).fetchone()

    # BUG (OTP bypass #1): a static, undocumented "debug" code always works,
    # regardless of the real generated OTP. No rate limiting either, so this
    # (or the real code) can be brute-forced freely.
    valid = entered == "000000" or (row is not None and entered == row["otp"])

    if valid:
        session.pop("awaiting_otp_for", None)
        return redirect(url_for("dashboard"))

    flash("Incorrect OTP code.")
    return redirect(url_for("verify_otp"))


@app.route("/resend-otp", methods=["POST"], endpoint="resend_otp")
def resend_otp():
    uid = session.get("awaiting_otp_for")
    if not uid:
        return jsonify({"error": "no pending verification"}), 400
    otp = gen_otp()
    db = get_db()
    db.execute("INSERT INTO otp_store (user_id, otp, created_at) VALUES (?,?,?)",
               (uid, otp, time.time()))
    db.commit()
    # BUG (OTP bypass #2 - OTP exposure): the freshly generated OTP is
    # echoed back in the JSON response "for demo/debug purposes",
    # visible to anyone watching the Network tab.
    return jsonify({"message": "A new OTP has been sent.", "debug_otp": otp})


# ----------------------------------------------------------------------
# BUG (2FA weakness #2 - client-trusted verification flag):
# This endpoint is meant to be called internally by front-end JS only
# after a real OTP check succeeded - but it performs NO server-side
# verification itself. It blindly trusts whatever "verified" flag and
# "user_id" the caller sends, so it can be called directly (e.g. from
# devtools console or Burp) to fully authenticate as ANY user id,
# without ever knowing a password or OTP. This also doubles as an
# account-takeover vector.
# ----------------------------------------------------------------------

@app.route("/api/complete-2fa", methods=["POST"], endpoint="complete_2fa")
def complete_2fa():
    data = request.get_json(silent=True) or {}
    if data.get("verified") is True and data.get("user_id"):
        session["user_id"] = data["user_id"]
        session.pop("awaiting_otp_for", None)
        return jsonify({"status": "ok"})
    return jsonify({"status": "denied"}), 403


# ----------------------------------------------------------------------
# Dashboard / account (clickjacking target - see PROTECTED_FROM_FRAMING)
# ----------------------------------------------------------------------

@app.route("/dashboard", endpoint="dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user)


@app.route("/security", methods=["GET"], endpoint="security")
def security():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("security.html", user=user)


@app.route("/toggle-2fa", methods=["POST"], endpoint="toggle_2fa")
def toggle_2fa():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    new_val = 0 if user["mfa_enabled"] else 1
    db.execute("UPDATE users SET mfa_enabled=? WHERE id=?", (new_val, user["id"]))
    db.commit()
    return redirect(url_for("security"))


# BUG (IDOR - sensitive data exposure): no ownership check, any logged-in
# session can pull any user's profile data by changing the id in the URL.
@app.route("/api/profile/<int:uid>", endpoint="api_profile")
def api_profile(uid):
    if not current_user():
        return jsonify({"error": "auth required"}), 401
    db = get_db()
    row = db.execute(
        "SELECT id, username, email, full_name, account_number, balance, mfa_enabled "
        "FROM users WHERE id=?", (uid,)
    ).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/logout", endpoint="logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ----------------------------------------------------------------------
# Registration (for your own account)
# ----------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"], endpoint="register")
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    full_name = request.form.get("full_name", "").strip()
    password = request.form.get("password", "")

    if not username or not email or not password:
        flash("All fields are required.")
        return redirect(url_for("register"))

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE username=? OR email=?", (username, email)
    ).fetchone()
    if existing:
        flash("Username or email already in use.")
        return redirect(url_for("register"))

    db.execute(
        "INSERT INTO users (username, email, password_hash, full_name, account_number, balance, mfa_enabled) "
        "VALUES (?,?,?,?,?,?,0)",
        (username, email, generate_password_hash(password), full_name,
         gen_account_number(), round(random.uniform(500, 5000), 2)),
    )
    db.commit()
    flash("Account created. You can log in now.")
    return redirect(url_for("login"))


# ----------------------------------------------------------------------
# Forgot / reset password (Account Takeover via IDOR on reset token)
# ----------------------------------------------------------------------

@app.route("/forgot-password", methods=["GET", "POST"], endpoint="forgot_password")
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    email = request.form.get("email", "").strip()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    # Always show the same generic message (no username/email enumeration here).
    generic_msg = "If that email exists in our system, a reset link has been generated below (local demo mode - no mail server)."

    reset_link = None
    if user:
        token = hashlib.sha1(f"{user['id']}{time.time()}{random.random()}".encode()).hexdigest()[:20]
        db.execute(
            "INSERT INTO reset_tokens (token, user_id, created_at, used) VALUES (?,?,?,0)",
            (token, user["id"], time.time()),
        )
        db.commit()
        # In a real app this token would only ever be emailed to the account
        # owner. Since this is a local practice app with no mail server, we
        # surface it here so *you* can complete the intended flow for your
        # own test account. The underlying vulnerability is independent of
        # this: see reset-password below.
        reset_link = url_for("reset_password", token=token, user_id=user["id"], _external=False)

    return render_template("forgot_password.html", generic_msg=generic_msg, reset_link=reset_link)


@app.route("/reset-password", methods=["GET", "POST"], endpoint="reset_password")
def reset_password():
    token = request.args.get("token") or request.form.get("token")
    user_id = request.args.get("user_id") or request.form.get("user_id")

    if not token or not user_id:
        flash("Invalid reset link.")
        return redirect(url_for("forgot_password"))

    db = get_db()

    if request.method == "GET":
        return render_template("reset_password.html", token=token, user_id=user_id)

    new_password = request.form.get("password", "")

    # BUG (Account Takeover via IDOR): the token is checked for existence /
    # not-used / not-expired, but it is NEVER checked that the token was
    # actually issued for THIS user_id. An attacker who requests a reset
    # for their OWN account gets a valid, unused token, then simply swaps
    # the user_id form/query field to a victim's id to reset the
    # victim's password instead of their own.
    row = db.execute(
        "SELECT * FROM reset_tokens WHERE token=? AND used=0", (token,)
    ).fetchone()

    if not row:
        flash("Reset link is invalid or has already been used.")
        return redirect(url_for("forgot_password"))

    if time.time() - row["created_at"] > 900:
        flash("Reset link has expired.")
        return redirect(url_for("forgot_password"))

    db.execute("UPDATE users SET password_hash=? WHERE id=?",
               (generate_password_hash(new_password), user_id))
    db.execute("UPDATE reset_tokens SET used=1 WHERE token=?", (token,))
    db.commit()
    flash("Password has been reset. You can log in now.")
    return redirect(url_for("login"))


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
