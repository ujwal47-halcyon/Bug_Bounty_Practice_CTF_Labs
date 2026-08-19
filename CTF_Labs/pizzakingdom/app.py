"""
PIZZA KINGDOM - Intentionally Vulnerable Web App for Bug Bounty Practice
=========================================================================
Built for hands-on practice, NOT for any real deployment or use against
real users. Every vulnerability is tagged with [VULN-xx] and documented
in VULNERABILITIES.md. Run locally only.

Author: practice lab for Ujwal (bug bounty / pentest training)
"""

import sqlite3
import hashlib
import random
import string
import time
import os
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, flash

app = Flask(__name__)
app.secret_key = "supersecret123"  # [VULN-09] weak, hardcoded session secret
DB = os.path.join(os.path.dirname(__file__), "pizzakingdom.db")

# ---------------------------------------------------------------------------
# DB SETUP
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, email TEXT UNIQUE, phone TEXT,
        password TEXT, is_verified INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, otp TEXT, created_at REAL, attempts INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, token TEXT, used INTEGER DEFAULT 0, created_at REAL
    );
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, items TEXT, address TEXT, total REAL, status TEXT
    );
    """)
    conn.commit()

    # seed a couple of demo users + orders so IDOR has something to find
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (name,email,phone,password,is_verified) VALUES (?,?,?,?,1)",
                   ("Demo Victim", "victim@example.com", "9999999999", hashlib.sha256(b"password123").hexdigest()))
        c.execute("INSERT INTO users (name,email,phone,password,is_verified) VALUES (?,?,?,?,1)",
                   ("Test Attacker", "attacker@example.com", "8888888888", hashlib.sha256(b"password123").hexdigest()))
        conn.commit()
        c.execute("INSERT INTO orders (user_id,items,address,total,status) VALUES (1,'Large Pepperoni x1','221B Baker Street',499,'Delivered')")
        c.execute("INSERT INTO orders (user_id,items,address,total,status) VALUES (2,'Veg Supreme x2','42 Wallaby Way',799,'Preparing')")
        conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def gen_otp():
    return "".join(random.choice(string.digits) for _ in range(4))  # 4-digit, small keyspace -> easy brute force


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return u


# ---------------------------------------------------------------------------
# HOME / MENU
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", user=current_user())


# ---------------------------------------------------------------------------
# REGISTER  ->  OTP EXPOSURE + OTP BYPASS + NO RATE LIMIT
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        password = request.form.get("password", "")
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db()
        try:
            conn.execute("INSERT INTO users (name,email,phone,password) VALUES (?,?,?,?)",
                         (name, email, phone, pwd_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Email already registered")
            return redirect(url_for("register"))

        uid = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
        otp = gen_otp()
        conn.execute("INSERT INTO otps (user_id, otp, created_at) VALUES (?,?,?)", (uid, otp, time.time()))
        conn.commit()
        conn.close()

        session["pending_user"] = uid

        # [VULN-01] OTP EXPOSURE: OTP echoed back in the page / API response.
        # A real app would only ever send this over SMS. Check the page
        # source / network tab after registering.
        flash(f"(DEV) Your OTP is {otp} - remove before production!")
        return redirect(url_for("verify_otp"))

    return render_template("register.html")


@app.route("/api/resend-otp", methods=["POST"])
def resend_otp():
    """[VULN-01b] OTP EXPOSURE via API - returns the OTP directly in JSON
    instead of only sending it out-of-band. No auth check on who can call
    this either."""
    uid = session.get("pending_user")
    if not uid:
        return jsonify({"error": "no pending verification"}), 400
    otp = gen_otp()
    conn = get_db()
    conn.execute("INSERT INTO otps (user_id, otp, created_at) VALUES (?,?,?)", (uid, otp, time.time()))
    conn.commit()
    conn.close()
    return jsonify({"status": "sent", "otp": otp})  # <-- should never be here


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    uid = session.get("pending_user")
    if not uid:
        return redirect(url_for("register"))

    if request.method == "POST":
        submitted = request.form.get("otp", "")

        # [VULN-02] OTP BYPASS: hardcoded master OTP works for ANY account.
        # Also: [VULN-05] NO RATE LIMIT - unlimited attempts, no lockout,
        # no delay, no captcha after N failures -> 4-digit OTP is brute
        # forceable in under 10,000 requests.
        conn = get_db()
        if submitted == "0000":
            conn.execute("UPDATE users SET is_verified=1 WHERE id=?", (uid,))
            conn.commit()
            conn.close()
            session.pop("pending_user", None)
            session["user_id"] = uid
            return redirect(url_for("index"))

        row = conn.execute(
            "SELECT * FROM otps WHERE user_id=? ORDER BY id DESC LIMIT 1", (uid,)
        ).fetchone()
        conn.execute("UPDATE otps SET attempts = attempts + 1 WHERE id=?", (row["id"],))
        conn.commit()

        if row and submitted == row["otp"]:
            conn.execute("UPDATE users SET is_verified=1 WHERE id=?", (uid,))
            conn.commit()
            conn.close()
            session.pop("pending_user", None)
            session["user_id"] = uid
            return redirect(url_for("index"))

        conn.close()
        flash("Invalid OTP")

    return render_template("verify_otp.html")


# ---------------------------------------------------------------------------
# LOGIN  ->  CAPTCHA EXPOSURE + CAPTCHA BYPASS + NO RATE LIMIT
# ---------------------------------------------------------------------------
def make_captcha():
    a, b = random.randint(1, 9), random.randint(1, 9)
    session["captcha_answer"] = str(a + b)
    return f"{a} + {b} = ?"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        captcha_input = request.form.get("captcha_input", "")
        captcha_field = request.form.get("captcha_answer", "")  # [VULN-03] CAPTCHA EXPOSURE:
        # the expected answer is rendered into a hidden form field in the
        # HTML instead of being validated purely server-side against session.

        # [VULN-04] CAPTCHA BYPASS: server compares the user-supplied answer
        # against the user-supplied hidden field instead of session state -
        # trivially bypassable by editing the hidden input, or just replaying
        # a captured valid pair with a script. There is also no session tie
        # or expiry check.
        if captcha_input != captcha_field:
            flash("Captcha incorrect")
            return render_template("login.html", captcha_q=make_captcha())

        # [VULN-05b] NO RATE LIMIT on login - unlimited password attempts,
        # enabling credential stuffing / brute force.
        conn = get_db()
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        user = conn.execute("SELECT * FROM users WHERE email=? AND password=?", (email, pwd_hash)).fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            return redirect(url_for("index"))
        flash("Invalid credentials")

    return render_template("login.html", captcha_q=make_captcha())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# FORGOT PASSWORD -> PREDICTABLE/REUSABLE TOKEN + EMAIL REDIRECTION TAKEOVER
# ---------------------------------------------------------------------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "")

        # [VULN-06] ACCOUNT TAKEOVER via reset-email manipulation: the app
        # looks up the account by `email`, but will happily "deliver" the
        # reset link to a completely different attacker-controlled address
        # supplied in `notify_email` — the account owner never sees it.
        deliver_to = request.form.get("notify_email") or email

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user:
            # [VULN-07] PREDICTABLE TOKEN: token = md5(email + static salt).
            # Anyone who knows/guesses a victim's email can compute their
            # reset token offline with no interaction with the server.
            token = hashlib.md5((email + "pizzakingdom_static_salt_2024").encode()).hexdigest()
            conn.execute("INSERT INTO reset_tokens (user_id, token, created_at) VALUES (?,?,?)",
                         (user["id"], token, time.time()))
            conn.commit()
            reset_link = url_for("reset_password", token=token, _external=True)
            conn.close()

            # [VULN-06b] the "email" is actually just shown on-screen / returned
            # in the response instead of only being sent out-of-band - so an
            # attacker doesn't even need the notify_email trick, the link
            # leaks directly in the HTTP response.
            flash(f"(DEV) Reset link generated and 'sent' to {deliver_to}: {reset_link}")
            return redirect(url_for("forgot_password"))
        conn.close()
        flash("If that email exists, a reset link was sent.")  # user enumeration is also possible via timing/response diff elsewhere

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = get_db()
    row = conn.execute("SELECT * FROM reset_tokens WHERE token=?", (token,)).fetchone()
    if not row:
        conn.close()
        return "Invalid token", 404

    if request.method == "POST":
        new_password = request.form.get("password", "")
        pwd_hash = hashlib.sha256(new_password.encode()).hexdigest()
        conn.execute("UPDATE users SET password=? WHERE id=?", (pwd_hash, row["user_id"]))
        # [VULN-08] TOKEN REUSE: token is never marked used / never expires,
        # so it can be replayed indefinitely to reset the password again.
        # (Correct code would set used=1 here and check it above.)
        conn.commit()
        conn.close()
        flash("Password reset successful. Token still valid for reuse (bug).")
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset_password.html", token=token)


# ---------------------------------------------------------------------------
# IDOR: PROFILE + ORDERS
# ---------------------------------------------------------------------------
@app.route("/profile/<int:user_id>")
def profile(user_id):
    # [VULN-10] IDOR: only checks that *someone* is logged in, never that
    # the logged-in user matches the requested user_id.
    if not session.get("user_id"):
        return redirect(url_for("login"))
    conn = get_db()
    user = conn.execute("SELECT id,name,email,phone FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if not user:
        return "Not found", 404
    return render_template("profile.html", profile=user)


@app.route("/order/<int:order_id>")
def order_detail(order_id):
    # [VULN-11] IDOR: same issue on order history/receipts - sequential IDs,
    # no ownership check, full name/address/order contents leak.
    if not session.get("user_id"):
        return redirect(url_for("login"))
    conn = get_db()
    order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    conn.close()
    if not order:
        return "Not found", 404
    return render_template("order.html", order=order)


@app.route("/my-orders")
def my_orders():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    conn = get_db()
    orders = conn.execute("SELECT * FROM orders WHERE user_id=?", (user["id"],)).fetchall()
    conn.close()
    return render_template("my_orders.html", orders=orders, user=user)


# ---------------------------------------------------------------------------
# BONUS: BROKEN ACCESS CONTROL -> UNAUTHENTICATED PRIVILEGE ESCALATION
# ---------------------------------------------------------------------------
@app.route("/api/debug/make-admin")
def make_admin():
    # [VULN-12] left-over debug endpoint, no auth check at all. Anyone can
    # promote any user_id to admin.
    user_id = request.args.get("user_id")
    conn = get_db()
    conn.execute("UPDATE users SET is_admin=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "user_id": user_id, "is_admin": True})


@app.route("/admin")
def admin():
    user = current_user()
    if not user or not user["is_admin"]:
        return "Forbidden", 403
    conn = get_db()
    users = conn.execute("SELECT id,name,email,is_admin FROM users").fetchall()
    conn.close()
    return render_template("admin.html", users=users)


# ---------------------------------------------------------------------------
# CART / CHECKOUT (functional filler, no vulns of interest here)
# ---------------------------------------------------------------------------
@app.route("/checkout", methods=["POST"])
def checkout():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    items = request.form.get("items", "Custom Pizza x1")
    address = request.form.get("address", "")
    total = request.form.get("total", "399")
    conn = get_db()
    conn.execute("INSERT INTO orders (user_id, items, address, total, status) VALUES (?,?,?,?,?)",
                 (user["id"], items, address, total, "Preparing"))
    conn.commit()
    conn.close()
    flash("Order placed!")
    return redirect(url_for("my_orders"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)  # debug=True is itself worth noting in your report
