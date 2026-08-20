"""
ShopNest — Intentionally Vulnerable E-Commerce Practice App
=============================================================
FOR AUTHORIZED LOCAL SECURITY TRAINING / BUG BOUNTY LAB PRACTICE ONLY.
Do not deploy this publicly or point it at real user data.

Every vulnerability below is intentional and commented with a
[VULN] tag explaining what it is and roughly how it's meant to be found.
Full writeups + exploit walkthroughs are in README.md and VULN_GUIDE.md.
"""

import sqlite3, hashlib, random, string, time, os, base64, json
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, g, make_response, Response
from mailer import send_email, EMAIL_ENABLED

app = Flask(__name__)
app.secret_key = "shopnest_dev_secret_2026"  # static secret on purpose, not the point of this lab
DB = os.path.join(os.path.dirname(__file__), "shopnest.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# In-memory stores used by several intentionally-weak flows (kept simple for lab clarity)
OTP_STORE = {}          # {username: {"code": "1234", "created": ts}}
CAPTCHA_STORE = {}       # {session_id: "answer"}
LOGIN_ATTEMPTS = {}       # {ip_or_xff: count}   <-- [VULN] trusts X-Forwarded-For, see below
RESET_TOKENS_LOG = []     # just for the /admin debug leak demo

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, email TEXT, password TEXT,
        role TEXT DEFAULT 'user', twofa_enabled INTEGER DEFAULT 0,
        balance REAL DEFAULT 500.0, avatar TEXT DEFAULT 'default.png'
    )""")
    c.execute("""CREATE TABLE products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, price REAL, description TEXT, image TEXT, stock INTEGER
    )""")
    c.execute("""CREATE TABLE orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, product_id INTEGER, qty INTEGER,
        status TEXT DEFAULT 'Processing', shipping_address TEXT
    )""")
    c.execute("""CREATE TABLE reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER, user_id INTEGER, username TEXT, content TEXT, rating INTEGER
    )""")

    # [LAB DATA] dummy users — plain-ish md5 hashing on purpose (weak crypto is a
    # believable real-world finding but NOT the focus vuln of this lab)
    users = [
        ("admin", "admin@shopnest.local", md5("Admin@123"), "admin", 0, 5000.0),
        ("alice", "alice@shopnest.local", md5("Alice@123"), "user", 0, 750.0),
        ("bob", "bob@shopnest.local", md5("Bob@123"), "user", 0, 300.0),
        ("charlie", "charlie@shopnest.local", md5("Charlie@123"), "user", 1, 900.0),
        ("victim", "victim@shopnest.local", md5("Victim@2024"), "user", 0, 1200.0),
    ]
    c.executemany("INSERT INTO users (username,email,password,role,twofa_enabled,balance) VALUES (?,?,?,?,?,?)", users)

    products = [
        ("Aether Wireless Earbuds Pro", 3499.0, "Noise-cancelling earbuds with 40hr battery life.", "earbuds.jpg", 42),
        ("Nimbus Mechanical Keyboard", 5999.0, "Hot-swappable 75% mechanical keyboard, RGB.", "keyboard.jpg", 18),
        ("Orbit Smartwatch Series 4", 8999.0, "AMOLED display, SpO2, 7-day battery.", "smartwatch.jpg", 25),
        ("Kestrel Running Shoes", 2799.0, "Lightweight breathable running shoes.", "shoes.jpg", 60),
        ("Solace Weighted Blanket", 1899.0, "7kg weighted blanket for better sleep.", "blanket.jpg", 33),
        ("Photon 65W GaN Charger", 1299.0, "Compact 3-port fast charger.", "charger.jpg", 80),
        ("Vertex Ergonomic Chair", 12999.0, "Mesh-back ergonomic office chair.", "chair.jpg", 12),
        ("Drift Bluetooth Speaker", 2199.0, "IPX7 waterproof portable speaker.", "speaker.jpg", 47),
    ]
    c.executemany("INSERT INTO products (name,price,description,image,stock) VALUES (?,?,?,?,?)", products)

    reviews = [
        (1, 2, "alice", "Sound quality is amazing, battery lasts all week!", 5),
        (1, 3, "bob", "Good but the case scratches easily.", 4),
        (2, 4, "charlie", "Best keyboard I've owned. Switches feel premium.", 5),
        (3, 2, "alice", "Battery drains fast with always-on display.", 3),
    ]
    c.executemany("INSERT INTO reviews (product_id,user_id,username,content,rating) VALUES (?,?,?,?,?)", reviews)

    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# [VULN] #10 — No rate limiting + #11 header-based "IP" trust
# ---------------------------------------------------------------------------
def get_client_key():
    """
    [VULN] Trusts the X-Forwarded-For header as the sole identity for
    rate-limiting / lockout tracking, with no check that the request
    actually came through a trusted proxy.
    Exploit: send X-Forwarded-For: <random-ip> on every request to reset
    your own attempt counter and brute-force endpoints that "look" rate limited.
    See VULN_GUIDE.md section 11.
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr

def note_attempt(key_prefix):
    key = key_prefix + ":" + get_client_key()
    LOGIN_ATTEMPTS[key] = LOGIN_ATTEMPTS.get(key, 0) + 1
    return LOGIN_ATTEMPTS[key]

# NOTE: on purpose, none of the sensitive endpoints below actually enforce a
# lockout even though they call note_attempt() and "look" protected — several
# real targets have this exact half-implemented pattern. Intermediate players
# should notice the counter never blocks anything.

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def effective_role():
    """
    [VULN] #12 Broken Access Control — role is trusted from a plain,
    unsigned cookie in addition to the session. If the 'role' cookie is
    present it silently overrides session role for nav/display AND for
    some server-side checks below (see /admin route).
    Exploit: log in as a normal user, then in DevTools Application tab
    add cookie role=admin. Reload.
    """
    cookie_role = request.cookies.get("role")
    if cookie_role:
        return cookie_role
    u = current_user()
    return u["role"] if u else "guest"

@app.context_processor
def inject_globals():
    return dict(current_user=current_user(), effective_role=effective_role())

# ---------------------------------------------------------------------------
# Storefront
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    return render_template("index.html", products=products)

@app.route("/product/<int:pid>")
def product(pid):
    db = get_db()
    p = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    reviews = db.execute("SELECT * FROM reviews WHERE product_id=?", (pid,)).fetchall()
    return render_template("product.html", p=p, reviews=reviews)

@app.route("/product/<int:pid>/review", methods=["POST"])
def add_review(pid):
    """
    [VULN] #13 Stored XSS — review content is stored and rendered with
    the Jinja |safe filter in product.html, no sanitisation.
    Exploit: submit a review containing e.g. an <img> tag with an onerror
    handler, or a <script> tag. Fires for every visitor viewing the product.
    Contrast with the product NAME field elsewhere, which IS escaped —
    that inconsistency is intentional and realistic.
    """
    u = current_user()
    username = u["username"] if u else "guest"
    uid = u["id"] if u else 0
    content = request.form.get("content", "")
    rating = request.form.get("rating", "5")
    db = get_db()
    db.execute("INSERT INTO reviews (product_id,user_id,username,content,rating) VALUES (?,?,?,?,?)",
               (pid, uid, username, content, rating))
    db.commit()
    return redirect(url_for("product", pid=pid))

@app.route("/search")
def search():
    """
    [VULN] #13 Reflected XSS — the raw query string is echoed back into
    the results page heading via |safe, unescaped.
    Exploit: /search?q=<script>alert(document.cookie)</script>
    """
    q = request.args.get("q", "")
    db = get_db()
    results = db.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    return render_template("search.html", q=q, results=results)

# ---------------------------------------------------------------------------
# Registration / Login
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        db = get_db()
        try:
            db.execute("INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)",
                       (username, email, md5(password), "user"))
            db.commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Username taken")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # [VULN] #10 no real rate limiting on login despite tracking attempts
        attempts = note_attempt("login:" + username)

        # [VULN] #4 Cloudflare-style checkbox captcha — client sets this hidden
        # field via JS with no server-side token check at all.
        captcha_verified = request.form.get("captcha_verified")
        if not captcha_verified:
            return render_template("login.html", error="Please verify you are not a robot.")

        db = get_db()
        u = db.execute("SELECT * FROM users WHERE username=? AND password=?", (username, md5(password))).fetchone()
        if u:
            if u["twofa_enabled"]:
                session["pending_2fa_user"] = u["id"]
                code = "".join(random.choice(string.digits) for _ in range(4))
                OTP_STORE[u["username"]] = {"code": code, "created": time.time()}
                return redirect(url_for("twofa_verify"))
            session["user_id"] = u["id"]
            resp = make_response(redirect(url_for("index")))
            resp.set_cookie("role", u["role"])  # [VULN] see effective_role()
            return resp
        error = "Invalid credentials"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("role", "", expires=0)
    return resp

# ---------------------------------------------------------------------------
# [VULN] #7 2FA bypass via forced browsing + weak/leaked OTP
# ---------------------------------------------------------------------------
@app.route("/2fa-verify", methods=["GET", "POST"])
def twofa_verify():
    uid = session.get("pending_2fa_user")
    if not uid:
        return redirect(url_for("login"))
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    error = None
    if request.method == "POST":
        code = request.form.get("code")
        note_attempt("2fa:" + u["username"])  # tracked but never enforced -> brute-forceable 4-digit code
        stored = OTP_STORE.get(u["username"], {})
        if stored.get("code") == code:
            session["user_id"] = u["id"]
            session.pop("pending_2fa_user", None)
            resp = make_response(redirect(url_for("index")))
            resp.set_cookie("role", u["role"])
            return resp
        error = "Invalid code"
    return render_template("twofa.html", error=error, username=u["username"])

@app.route("/dashboard")
def dashboard():
    """
    [VULN] #7 2FA bypass — this page only checks session['user_id'], which
    normally isn't set until 2FA passes... EXCEPT session['pending_2fa_user']
    plus a stale/previous session['user_id'] from an earlier login can leave
    this reachable, and more importantly /profile/<id> and /order/<id> below
    don't re-check twofa status at all once *any* user_id is ever present.
    See VULN_GUIDE.md #7 for the exact forced-browsing chain.
    """
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    db = get_db()
    orders = db.execute("SELECT o.*, p.name, p.price FROM orders o JOIN products p ON o.product_id=p.id WHERE o.user_id=?", (u["id"],)).fetchall()
    return render_template("dashboard.html", orders=orders)

# ---------------------------------------------------------------------------
# [VULN] #2/#3 OTP generation, exposure & bypass  (also used for checkout OTP)
# ---------------------------------------------------------------------------
@app.route("/api/send-otp", methods=["POST"])
def send_otp():
    """
    [VULN] #2 — OTP is 4 digits, has no expiry enforcement, and is
    returned directly in the JSON response ("for demo/debug purposes")
    instead of only being sent out-of-band. Visible in DevTools > Network.
    """
    username = request.json.get("username") if request.is_json else request.form.get("username")
    code = "".join(random.choice(string.digits) for _ in range(4))
    OTP_STORE[username] = {"code": code, "created": time.time()}
    emailed = send_email(
        subject=f"ShopNest — your verification code is {code}",
        body=f"Hi {username},\n\nYour ShopNest verification code is: {code}\n\n"
             f"It doesn't expire and isn't rate-limited (lab: notice both of those "
             f"in your testing). If you didn't request this, ignore it.\n\n— ShopNest",
    )
    return jsonify({"status": "sent",
                     "message": f"OTP sent to registered email for {username}" + (" (check your inbox)" if emailed else ""),
                     "debug_otp": code})  # <-- the leak, still present even with real email delivery

@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    username = request.form.get("username")
    code = request.form.get("code")
    note_attempt("otp:" + username)  # not enforced, brute-forceable (10,000 combos, no lockout)
    stored = OTP_STORE.get(username, {})
    if stored.get("code") == code:
        return jsonify({"status": "verified"})
    return jsonify({"status": "invalid"})

@app.route("/api/debug/last-otp")
def debug_last_otp():
    """
    [VULN] #3 OTP exposer — a leftover debug endpoint that leaks the most
    recent OTP for any username via query param, no auth required.
    Exploit: /api/debug/last-otp?username=victim
    """
    username = request.args.get("username")
    stored = OTP_STORE.get(username)
    if not stored:
        return jsonify({"error": "no otp found"}), 404
    return jsonify({"username": username, "otp": stored["code"]})

# ---------------------------------------------------------------------------
# [VULN] #4/#5 CAPTCHA image bypass + exposer
# ---------------------------------------------------------------------------
CAPTCHA_CHARS = string.ascii_uppercase + string.digits

@app.route("/api/captcha")
def get_captcha():
    """
    [VULN] #4 — the "image" captcha is actually rendered as styled text in
    the DOM (SVG), and the answer is embedded in a data attribute AND the
    alt text of the element for "accessibility" — viewable via view-source
    or DevTools without solving anything visually.
    """
    answer = "".join(random.choice(CAPTCHA_CHARS) for _ in range(5))
    sid = session.get("_id") or base64.b64encode(os.urandom(8)).decode()
    session["_id"] = sid
    CAPTCHA_STORE[sid] = answer
    return jsonify({"captcha_svg_text": answer, "alt_text_answer": answer})  # the leak

@app.route("/api/captcha/verify", methods=["POST"])
def verify_captcha():
    """
    [VULN] #5 CAPTCHA exposer — verification endpoint echoes back the
    expected answer in its response body when verification fails
    ("to help users debug"), letting an attacker learn the answer in one
    wrong guess.
    """
    sid = session.get("_id")
    guess = request.form.get("answer", "")
    expected = CAPTCHA_STORE.get(sid, "")
    if guess.upper() == expected:
        return jsonify({"status": "ok"})
    return jsonify({"status": "fail", "expected_for_debug": expected})

# ---------------------------------------------------------------------------
# [VULN] #6/#8 Account takeover via predictable reset token + email takeover
# ---------------------------------------------------------------------------
def make_reset_token(username):
    """
    [VULN] #6 — token is a deterministic MD5 of username + a fixed,
    guessable pepper, with NO expiry and NO per-request randomness.
    Anyone who knows/guesses a username can compute a valid reset token
    for that account offline.
    """
    return md5(username + "shopnest-static-pepper")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = None
    if request.method == "POST":
        username = request.form.get("username")
        note_attempt("forgot:" + username)
        token = make_reset_token(username)
        RESET_TOKENS_LOG.append({"username": username, "token": token, "ts": time.time()})
        reset_link = url_for("reset_password", username=username, token=token, _external=True)
        emailed = send_email(
            subject="ShopNest — reset your password",
            body=f"Hi {username},\n\nClick the link below to reset your ShopNest password:\n\n"
                 f"{reset_link}\n\n"
                 f"This link doesn't expire (lab: worth noting for your writeup). "
                 f"If you didn't request this, ignore it.\n\n— ShopNest",
        )
        # Still shown on-page too, matching real misconfigs where staging/dev
        # builds leak the link in the response as well as emailing it.
        message = f"If that account exists, a reset link was sent" + (" to your inbox." if emailed else ".") + \
                  f" (Lab mode link: {reset_link})"
    return render_template("forgot_password.html", message=message)

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    username = request.args.get("username") or request.form.get("username")
    token = request.args.get("token") or request.form.get("token")
    error = None
    if not username:
        return render_template("reset_password.html", error="Missing username", username=username, token=token)
    expected = make_reset_token(username)
    if token != expected:
        error = "Invalid or expired token"
        return render_template("reset_password.html", error=error, username=username, token=token)
    if request.method == "POST":
        new_password = request.form.get("password")
        db = get_db()
        db.execute("UPDATE users SET password=? WHERE username=?", (md5(new_password), username))
        db.commit()
        return redirect(url_for("login"))
    return render_template("reset_password.html", error=None, username=username, token=token)

@app.route("/profile/<int:uid>")
def profile(uid):
    """
    [VULN] #12 IDOR — any logged in user can view ANY profile by changing
    the id in the URL, no ownership check against session user.
    """
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        return "Not found", 404
    return render_template("profile.html", u=u)

@app.route("/profile/<int:uid>/change-email", methods=["POST"])
def change_email(uid):
    """
    [VULN] #8 Email takeover — changes the email on ANY user id passed in
    the URL with no ownership check AND no re-authentication (no current
    password / no confirmation link to the new address). Combine with the
    IDOR above or with the clickjacking demo page to takeover silently.
    """
    new_email = request.form.get("email")
    db = get_db()
    db.execute("UPDATE users SET email=? WHERE id=?", (new_email, uid))
    db.commit()
    return redirect(url_for("profile", uid=uid))

@app.route("/order/<int:oid>")
def view_order(oid):
    """[VULN] #12 IDOR on orders — same pattern as profile."""
    db = get_db()
    o = db.execute("SELECT o.*, p.name, p.price, u.username FROM orders o JOIN products p ON o.product_id=p.id JOIN users u ON o.user_id=u.id WHERE o.id=?", (oid,)).fetchone()
    if not o:
        return "Not found", 404
    return render_template("order.html", o=o)

# ---------------------------------------------------------------------------
# Cart / checkout (simple, session cart)
# ---------------------------------------------------------------------------
@app.route("/cart/add/<int:pid>")
def cart_add(pid):
    cart = session.get("cart", {})
    cart[str(pid)] = cart.get(str(pid), 0) + 1
    session["cart"] = cart
    return redirect(url_for("cart_view"))

@app.route("/cart")
def cart_view():
    db = get_db()
    cart = session.get("cart", {})
    items = []
    total = 0
    for pid, qty in cart.items():
        p = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if p:
            items.append({"product": p, "qty": qty, "subtotal": p["price"] * qty})
            total += p["price"] * qty
    return render_template("cart.html", items=items, total=total)

@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    db = get_db()
    cart = session.get("cart", {})
    if request.method == "POST":
        for pid, qty in cart.items():
            db.execute("INSERT INTO orders (user_id,product_id,qty,shipping_address) VALUES (?,?,?,?)",
                       (u["id"], pid, qty, request.form.get("address", "")))
        db.commit()
        session["cart"] = {}
        return redirect(url_for("dashboard"))
    return render_template("checkout.html", cart=cart)

# ---------------------------------------------------------------------------
# [VULN] #9 Null-byte / weak upload validation -> path traversal
# ---------------------------------------------------------------------------
@app.route("/profile/<int:uid>/avatar", methods=["POST"])
def upload_avatar(uid):
    """
    [VULN] #9 — extension check only inspects text AFTER the last '.' the
    naive way (`filename.rsplit('.',1)[1]`), and the raw filename (including
    any '../' path segments a client sends) is used when saving. Modern
    Python doesn't truncate at a literal null byte the way old PHP did, but
    this endpoint still trusts the client-supplied filename outright, which
    is the realistic 2026-era version of the same bug class: path traversal
    via unsanitised filenames. Exploit: upload a file named
    '../../templates/product.html' (or similar) as a "jpg" and observe where
    it lands. See VULN_GUIDE.md #9 for the walkthrough and why the null-byte
    trick itself no longer works on modern Python/Flask.
    """
    f = request.files.get("avatar")
    if not f or "." not in f.filename:
        return "No file", 400
    ext = f.filename.rsplit(".", 1)[1].lower()
    if ext not in ("jpg", "jpeg", "png", "gif"):
        return "Invalid file type", 400
    # intentionally naive: saves using the raw client filename
    save_path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(save_path)
    db = get_db()
    db.execute("UPDATE users SET avatar=? WHERE id=?", (f.filename, uid))
    db.commit()
    return redirect(url_for("profile", uid=uid))

# ---------------------------------------------------------------------------
# [VULN] #12 Broken access control — admin panel + source/backup disclosure
# ---------------------------------------------------------------------------
@app.route("/admin")
def admin_panel():
    """
    Checks effective_role() which, remember, can be overridden by an
    unsigned cookie. This is the payoff for the cookie-manipulation vuln.
    """
    if effective_role() != "admin":
        return "403 Forbidden", 403
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    orders = db.execute("SELECT o.*, u.username, p.name FROM orders o JOIN users u ON o.user_id=u.id JOIN products p ON o.product_id=p.id").fetchall()
    return render_template("admin.html", users=users, orders=orders, reset_log=RESET_TOKENS_LOG)

@app.route("/admin/promote/<int:uid>")
def admin_promote(uid):
    """Same cookie-trust bug reachable on a state-changing action, no CSRF token."""
    if effective_role() != "admin":
        return "403 Forbidden", 403
    db = get_db()
    db.execute("UPDATE users SET role='admin' WHERE id=?", (uid,))
    db.commit()
    return redirect(url_for("admin_panel"))

# a couple of classic "left it in prod" disclosure endpoints, linked only
# from an HTML comment on the homepage (view-source to find them)
@app.route("/backup.zip")
def backup_zip():
    return Response("PK\x03\x04 (this would be a real backup archive containing app.py, shopnest.db, and .env in a live misconfig)",
                     mimetype="application/zip")

@app.route("/.git/config")
def git_config_leak():
    return Response("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/shopnest-dev/shopnest-backend.git\n",
                     mimetype="text/plain")

# ---------------------------------------------------------------------------
# [VULN] #1 Clickjacking — sensitive settings page served with NO
# X-Frame-Options / frame-ancestors CSP anywhere in the app.
# ---------------------------------------------------------------------------
@app.after_request
def add_headers(resp):
    # Deliberately NOT setting X-Frame-Options / CSP frame-ancestors.
    # Deliberately NOT setting a strict CSP (so the XSS vulns above work).
    resp.headers["X-Powered-By"] = "ShopNest/4.2 (Flask)"
    return resp

@app.route("/clickjacking-demo")
def clickjacking_demo():
    """
    Standalone attacker-controlled page for practicing the clickjacking
    exploit against /profile/<id>/change-email. Iframes the real settings
    page and overlays a decoy button. See VULN_GUIDE.md #1 for the full
    step-by-step tutorial (why it works, how to line up the overlay, and
    the fix: X-Frame-Options / CSP frame-ancestors).
    """
    u = current_user()
    uid = u["id"] if u else 2
    return render_template("clickjacking_demo.html", uid=uid)

# ---------------------------------------------------------------------------
# [VULN] header-reflected XSS via User-Agent on an admin debug page
# ---------------------------------------------------------------------------
@app.route("/admin/debug-headers")
def debug_headers():
    if effective_role() != "admin":
        return "403 Forbidden", 403
    ua = request.headers.get("User-Agent", "")
    referer = request.headers.get("Referer", "")
    return render_template("debug_headers.html", ua=ua, referer=referer)

# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not os.path.exists(DB):
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
