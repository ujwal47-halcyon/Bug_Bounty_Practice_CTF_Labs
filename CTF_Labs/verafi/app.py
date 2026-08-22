"""
Verafi (CTF Edition) — deliberately vulnerable digital-banking site for
bug bounty practice, wired up as a capture-the-flag.

⚠️ FOR LOCAL, AUTHORIZED PRACTICE ONLY. Every bug here is intentional.
Never deploy this outside a network you control.

Run:
    pip install flask --break-system-packages
    python3 app.py
Then browse to http://192.168.x.x:5000 (see README for finding your LAN IP)

How the CTF works: exploiting a vulnerability correctly makes its response
carry a hidden flag — almost always in a response HEADER, sometimes in the
body — never in the visible page UI. You won't see flags by just clicking
around; you have to inspect real responses (curl -i, curl -v, or Burp).
Collect flags, then submit them at /flags to track progress.
"""

import base64
import re
import time
import uuid
from collections import deque, defaultdict

from flask import Flask, request, render_template, redirect, make_response, session, jsonify

app = Flask(__name__)
app.secret_key = "dev-only-not-a-real-secret"

# ---------------------------------------------------------------------------
# In-memory "database"
# ---------------------------------------------------------------------------

USERS = {
    "demo@verafi.io": {
        "id": 1, "email": "demo@verafi.io", "password": "Demo@1234",
        "nickname": "Demo User", "role_id": 2, "role": "user", "balance": 4820.55,
    },
    "priya.rao@verafi.io": {
        "id": 2, "email": "priya.rao@verafi.io", "password": "Priya@9821",
        "nickname": "Priya R", "role_id": 2, "role": "user", "balance": 15320.10,
    },
    "admin@verafi.io": {
        "id": 99, "email": "admin@verafi.io", "password": "R00tAdmin!2026",
        "nickname": "Ops Admin", "role_id": 1, "role": "admin", "balance": 0,
    },
}
NEXT_UID = 100

OTP_STORE = {}
MASTER_OTP = "000000"
LOGIN_ATTEMPTS = defaultdict(int)          # keyed by client-supplied XFF
REAL_IP_ATTEMPTS = defaultdict(int)        # keyed by actual remote_addr
SEEN_XFF_PER_IP = defaultdict(set)

DEVICE_CACHE = {}
CACHE_TTL = 60

SECURITY_LOG = deque(maxlen=30)
FRAUD_BOT_LOG = deque(maxlen=20)
SEARCH_HISTORY = deque(maxlen=8)

RATE_TEST_COUNTS = defaultdict(int)
RATE_TEST_THRESHOLD = 8

# ---------------------------------------------------------------------------
# CTF layer — every flag is delivered via a response header on the exact
# request that proves the vulnerability, never printed on the visible page.
# ---------------------------------------------------------------------------

FLAGS = {
    "robots_disclosure":       "VERAFI{r0b0ts_d0t_txt_map5_y0ur_att4ck_surf4ce}",
    "source_disclosure":       "VERAFI{b4ckup_f1les_l3ak_pr0d_s3cr3ts}",
    "git_disclosure":          "VERAFI{exp0sed_dotgit_1s_free_r3c0n}",
    "cookie_role_bypass":      "VERAFI{cl13nt_cook13s_ar3_n0t_4uth}",
    "idor":                    "VERAFI{1ncrement1ng_1ds_1s_st1ll_1d0r}",
    "mass_assignment":         "VERAFI{r0le_1d_sh0uld_never_be_cl13nt_s3t}",
    "otp_exposure":            "VERAFI{d3bug_0tp_1n_pr0d_r3sp0nse}",
    "otp_bypass":              "VERAFI{m4ster_0tp_l3ft_1n_fr0m_qa}",
    "predictable_reset_token": "VERAFI{b4se64_1s_n0t_encrypt10n}",
    "account_takeover":        "VERAFI{ch41ned_bugs_eq_full_t4keover}",
    "twofa_bypass":            "VERAFI{f0rced_br0ws1ng_sk1ps_2fa}",
    "email_takeover":          "VERAFI{n0_reauth_n0_conf1rm4t10n}",
    "captcha_exposure":        "VERAFI{h1dden_h3ader_l3aks_captcha_l0g1c}",
    "captcha_bypass":          "VERAFI{fake_turnst1le_never_c4lls_s1teverify}",
    "no_rate_limit_login":     "VERAFI{unl1m1ted_l0g1n_att3mpts}",
    "no_rate_limit_otp":       "VERAFI{unl1m1ted_0tp_att3mpts}",
    "no_rate_limit_forgot":    "VERAFI{unl1m1ted_f0rg0t_pw_requests}",
    "no_rate_limit_reset":     "VERAFI{unl1m1ted_reset_requests}",
    "ip_spoof_bypass":         "VERAFI{xff_1s_cl13nt_c0ntr0lled}",
    "null_byte":               "VERAFI{val1dat0r_and_h4ndler_d1sagree}",
    "reflected_xss_basic":     "VERAFI{plain_0l_reflected_xss}",
    "filtered_xss_bypass":     "VERAFI{bl4cklists_alw4ys_m1ss_s0meth1ng}",
    "limited_input_xss":       "VERAFI{cl13nt_s1de_regex_1s_n0t_a_c0ntr0l}",
    "email_validator_xss":     "VERAFI{unanch0red_regex_str1kes_ag41n}",
    "header_stored_xss":       "VERAFI{1nternal_d4shb0ards_trust_headers}",
    "reflected_header_xss":    "VERAFI{referer_1s_user_c0ntr0lled}",
    "cache_hit_xss":           "VERAFI{p01soned_cache_serv3d_t0_others}",
    "url_based_xss":           "VERAFI{404_p4ges_reflect_t00}",
    "bot_xss":                 "VERAFI{the_b0t_0perat0r_1s_the_v1ct1m}",
}

SOLVED = defaultdict(set)   # player_id -> set of solved challenge ids


def player_id():
    return request.cookies.get("player_id") or str(uuid.uuid4())


def naive_filter(value: str) -> str:
    for bad in ("<script", "onerror=", "onload=", "javascript:"):
        value = re.sub(re.escape(bad), "", value, flags=re.IGNORECASE)
    return value


EMAIL_SERVER_REGEX = re.compile(r"[A-Za-z0-9.@]+")   # unanchored — VULN
NICK_SERVER_REGEX = re.compile(r"[A-Za-z0-9 ]+")      # unanchored — VULN
OTP_FORMAT_REGEX = re.compile(r"^\d{6}$")
TURNSTILE_TOKEN_REGEX = re.compile(r"^[A-Za-z0-9._-]{20,}$")
EVENT_HANDLER_REGEX = re.compile(r"<[a-z]+[^>]*\son[a-z]+\s*=", re.IGNORECASE)


def current_user():
    return USERS.get(session.get("email"))


def log_headers(path):
    SECURITY_LOG.appendleft({
        "id": str(uuid.uuid4())[:8], "ts": time.strftime("%H:%M:%S"), "path": path,
        "user_agent": request.headers.get("User-Agent", ""),
        "referer": request.headers.get("Referer", ""),
        "x_forwarded_for": request.headers.get("X-Forwarded-For", ""),
        "accept_language": request.headers.get("Accept-Language", ""),
    })


def rate_bump(name):
    key = (name, request.remote_addr)
    RATE_TEST_COUNTS[key] += 1
    return RATE_TEST_COUNTS[key]


# ---------------------------------------------------------------------------
# CTF meta pages
# ---------------------------------------------------------------------------

@app.route("/flags", methods=["GET", "POST"])
def flags_page():
    pid = player_id()
    message = None
    if request.method == "POST":
        submitted = request.form.get("flag", "").strip()
        matched = None
        for cid, flag in FLAGS.items():
            if submitted == flag:
                matched = cid
                break
        if matched:
            SOLVED[pid].add(matched)
            message = ("correct", matched)
        elif submitted:
            message = ("wrong", None)

    solved = SOLVED[pid]
    resp = make_response(render_template(
        "flags.html", challenge_ids=sorted(FLAGS.keys()), solved=solved,
        total=len(FLAGS), solved_count=len(solved), message=message,
    ))
    resp.set_cookie("player_id", pid)
    return resp


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        "Disallow: /admin-panel-x7q\n"
        "Disallow: /source-backup\n"
        "Disallow: /.git/config\n"
        "Disallow: /api/\n"
        "Disallow: /internal/\n"
    )
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain"
    resp.headers["X-Verafi-Flag"] = FLAGS["robots_disclosure"]
    return resp


@app.route("/source-backup")
def source_backup():
    fake_source = (
        "# .env.backup — DO NOT COMMIT (someone did)\n"
        "DB_HOST=verafi-prod-db-internal.ap-south-1.rds.local\n"
        "DB_USER=verafi_svc\n"
        "DB_PASS=Tr0ub4dor&3-prod\n"
        "JWT_SECRET=b7f3c1e2a9d4f6e8c0b1a2d3e4f5061728394a5b\n"
        "OTP_MASTER_OVERRIDE=000000  # QA bypass, remove before GA (never removed)\n"
    )
    resp = make_response(fake_source, 200)
    resp.headers["Content-Type"] = "text/plain"
    resp.headers["X-Verafi-Flag"] = FLAGS["source_disclosure"]
    return resp


@app.route("/.git/config")
def git_config():
    fake_git = (
        "[remote \"origin\"]\n"
        "  url = https://gitlab.internal.verafi.io/platform/verafi-web.git\n"
        "[user]\n  email = deploy-bot@verafi.io\n"
    )
    resp = make_response(fake_git, 200)
    resp.headers["Content-Type"] = "text/plain"
    resp.headers["X-Verafi-Flag"] = FLAGS["git_disclosure"]
    return resp


# ---------------------------------------------------------------------------
# Login — realistic fake captcha, spoofable rate limit, weak session
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        resp = make_response(render_template("login.html", error=None))
        resp.headers["X-Verafi-Debug"] = "captcha-verification-mode=client-side-only"
        resp.headers["X-Verafi-Flag"] = FLAGS["captcha_exposure"]
        return resp

    error = None
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    turnstile_token = request.form.get("cf-turnstile-response", "")

    count = rate_bump("login")

    if not turnstile_token or not TURNSTILE_TOKEN_REGEX.match(turnstile_token):
        error = "Please complete the human verification check."
        return render_template("login.html", error=error)

    key = request.headers.get("X-Forwarded-For", request.remote_addr)
    real_ip = request.remote_addr
    SEEN_XFF_PER_IP[real_ip].add(key)

    if LOGIN_ATTEMPTS[key] >= 5:
        error = "Too many attempts from your network. Try later."
        resp = make_response(render_template("login.html", error=error))
        if count > RATE_TEST_THRESHOLD:
            resp.headers["X-Verafi-Flag"] = FLAGS["no_rate_limit_login"]
        return resp

    user = USERS.get(email)
    if user and user["password"] == password:
        session["email"] = email
        session["pending_2fa"] = True
        resp = make_response(redirect("/2fa-verify"))
        resp.set_cookie("role", user["role"])
        resp.set_cookie("uid", str(user["id"]))

        resp.headers["X-Verafi-Flag"] = FLAGS["captcha_bypass"]
        if REAL_IP_ATTEMPTS[real_ip] >= 6 and len(SEEN_XFF_PER_IP[real_ip]) >= 2:
            resp.headers["X-Verafi-Flag"] = FLAGS["ip_spoof_bypass"]
        return resp
    else:
        LOGIN_ATTEMPTS[key] += 1
        REAL_IP_ATTEMPTS[real_ip] += 1
        error = "Invalid email or password."
        resp = make_response(render_template("login.html", error=error))
        if count > RATE_TEST_THRESHOLD:
            resp.headers["X-Verafi-Flag"] = FLAGS["no_rate_limit_login"]
        return resp


@app.route("/2fa-verify", methods=["GET", "POST"])
def twofa_verify():
    if "email" not in session:
        return redirect("/login")
    error = None
    if request.method == "POST":
        code = request.form.get("code", "")
        if code == MASTER_OTP or code == "111111":
            session["pending_2fa"] = False
            return redirect("/dashboard")
        error = "Incorrect authentication code."
    return render_template("twofa.html", error=error)


# ---------------------------------------------------------------------------
# Dashboard — 2FA bypass, cache-based XSS (status lives only in headers)
# ---------------------------------------------------------------------------

@app.route("/dashboard")
def dashboard():
    if "email" not in session:
        return redirect("/login")
    user = current_user() or USERS["demo@verafi.io"]
    was_pending_2fa = session.get("pending_2fa", False)

    now = time.time()
    cache_key = "device-widget"
    cached = DEVICE_CACHE.get(cache_key)
    cache_status = "HIT"
    if not cached or now - cached["ts"] > CACHE_TTL:
        ua = request.headers.get("User-Agent", "unknown device")
        DEVICE_CACHE[cache_key] = {"html": ua, "ts": now}
        cache_status = "MISS"
        cached = DEVICE_CACHE[cache_key]

    resp = make_response(render_template("dashboard.html", user=user, device_html=cached["html"]))
    resp.headers["X-Cache"] = cache_status

    if was_pending_2fa:
        resp.headers["X-Verafi-Flag"] = FLAGS["twofa_bypass"]
    elif "<" in user.get("nickname", ""):
        resp.headers["X-Verafi-Flag"] = FLAGS["limited_input_xss"]
    elif "<" in user.get("email", ""):
        resp.headers["X-Verafi-Flag"] = FLAGS["email_validator_xss"]
    elif cache_status == "HIT" and "<" in cached["html"]:
        resp.headers["X-Verafi-Flag"] = FLAGS["cache_hit_xss"]

    return resp


# ---------------------------------------------------------------------------
# Forgot password / OTP / reset — the account-takeover chain
# ---------------------------------------------------------------------------

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    debug_otp = None
    sent = False
    flag_to_set = None
    if request.method == "POST":
        email = request.form.get("email", "")
        count = rate_bump("forgot-password")
        otp = f"{uuid.uuid4().int % 1000000:06d}"
        OTP_STORE[email] = {"otp": otp, "ts": time.time()}
        sent = True
        debug_otp = otp
        flag_to_set = FLAGS["otp_exposure"]
        if count > RATE_TEST_THRESHOLD:
            flag_to_set = FLAGS["no_rate_limit_forgot"]
    resp = make_response(render_template("forgot_password.html", sent=sent, debug_otp=debug_otp))
    if flag_to_set:
        resp.headers["X-Verafi-Flag"] = flag_to_set
    return resp


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    error = None
    email = request.values.get("email", "")
    flag_to_set = None
    if request.method == "POST":
        submitted = request.form.get("otp", "")
        dev_override = request.form.get("dev_override", "false")
        count = rate_bump("verify-otp")

        if not OTP_FORMAT_REGEX.match(submitted):
            error = "Invalid code format — must be 6 digits."
        else:
            record = OTP_STORE.get(email)
            bypassed = (submitted == MASTER_OTP) or (dev_override == "true")
            correct = record and submitted == record["otp"]
            if bypassed or correct:
                token = base64.b64encode(email.encode()).decode()
                resp = make_response(redirect(f"/reset-password?token={token}"))
                if bypassed:
                    resp.headers["X-Verafi-Flag"] = FLAGS["otp_bypass"]
                if count > RATE_TEST_THRESHOLD:
                    resp.headers["X-Verafi-Flag"] = FLAGS["no_rate_limit_otp"]
                return resp
            error = "Incorrect code."
        if count > RATE_TEST_THRESHOLD:
            flag_to_set = FLAGS["no_rate_limit_otp"]

    resp = make_response(render_template("verify_otp.html", email=email, error=error))
    if flag_to_set:
        resp.headers["X-Verafi-Flag"] = flag_to_set
    return resp


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    error = None
    done = False
    token = request.values.get("token", "")
    try:
        email = base64.b64decode(token.encode()).decode()
    except Exception:
        email = ""

    flag_to_set = None
    if request.method == "POST":
        new_password = request.form.get("password", "")
        count = rate_bump("reset-password")
        if email in USERS and new_password:
            USERS[email]["password"] = new_password
            done = True
            flag_to_set = FLAGS["predictable_reset_token"]
            if email != session.get("email"):
                flag_to_set = FLAGS["account_takeover"]
            if count > RATE_TEST_THRESHOLD:
                flag_to_set = FLAGS["no_rate_limit_reset"]
        else:
            error = "Invalid or expired reset link."

    resp = make_response(render_template("reset_password.html", email=email, error=error, done=done))
    if flag_to_set:
        resp.headers["X-Verafi-Flag"] = flag_to_set
    return resp


# ---------------------------------------------------------------------------
# Email takeover + IDOR + mass assignment
# ---------------------------------------------------------------------------

@app.route("/change-email", methods=["GET", "POST"])
def change_email():
    if "email" not in session:
        return redirect("/login")
    user = current_user()
    error = None
    done = False
    flag_to_set = None
    if request.method == "POST":
        new_email = request.form.get("new_email", "")
        if new_email and user:
            old_email = user["email"]
            user["email"] = new_email
            USERS[new_email] = user
            del USERS[old_email]
            session["email"] = new_email
            done = True
            flag_to_set = FLAGS["email_takeover"]
        else:
            error = "Enter a new email."
    resp = make_response(render_template("change_email.html", error=error, done=done, user=user))
    if flag_to_set:
        resp.headers["X-Verafi-Flag"] = flag_to_set
    return resp


@app.route("/api/user/<int:uid>")
def api_user(uid):
    for u in USERS.values():
        if u["id"] == uid:
            resp = jsonify(u)
            resp.headers["X-Verafi-Flag"] = FLAGS["idor"]
            return resp
    return jsonify({"error": "not found"}), 404


@app.route("/api/profile/update", methods=["POST"])
def api_profile_update():
    if "email" not in session:
        return jsonify({"error": "unauthorized"}), 401
    user = current_user()
    data = request.get_json(silent=True) or {}
    was_admin_before = user.get("role") == "admin"
    for k, v in data.items():
        if k in user:
            user[k] = v
    if user.get("role_id") == 1:
        user["role"] = "admin"
    resp = jsonify(user)
    if user.get("role") == "admin" and not was_admin_before:
        resp.headers["X-Verafi-Flag"] = FLAGS["mass_assignment"]
    return resp


# ---------------------------------------------------------------------------
# Admin surfaces — protected only by the client-editable cookie
# ---------------------------------------------------------------------------

@app.route("/admin-panel-x7q")
def admin_panel():
    role = request.cookies.get("role", "guest")
    if role != "admin":
        return render_template("403.html"), 403
    resp = make_response(render_template("admin_panel.html", users=USERS.values(), logs=list(SECURITY_LOG)))
    resp.headers["X-Verafi-Flag"] = FLAGS["cookie_role_bypass"]
    combined = "".join(
        l.get("user_agent", "") + l.get("referer", "") + l.get("x_forwarded_for", "") + l.get("accept_language", "")
        for l in SECURITY_LOG
    )
    if "<" in combined:
        resp.headers["X-Verafi-Flag"] = FLAGS["header_stored_xss"]
    return resp


@app.route("/internal/fraud-bot-log")
def fraud_bot_log_page():
    role = request.cookies.get("role", "guest")
    if role != "admin":
        return render_template("403.html"), 403
    resp = make_response(render_template("fraud_bot_log.html", bot_log=list(FRAUD_BOT_LOG)))
    if any("<" in l.get("snippet", "") for l in FRAUD_BOT_LOG):
        resp.headers["X-Verafi-Flag"] = FLAGS["bot_xss"]
    return resp


# ---------------------------------------------------------------------------
# XSS zoo
# ---------------------------------------------------------------------------

@app.route("/search")
def search():
    q = request.args.get("q", "")
    SEARCH_HISTORY.appendleft(q)
    resp = make_response(render_template("search.html", q=q, mode="open", history=list(SEARCH_HISTORY)))
    if "<" in q:
        resp.headers["X-Verafi-Flag"] = FLAGS["reflected_xss_basic"]
    return resp


@app.route("/secure-search")
def secure_search():
    q = request.args.get("q", "")
    filtered = naive_filter(q)
    resp = make_response(render_template("search.html", q=filtered, mode="filtered", history=[]))
    if EVENT_HANDLER_REGEX.search(filtered) or "<script" in filtered.lower():
        resp.headers["X-Verafi-Flag"] = FLAGS["filtered_xss_bypass"]
    return resp


@app.route("/transactions")
def transactions():
    referer = request.headers.get("Referer", "")
    log_headers("/transactions")
    filt = request.args.get("filter", "All transactions")
    resp = make_response(render_template("transactions.html", referer=referer, filt=filt))
    if "<" in referer:
        resp.headers["X-Verafi-Flag"] = FLAGS["reflected_header_xss"]
    return resp


@app.route("/submit-link", methods=["GET", "POST"])
def submit_link():
    done = False
    if request.method == "POST":
        url = request.form.get("url", "")
        snippet = request.form.get("page_snippet", "")
        FRAUD_BOT_LOG.appendleft({"id": str(uuid.uuid4())[:8], "url": url,
                                    "snippet": snippet, "ts": time.strftime("%H:%M:%S")})
        done = True
    return render_template("submit_link.html", done=done)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    global NEXT_UID
    error = None
    if request.method == "POST":
        email = request.form.get("email", "")
        nickname = request.form.get("nickname", "")
        password = request.form.get("password", "")

        if not EMAIL_SERVER_REGEX.search(email) or not password:
            error = "Enter a valid email and password."
        else:
            uid = NEXT_UID
            NEXT_UID += 1
            USERS[email] = {"id": uid, "email": email, "password": password,
                              "nickname": nickname, "role_id": 2, "role": "user", "balance": 0}
            session["email"] = email
            session["pending_2fa"] = False
            return redirect("/dashboard")
    return render_template("signup.html", error=error)


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    check_target = filename.split("\x00")[0] if "\x00" in filename else filename
    allowed = check_target.lower().endswith((".pdf", ".png", ".jpg"))
    resp = jsonify({
        "requested_file": filename, "validated_against": check_target,
        "extension_check_passed": allowed,
    })
    if "\x00" in filename and allowed and not filename.lower().endswith((".pdf", ".png", ".jpg")):
        resp.headers["X-Verafi-Flag"] = FLAGS["null_byte"]
    return resp


@app.errorhandler(404)
def not_found(e):
    resp = make_response(render_template("404.html", path=request.path), 404)
    if "<" in request.path:
        resp.headers["X-Verafi-Flag"] = FLAGS["url_based_xss"]
    return resp


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
