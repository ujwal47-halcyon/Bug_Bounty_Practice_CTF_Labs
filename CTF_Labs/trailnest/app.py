"""
TrailNest Gear — deliberately vulnerable e-commerce site for XSS practice.

⚠️ FOR LOCAL, AUTHORIZED PRACTICE ONLY. Every bug in this file is intentional
and documented in README.md. Do not deploy this anywhere public — it has
zero real security controls on purpose.

Run:
    pip install flask --break-system-packages
    python3 app.py
Then browse to http://127.0.0.1:5000
"""

import re
import time
import uuid
from collections import deque

from flask import (
    Flask, request, render_template, redirect, make_response,
    session, Response
)
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = "dev-only-not-a-real-secret"

# ---------------------------------------------------------------------------
# "Database" — everything in memory, reset on restart
# ---------------------------------------------------------------------------

PRODUCTS = {
    "1001": {"name": "Ridgeline 45L Pack", "price": 189.00,
              "desc": "A 45-liter backpacking pack built for multi-day trail routes.",
              "img": "pack"},
    "1002": {"name": "Alpine Storm Shell", "price": 129.00,
              "desc": "Waterproof shell jacket rated for sustained alpine weather.",
              "img": "jacket"},
    "1003": {"name": "Basecamp 2P Tent", "price": 249.00,
              "desc": "Freestanding two-person tent, 3-season, 2.3kg packed.",
              "img": "tent"},
    "1004": {"name": "Traverse Trail Runners", "price": 139.00,
              "desc": "Low-cut trail runners with a sticky rubber outsole.",
              "img": "shoes"},
}

USERS = {
    # seeded demo account
    "demo@trailnest.io": {"password": "demo1234", "email": "demo@trailnest.io",
                            "display_name": "Demo Hiker"}
}

# VULN #1 — "cache" of search terms shown in the homepage "Trending on TrailNest"
# widget. This simulates a page/edge cache that stores rendered fragments and
# serves them to every visitor until the TTL expires or an admin flushes it.
SEARCH_CACHE = deque(maxlen=8)     # list of {"q": ..., "ts": ...}
CACHE_TTL_SECONDS = 90

# VULN #2 — request log the "admin" dashboard renders, capturing raw headers
# from every request that hits /product/<id>. A real internal tool like this
# (support/ops dashboards, WAF log viewers, analytics panels) is a classic
# stored-XSS-via-headers sink.
REQUEST_LOG = deque(maxlen=25)

EMAIL_CLIENT_REGEX = r"^[A-Za-z0-9.@]+$"   # enforced in the browser only (see profile.html)
# VULN #3 — the server-side check below is intentionally weaker than the
# client-side one: it's missing anchors (^...$), so it only checks that the
# string *contains* something matching, not that the *whole* string matches.
EMAIL_SERVER_REGEX = re.compile(r"[A-Za-z0-9.@]+")


def naive_script_filter(value: str) -> str:
    """
    VULN #4 — a classic blacklist filter used on /search. It strips the
    literal substring '<script' case-insensitively and calls it a day.
    This is exactly the kind of filter real-world apps still ship, and it's
    trivially bypassed with alternate tags/event handlers/case tricks.
    """
    return re.sub(r"<script", "", value, flags=re.IGNORECASE)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    now = time.time()
    trending = [e for e in SEARCH_CACHE if now - e["ts"] < CACHE_TTL_SECONDS]
    return render_template("home.html", products=PRODUCTS, trending=trending,
                            cache_ttl=CACHE_TTL_SECONDS)


@app.route("/search")
def search():
    q = request.args.get("q", "")

    # naive blacklist filter — VULN #4, bypassable
    filtered = naive_script_filter(q)

    # reflected immediately on the results page...
    results = [p for p in PRODUCTS.values() if q.lower() in p["name"].lower()]

    # ...AND written into the shared cache that every visitor's homepage reads
    # from (VULN #1: cache-stored XSS). No per-user scoping, no encoding.
    if q:
        SEARCH_CACHE.appendleft({"q": filtered, "ts": time.time()})

    return render_template("search.html", q=filtered, results=results)


@app.route("/product/<pid>")
def product(pid):
    p = PRODUCTS.get(pid)
    if not p:
        return redirect("/error?msg=" + request.args.get("msg", "Product not found"))

    referer = request.headers.get("Referer", "")

    # VULN #5 — the referring page is echoed back on the product page
    # ("You arrived from: ...") without any encoding. An attacker who can
    # get a victim to click a link with a crafted Referer (or spoof it via
    # a meta-refresh/rel=noreferrer trick, or just via an intercepting
    # proxy during testing) gets script execution here.
    REQUEST_LOG.appendleft({
        "id": str(uuid.uuid4())[:8],
        "path": f"/product/{pid}",
        "ts": time.strftime("%H:%M:%S"),
        "user_agent": request.headers.get("User-Agent", ""),
        "referer": referer,
        "x_forwarded_for": request.headers.get("X-Forwarded-For", ""),
        "accept_language": request.headers.get("Accept-Language", ""),
    })

    return render_template("product.html", p=p, pid=pid, referer=referer)


@app.route("/admin/logs")
def admin_logs():
    # No auth check at all — deliberately. In the real world this is often
    # "protected" by an obscure URL or a client-side check only, which is
    # its own bug class worth practicing separately.
    return render_template("admin_logs.html", logs=list(REQUEST_LOG))


@app.route("/admin/cache/flush", methods=["POST"])
def admin_flush_cache():
    SEARCH_CACHE.clear()
    return redirect("/")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        display_name = request.form.get("display_name", "")

        # VULN #3 — server-side regex has no ^...$ anchors, so it just needs
        # to find *a* matching run of allowed chars somewhere in the string.
        # Anything can be appended after a valid-looking prefix.
        # e.g.  a@b.com"><img src=x onerror=alert(document.domain)>
        # -> the regex still matches on "a@b.com" and re.search() is happy,
        #    so the FULL raw string (including the payload) gets stored.
        if not EMAIL_SERVER_REGEX.search(email):
            error = "Please enter a valid email address."
        elif not email or not password:
            error = "Email and password are required."
        else:
            USERS[email] = {"password": password, "email": email,
                              "display_name": display_name}
            session["email"] = email
            return redirect("/profile")

    return render_template("signup.html", error=error)


@app.route("/profile")
def profile():
    email = session.get("email", "demo@trailnest.io")
    user = USERS.get(email, USERS["demo@trailnest.io"])
    return render_template("profile.html", user=user)


@app.route("/redirect")
def open_redirect():
    # VULN #6 — open redirect PLUS a reflected-XSS interstitial. The "next"
    # param drives both the http-equiv redirect target and the human-readable
    # message, and neither is encoded.
    next_url = request.args.get("next", "/")
    return render_template("redirecting.html", next_url=next_url)


@app.route("/error")
def error_page():
    # VULN #7 — plain reflected XSS via a query param, the "hello world" of
    # web XSS, kept here so the lab has a zero-friction warm-up target.
    msg = request.args.get("msg", "Something went wrong.")
    return render_template("error.html", msg=msg)


@app.route("/reset-password")
def reset_password():
    # VULN #8 — host header trust issue. The password-reset link is built
    # from X-Forwarded-Host (common behind reverse proxies / CDNs) instead
    # of a fixed, server-side configured hostname, and it's rendered
    # unescaped. Send a crafted X-Forwarded-Host and the "reset link" shown
    # to the "victim" carries your payload.
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "trailnest.io")
    token = str(uuid.uuid4())[:12]
    return render_template("reset_password.html", host=host, token=token)


if __name__ == "__main__":
    # 0.0.0.0 binds every interface, including your 192.168.x.x LAN IP, so
    # you can hit this from another device on the same network (e.g. a
    # separate attacker box, phone, or your Kali VM). debug=True gives you
    # the Werkzeug debugger AND arbitrary code execution to anyone who can
    # reach this port — fine on a private LAN you control, never anywhere
    # else. Run `hostname -I` or `ip a` to find your 192.168.x.x address.
    app.run(debug=True, host="0.0.0.0", port=5000)
