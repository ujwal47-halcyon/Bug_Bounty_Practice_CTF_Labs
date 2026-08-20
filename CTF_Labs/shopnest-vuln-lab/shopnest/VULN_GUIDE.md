# VULN_GUIDE.md — ShopNest Exploitation Walkthroughs

Work through these roughly in order — several build on each other (the
cookie-role bug feeds into IDOR/admin access; the OTP leak feeds into 2FA
bypass). Try to find each one blind first, then use this to check yourself.

---

## 1. Clickjacking → sensitive-action hijack

**Root cause:** the app never sets `X-Frame-Options` or a `Content-Security-Policy: frame-ancestors` header (check `curl -I` on any page — it's just not there).

**Steps:**
1. Log in as `victim`, note their profile is at `/profile/5`.
2. Open `/clickjacking-demo` (this is your "attacker page" — imagine it's hosted on `evil-vouchers.example`).
3. It iframes `/profile/5` and overlays a decoy "Claim Voucher" button positioned over the real "Update email" button.
4. In a real attack you'd pre-fill the iframed form (e.g. via a query param your backend injects, or by scripting the iframe if same-origin isn't blocking you) so one click submits *your* email into the victim's account.
5. **Fix for the real world:** `X-Frame-Options: DENY` or `frame-ancestors 'none'`, plus SameSite cookies as defense in depth.

---

## 2 & 3. OTP bypass and exposure

Two separate bad patterns stacked together:

- `POST /api/send-otp` returns the OTP directly in the JSON body (`debug_otp`) — open DevTools → Network on the 2FA page and watch the "Resend code" request.
- `GET /api/debug/last-otp?username=<x>` is a leftover debug route with **no auth check at all**. Try `?username=victim` or `?username=charlie`.
- Even without either leak, the OTP is 4 digits and `POST /api/verify-otp` has no lockout — 10,000 requests via Burp Intruder will always land it eventually. Combine this with #11 below once you notice the counter never actually blocks you.

---

## 4, 5. CAPTCHA bypasses

- `GET /api/captcha` returns the plaintext answer in the JSON response (`alt_text_answer`) instead of only rendering it as an image server-side.
- `POST /api/captcha/verify` echoes the expected answer back on a *failed* attempt (`expected_for_debug`) — submit garbage once, read the real answer, submit again.
- On the login page, "I'm not a robot" is a plain checkbox that sets a hidden field via `onchange` in the HTML — there's no server-issued challenge/token at all. Proof: `curl` the login POST directly with `captcha_verified=true` hardcoded and skip the checkbox entirely.

---

## 6. Account takeover via predictable reset token

`POST /forgot-password` computes the reset token as `md5(username + "shopnest-static-pepper")` — deterministic, no expiry, no per-request nonce.

1. You don't even need the leaked link — if you know the pepper (or find it in `app.py`/`/backup.zip` in a real misconfigured deploy), you can compute a valid token for **any** username offline: `md5("victim" + "shopnest-static-pepper")`.
2. Visit `/reset-password?username=victim&token=<computed>` and set a new password. Full account takeover, no interaction from the victim.
3. **Fix:** random, single-use, short-lived tokens stored server-side and invalidated after use.

---

## 7. 2FA bypass via forced browsing

1. Log in as `charlie` (2FA-enabled). You'll land on `/2fa-verify`.
2. Instead of entering the code, try navigating directly to `/dashboard` or `/profile/4` — notice these only ever check `session['user_id']`, and depending on how your session evolved in earlier testing (e.g. a previous successful login you didn't fully log out of) that value can already be set, letting you skip the second factor entirely.
3. More reliably: the OTP itself is 4 digits with no lockout (see #2/#3) — brute force `/api/verify-otp` for charlie's session.
4. **Fix:** every session-protected route should check a `session['2fa_passed']` flag set only after successful OTP verification, and that flag should be scoped per-login, not reused.

---

## 8. Email takeover

`POST /profile/<uid>/change-email` updates the email for whatever `<uid>` is in the URL with:
- no check that `<uid>` matches the logged-in session user (see IDOR, #13), and
- no re-entry of the current password, and
- no confirmation link sent to the *old* email before the change takes effect.

Chain: find a victim's user id (IDOR on `/profile/<id>` lets you enumerate ids 1–N and read usernames), then `POST /profile/<id>/change-email` directly with your own email. Now trigger "forgot password" — the reset flow will happily talk to whichever email is on file.

---

## 9. Weak upload validation → path traversal

`POST /profile/<uid>/avatar` checks the extension with `filename.rsplit('.',1)[1]` and then saves the file using the **raw client-supplied filename**, unsanitised.

- Note: the classic PHP-era "null byte truncation" trick (`shell.php%00.jpg`) does **not** work against modern Python/Flask — Python strings don't truncate at `\x00` the way old C-backed PHP did. Worth confirming that for yourself rather than assuming old writeups still apply.
- What *does* still work here: send a multipart filename containing path traversal segments (e.g. `../../templates/product.html`) with an allowed extension trick, and see where Flask's `os.path.join` actually writes the file. This is the realistic 2026 version of "unsanitised filename" bugs — same impact class (arbitrary file write), different mechanism than the null-byte trick.
- **Fix:** use `werkzeug.utils.secure_filename()`, generate your own filename server-side, and validate actual file content (magic bytes), not just the extension string.

---

## 10 & 11. Missing rate limiting + spoofable "IP" tracking

Login, OTP verify, forgot-password, and reset-password all call `note_attempt()`, which increments a counter — but **nothing ever reads that counter to block a request**. Confirm with Burp Intruder: hammer `/api/verify-otp` and watch that nothing ever returns a lockout response.

Separately, `get_client_key()` trusts `X-Forwarded-For` outright with no check that the request came through an actual trusted proxy:

```
curl -X POST http://127.0.0.1:5000/login \
  -H "X-Forwarded-For: 203.0.113.7" \
  -d "username=alice&password=guess1&captcha_verified=true"
```

Rotate the header value on every request to reset whatever tracking key you're bucketed under, even if a real lockout *were* implemented naively. This mirrors a very common real-world misconfig: rate limiting keyed off a client-controlled header instead of the actual peer address (or a properly validated trusted-proxy chain).

**Fix:** enforce actual lockout/backoff server-side (e.g. Flask-Limiter with Redis), and only trust `X-Forwarded-For` when the direct peer is a known, trusted reverse proxy.

---

## 12. Broken access control

Several independent bugs, all under this umbrella:

- **Cookie role tampering:** after any login, a plain `role=<value>` cookie is set. `effective_role()` in `app.py` trusts this cookie *over* the session if present. In your browser devtools (Application → Cookies), change `role` to `admin` and reload — the admin nav item appears, and `/admin`, `/admin/promote/<id>` become reachable.
- **IDOR:** `/profile/<id>` and `/order/<id>` never check that `<id>` belongs to the requesting session — increment the id in the URL to read other users' data.
- **Source/backup disclosure:** view-source on any page — there's an HTML comment referencing `/backup.zip` and `/.git/config`, both of which resolve with real (simulated) content instead of 404.
- **Unauthenticated state-changing action:** `/admin/promote/<id>` has no CSRF token, so once you've got the role cookie set, a simple GET request is enough to grant yourself (or anyone) admin permanently in the DB.

**Fix:** never trust client-supplied cookies for authorization — derive role strictly from the server-side session; add ownership checks on every object-by-id route; remove debug/backup artifacts from the deployed app; add CSRF tokens to all state-changing requests.

---

## 13. XSS (stored, reflected, header-reflected)

- **Stored:** `/product/<id>` review form → the `content` field is rendered with Jinja's `|safe` filter, no escaping. Submit `<img src=x onerror=alert(document.cookie)>` or a `<script>` tag as a review — it fires for every future visitor to that product page. Compare this to the **product name** field on the same page, which *is* correctly auto-escaped — that inconsistency (some fields sanitised, others not) is deliberate and mirrors how real targets often only fix the fields someone already reported.
- **Reflected:** `/search?q=<script>...</script>` — the query string is echoed with `|safe` into the results heading.
- **Header-reflected:** `/admin/debug-headers` (reachable once you have the role cookie from #12) renders the raw `User-Agent` and `Referer` headers with `|safe`. If this page is ever visited by a real admin/support bot inspecting a "suspicious session," a crafted `User-Agent` on your own request could execute in *their* authenticated context — a nice illustration of why header values are still attacker-controlled input even though they don't look like a normal parameter.

**Fix:** never use `|safe` (or equivalent) on anything derived from user input, including request headers; rely on Jinja's default autoescaping; add a strict CSP as defense in depth.

---

## Suggested report structure once you've confirmed one of these

```
Title: <short, specific>
Severity/CVSS: <vector + score>
CWE: <id>
Component: <route/endpoint>
Steps to reproduce: <numbered>
Impact: <what an attacker actually gains>
Suggested fix: <one or two sentences>
```

Same format you're already using for the b1n0.com disclosures — good habit to keep consistent across lab and live-target work.
