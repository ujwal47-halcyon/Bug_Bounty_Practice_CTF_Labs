# Pizza Kingdom — Vulnerability Map

Use this as an answer key once you've found things yourself — try blind first,
then check here. For each one, practice writing it up like a real bounty
report: summary, steps to reproduce, impact, CVSS/P-rating, fix.

---

### VULN-01 — OTP Exposure (Registration flash message)
**Where:** `POST /register`
**Bug:** the OTP is echoed back in the flash message shown after signup.
**Real-world analogue:** dev/debug code left in prod that logs or returns
OTPs meant only for SMS delivery.
**Try:** register a new account, view the OTP directly on the confirmation
page (or in the raw HTTP response in Burp) without ever touching a phone.

### VULN-01b — OTP Exposure via API
**Where:** `POST /api/resend-otp`
**Bug:** returns `{"otp": "1234"}` directly in the JSON response.
**Try:** trigger "Resend OTP" on the verify page, check Burp's HTTP history
or the Network tab — no phone required.

### VULN-02 — OTP Bypass (master code)
**Where:** `POST /verify-otp`
**Bug:** `0000` is a hardcoded backdoor that verifies *any* account.
**Try:** register any account, submit `0000` at the OTP screen.

### VULN-05 — No Rate Limit on OTP
**Where:** `POST /verify-otp`
**Bug:** unlimited submission attempts against a 4-digit (10,000-value)
keyspace, no lockout, no delay, no CAPTCHA step-up after failures.
**Try:** script a loop (Burp Intruder / simple `requests` script) posting
0000–9999 until one hits (or note it's trivially automatable even before
factoring in VULN-02).

### VULN-03 — CAPTCHA Exposure
**Where:** `GET/POST /login`
**Bug:** the expected captcha answer is rendered into a hidden `<input>`
in the page HTML instead of only being validated server-side.
**Try:** view page source, read `captcha_answer`'s value directly.

### VULN-04 — CAPTCHA Bypass
**Where:** `POST /login`
**Bug:** server compares the user's typed answer against the *user-supplied*
hidden field instead of a server-side session value — so an attacker can
submit any matching pair (`captcha_input=5&captcha_answer=5`) regardless of
what was actually shown, or fully automate login attempts by scripting the
form without ever solving the math.
**Try:** intercept the login POST in Burp, set both fields to the same
arbitrary number, replay repeatedly.

### VULN-05b — No Rate Limit on Login
**Where:** `POST /login`
**Bug:** no attempt counter, no lockout, no delay — once CAPTCHA is
bypassed (VULN-04), this is a clean path to credential stuffing / password
spraying against `victim@example.com` / `attacker@example.com` (seeded
demo accounts, password: `password123`).

### VULN-06 — Account Takeover via Reset-Email Redirection
**Where:** `POST /forgot-password`
**Bug:** accepts an optional `notify_email` parameter and "delivers" the
reset link there instead of to the actual account owner's registered
email — classic parameter-manipulation account takeover pattern seen in
real bug bounty programs.
**Try:** submit the victim's account email in `email`, and your own address
in `notify_email`. In this lab the "email" is simulated via an on-screen
flash message (see VULN-06b) so you can see the exfiltrated link directly.

### VULN-06b — Reset Link Leaked in HTTP Response
**Where:** `POST /forgot-password`
**Bug:** the full reset link (including token) is returned directly in the
response instead of only being sent out-of-band via email — meaning you
don't even need the `notify_email` trick above to get it.

### VULN-07 — Predictable Reset Token
**Where:** token generation in `forgot_password()`
**Bug:** `token = md5(email + "pizzakingdom_static_salt_2024")`. Anyone who
knows the static salt (e.g. leaked in a JS bundle, GitHub repo, or via
error messages elsewhere) can compute any user's reset token completely
offline, with zero interaction with the target server.
**Try:** compute the md5 yourself for `victim@example.com` and hit
`/reset-password/<token>` directly without ever calling `/forgot-password`.

### VULN-08 — Reset Token Reuse (not invalidated / no expiry)
**Where:** `POST /reset-password/<token>`
**Bug:** the token is never marked used and never expires, so a single
leaked/guessed token can reset the password repeatedly, indefinitely.

### VULN-09 — Weak/Hardcoded Session Secret
**Where:** `app.secret_key = "supersecret123"`
**Bug:** static, guessable Flask secret key — if exposed (e.g. via a public
repo), an attacker can forge signed session cookies.

### VULN-10 — IDOR on Profile
**Where:** `GET /profile/<user_id>`
**Bug:** only checks that *a* user is logged in, never that the logged-in
user owns the requested `user_id`. Sequential integer IDs make enumeration
trivial.
**Try:** log in as any account, then browse `/profile/1`, `/profile/2`, etc.

### VULN-11 — IDOR on Orders
**Where:** `GET /order/<order_id>`
**Bug:** same pattern — full order contents (items, delivery address,
total) for any user, accessible by any authenticated session just by
changing the ID in the URL.

### VULN-12 — Broken Access Control / Privilege Escalation
**Where:** `GET /api/debug/make-admin?user_id=<id>`
**Bug:** completely unauthenticated debug endpoint that grants admin rights
to any user ID. Combine with VULN-10/11-style ID enumeration to escalate
your own account, then access `/admin`.

### Bonus notes worth writing up
- `debug=True` in `app.run()` — Werkzeug debugger, if reachable, can lead
  to RCE in real deployments.
- No CSRF tokens anywhere — every state-changing form (checkout, reset,
  make-admin) is CSRF-able.
- Passwords hashed with unsalted SHA-256, not bcrypt/argon2 — offline
  cracking is fast if the DB ever leaks.

---

## Suggested practice workflow
1. Run the app, proxy everything through Burp (same LAN-IP workaround you
   already use for the other labs).
2. Try to find each bug *without* this file first — treat it like a real
   target.
3. For each one you confirm, write a mini report: title, severity (use
   real P-rating logic — think about actual business impact, not just
   "it's a bug"), reproduction steps, and a suggested fix.
4. Chain them: e.g. VULN-07 (predictable token) → account takeover →
   VULN-12 (unauth privilege escalation) → full admin panel access. Bounty
   programs pay much better for chained impact than isolated low-severity
   findings.
