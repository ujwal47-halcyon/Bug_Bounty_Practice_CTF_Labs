# SPOILERS — Vulnerability Walkthrough

Try to find everything yourself first (see README's "suggested practice
order"). Use this to check your work or get unstuck.

## 1. CAPTCHA bypass — bug A: missing-parameter bypass
After 2 failed logins, `/login` shows a math captcha. The server only
validates the answer *if the field was submitted at all*:
```python
if submitted:
    if str(submitted) != str(correct):
        ...fail...
```
Intercept the login POST in Burp and delete the `captcha_answer` field
entirely (not just empty it — remove the key). The check is skipped and
the request proceeds as if the captcha passed.

## 2. CAPTCHA bypass — bug B: answer exposed in page source
The correct answer is rendered straight into the HTML as a hidden field:
```html
<input type="hidden" id="captcha-debug" value="...">
```
View source / inspect element on the login page to read it directly —
no need to actually solve the math.

## 3. OTP bypass — bug A: static backdoor code
`/verify-otp` accepts a hardcoded "debug" code regardless of the real
OTP: entering `000000` always succeeds, for any account with 2FA enabled.

## 4. OTP bypass — bug B: OTP exposed in response
Click "Resend code" on the OTP screen and check the Network tab / raw
response. The JSON response includes a `debug_otp` field containing the
real code that was just generated, in plaintext.

## 5. 2FA bypass — bug A: forced browsing / broken state machine
On `/login`, the server sets the authenticated session cookie (`user_id`)
immediately after the password check succeeds — before the OTP step. So
after entering a correct username/password for an MFA-enabled account,
instead of submitting an OTP, just navigate directly to `/dashboard`.
You're in.

## 6. 2FA bypass — bug B: client-trusted verification endpoint
There's an endpoint `/api/complete-2fa` intended to be called only by
front-end JS after a real OTP check. It performs no verification of its
own — it trusts whatever you send it:
```bash
curl -X POST http://127.0.0.1:5000/api/complete-2fa \
  -H "Content-Type: application/json" \
  -d '{"verified": true, "user_id": 1}' \
  -b "session=<your session cookie>"
```
This logs you in as whatever `user_id` you specify, without ever touching
a password or OTP — also usable as a straight account-takeover primitive
if you can guess/enumerate user IDs.

## 7. Account takeover via password reset (IDOR)
`/forgot-password` issues a valid reset token tied to *your own* email.
`/reset-password` checks that the token exists and hasn't been used or
expired — but never checks that the token was actually issued for the
`user_id` in the request. Request a reset for your own test account, then
on the reset-password submission, swap the `user_id` field to a victim's
id (e.g. try IDs 1, 2, 3 for the seeded dummy clients) while keeping your
own valid token. This resets the victim's password instead of yours.

## 8. IDOR — sensitive profile data exposure
`GET /api/profile/<id>` returns full profile JSON (email, account number,
balance, MFA status) for any user id, as long as you're logged in as
*someone* — no ownership check. Enumerate ids 1, 2, 3... to pull other
users' data.

## 9. Clickjacking
`/dashboard` and `/security` are deliberately excluded from
`X-Frame-Options` / CSP `frame-ancestors` protection (every other page has
it). Open `clickjack_poc/attacker.html` in the same browser where you're
logged in to NovaBank — it iframes `/security` invisibly under a decoy
"Claim your prize" button positioned over the real "Disable 2FA" button.
You'll need to tweak the iframe's `top`/`left` offsets in the PoC's
`<style>` block (temporarily set `opacity: 0.4` to align it visually,
then set it back to `0`) since exact pixel position depends on your
browser/OS rendering.

## Bug classes summary (for your notes)

| # | Category | Location |
|---|----------|----------|
| 1 | Broken auth logic (CAPTCHA) | `/login` |
| 2 | Sensitive data in page source (CAPTCHA) | `/login` |
| 3 | Weak/backdoor credential (OTP) | `/verify-otp` |
| 4 | Sensitive data exposure (OTP) | `/resend-otp` |
| 5 | Broken authentication state machine (2FA) | `/login` → `/dashboard` |
| 6 | Client-side trust / missing server verification (2FA) | `/api/complete-2fa` |
| 7 | IDOR → Account Takeover | `/reset-password` |
| 8 | IDOR → Data exposure | `/api/profile/<id>` |
| 9 | Clickjacking (missing frame protection) | `/dashboard`, `/security` |
