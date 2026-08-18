# NovaBank Secure Portal (Local Practice Target)

A deliberately vulnerable, locally-hosted banking-style web app for your own
bug bounty / pentest practice. Built to look like a legitimate consumer bank
login portal, with realistic (not obviously flagged) logic bugs across
2FA, OTP handling, CAPTCHA, account recovery, and clickjacking.

**Run this only on `127.0.0.1`, only on your own machine. Do not deploy it
to any shared network, VPS, or the public internet — it is intentionally
insecure.**

## Setup

```bash
cd novabank
pip install -r requirements.txt
python3 seed.py      # one-time: creates novabank.db + 3 dummy client accounts
python3 app.py        # starts on http://127.0.0.1:5000
```

Then open `http://127.0.0.1:5000` in your browser.

- Register your own account at `/register` — this is your primary test account.
- The 3 seeded dummy clients (`sarah.mendes`, `raj.kapoor`, `emily.chen`)
  have randomly generated passwords that are hashed and never printed
  anywhere — including by `seed.py` itself. You're meant to reach them
  through the app's vulnerabilities (account takeover / IDOR), not by
  reading the database file.
- Two of the three dummy accounts have 2FA enabled; one doesn't — useful
  for testing both the MFA-bypass paths and the plain login flow.

## What's in scope

Everything in this app. It's your own local instance — go at it exactly
like a real target: use Burp/ZAP as a proxy, inspect requests/responses,
try the browser devtools console, view page source, tamper with
parameters, etc.

## Layout

```
novabank/
  app.py                  Flask app (all routes/logic)
  seed.py                 One-time DB seed script
  requirements.txt
  templates/              Jinja2 HTML templates
  static/style.css
  clickjack_poc/
    attacker.html         Standalone clickjacking PoC page (open directly in browser)
  novabank.db              Created after you run seed.py
```

## Suggested practice order

1. Recon the app manually first — click through every page, note every
   request in your proxy, before touching `SPOILERS.md`.
2. Try to find each of these on your own:
   - CAPTCHA bypass (two different bugs)
   - OTP bypass (two different bugs)
   - 2FA bypass (two different bugs)
   - Account takeover via password reset
   - IDOR on a profile/data endpoint
   - Clickjacking on an authenticated page
3. Only open `SPOILERS.md` once you're stuck or want to verify what you found.

## Resetting

Delete `novabank.db` and rerun `python3 seed.py` to start fresh (this wipes
your own registered account too).

## Notes

- Sessions use Flask's default signed-cookie sessions with a hardcoded
  `secret_key` — fine for local practice, never do this in production.
- There is no rate limiting anywhere in this app (also intentional — it
  makes some of the bugs easier to explore, e.g. brute-forcing OTPs or
  CAPTCHA answers).
- `debug=True` is set in `app.py`, so Flask's interactive debugger is
  active. Again: local-only, never expose this.
