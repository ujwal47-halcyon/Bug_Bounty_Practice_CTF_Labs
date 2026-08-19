# Pizza Kingdom — Vulnerable Lab App

A deliberately vulnerable pizza-ordering site for bug bounty / web pentest
practice. **Local use only — never deploy this publicly or point it at
real users.**

## Setup

```bash
cd pizzakingdom
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Runs on `http://0.0.0.0:5000` — from your Kali VM, hit it via your host's
LAN IP the same way you've been doing for the other Flask labs, so Burp
can intercept it properly.

## Seeded demo accounts

| Email | Password |
|---|---|
| victim@example.com | password123 |
| attacker@example.com | password123 |

## What to do

Don't peek at `VULNERABILITIES.md` first — try to find the bugs blind like
a real target, then check your findings against it and practice writing
each one up as a proper report (summary, repro steps, impact, severity,
fix).

Covers: OTP exposure, OTP bypass, CAPTCHA exposure, CAPTCHA bypass, no
rate limiting on OTP/login, account takeover via reset-email
manipulation, predictable/reusable password reset tokens, IDOR on
profile and order endpoints, and unauthenticated privilege escalation.

## Resetting state

Delete `pizzakingdom.db` and restart the app to get a fresh database with
the two seeded accounts and demo orders.
