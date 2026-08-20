# ShopNest — Vulnerable E-Commerce Lab (2026 build)

A realistic-looking e-commerce storefront built specifically for you to practice
bug bounty methodology against. **Local use only — never deploy this publicly.**

## Run it

```bash
cd shopnest
pip install -r requirements.txt
python3 app.py
```

Visit `http://127.0.0.1:5000`. The SQLite DB (`shopnest.db`) is auto-created
and reseeded from scratch every time you run `app.py` directly (delete it and
restart to reset state).

## Real email delivery (optional but recommended)

By default, password-reset links and OTP codes just show up on-page (fine
for quick testing). If you want them delivered to your actual Gmail inbox —
useful for practicing the full real-world flow — set up SMTP:

1. `cp .env.example .env`
2. Generate a **Gmail App Password** (not your normal Gmail password —
   Google blocks plain-password SMTP logins):
   - Go to your Google Account → **Security**
   - Turn on **2-Step Verification** if it isn't already on (required for App Passwords)
   - Go to **Security → App passwords** (or search "app passwords" in your account settings)
   - Create one named e.g. `shopnest-lab`, copy the 16-character password it gives you
3. Edit `.env`:
   ```
   GMAIL_ADDRESS=youraccount@gmail.com
   GMAIL_APP_PASSWORD=the 16-char app password (spaces are fine)
   NOTIFY_EMAIL=youraccount@gmail.com
   ```
   `GMAIL_ADDRESS` is the account that sends the mail. `NOTIFY_EMAIL` is
   where it lands — set it to whichever inbox you actually want to check
   (can be the same address, or any address you own).
4. Restart `python3 app.py`. Password reset links (from `/forgot-password`)
   and OTP codes (from the 2FA flow) will now also be emailed for real, in
   addition to still showing on-page.

If `.env` is missing or incomplete, the app just skips sending and falls
back to on-page display — nothing breaks.

**Never commit your `.env`** — it's already in `.gitignore`. Since the app
password only allows SMTP sending (not full account access), the blast
radius if it ever leaked is small, but treat it like any other credential.

## Dummy accounts

| Username | Password     | Notes                          |
|----------|--------------|---------------------------------|
| admin    | Admin@123    | role=admin, target for privesc |
| alice    | Alice@123    | regular user, has orders/reviews |
| bob      | Bob@123      | regular user                   |
| charlie  | Charlie@123  | **2FA enabled** — for 2FA-bypass practice |
| victim   | Victim@2024  | target account for takeover/IDOR practice |

## What's in scope

Fourteen intentional, intermediate-difficulty vulnerability classes are wired
into this app — see **VULN_GUIDE.md** for the full walkthrough of each one
(what it is, where it lives, and how to exploit it step by step):

1. Clickjacking → sensitive-action hijack
2. OTP bypass (predictable/brute-forceable, unrate-limited)
3. OTP exposure via debug endpoint & API response
4. CAPTCHA image bypass (answer embedded in response)
5. Client-side-only "I'm not a robot" checkbox bypass
6. CAPTCHA exposer (answer leaked on failed verify)
7. Account takeover via predictable password-reset token
8. 2FA bypass via forced browsing
9. Email takeover (no re-auth / no confirmation)
10. Missing rate limiting on OTP / login / forgot-password / reset-password
11. Rate-limit bypass via spoofed `X-Forwarded-For` header
12. Null-byte-era file upload validation → path traversal
13. Broken access control: cookie role tampering, IDOR on profiles/orders,
    exposed source/backup files, hidden admin routes
14. XSS: stored (reviews), reflected (search), header-reflected (User-Agent
    on an admin debug tool)

Each is tagged `[VULN]` with a comment directly in `app.py` explaining the
flaw, so once you've tried to find something blind, you can go check your
reasoning against the code.

## Suggested workflow

1. **Recon first.** Crawl the site like you don't have the source: map every
   route, check `view-source:` on every page, poke at cookies, hit
   `/robots.txt`, look for comments in the HTML.
2. **Manual verification in Burp** before you believe anything — same habit
   you've been building with the b1n0.com work. A couple of these vulns
   *look* protected (rate-limit counters that never actually block, a 2FA
   step that still leaves a bypassable path) specifically so you practice
   telling real controls from decorative ones.
3. **Write it up like a real report** for at least 2–3 of these: repro
   steps, impact, CVSS/CWE, and a suggested fix. That's the muscle that
   actually transfers to eJPT/OSCP and to paid bounty work.
4. Reset the DB (`rm shopnest.db && python3 app.py`) between passes if state
   gets messy (e.g. after promoting a user to admin).
