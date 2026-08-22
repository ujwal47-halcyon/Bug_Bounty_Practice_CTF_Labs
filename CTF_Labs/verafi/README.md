# Verafi — Bug Bounty CTF

A realistic-looking digital banking app (Flask, 2026 fintech UI) wired up
as a capture-the-flag. It has real, working vulnerabilities across auth,
access control, and XSS. This README teaches you *how* to hunt — it does
not tell you what's broken or where. Find that yourself, the way you would
on a real program.

## Run it

```bash
pip install flask --break-system-packages
python3 app.py
hostname -I        # find your LAN IP
```
Browse to `http://192.168.x.x:5000` — not localhost, so it feels like a
real target and you can proxy it through Burp on another device if you want.

⚠️ `debug=True` means the Werkzeug debugger is live on that port — fine on
a home network you trust, never expose this beyond your router.

Demo account to start from: `demo@verafi.io` / `Demo@1234`.

---

## How the CTF works

- There are **29 flags**, one per distinct vulnerability.
- A flag looks like `VERAFI{...}`.
- **Flags are never printed anywhere in the visible page/UI.** They show up
  in the HTTP **response** on the exact request that proves you actually
  exploited the bug — almost always as a response header, sometimes you'll
  need to reason about what "proves" the exploit before you'll see one.
- This means clicking around in a browser will never reveal a flag by
  itself. You need to **look at raw responses** — `curl -i`, `curl -v`, or
  your proxy's history — the same habit you'll need on real programs where
  the interesting stuff (rate-limit counters, cache status, debug headers,
  auth logic) never shows up in the rendered page either.
- Submit flags at **`/flags`** — it tracks which of the 29 you've found.

## Where to start

Treat this exactly like a real engagement:
1. **Recon first.** Map the app manually — every page, every form, every
   link. Check for a `robots.txt`. Check for common leftover files
   (backups, version control folders). Don't skip this because it "feels
   like busywork" — on this target, recon directly unlocks later steps.
2. **Read every response fully**, not just the rendered page. `curl -i` a
   page you've already seen in the browser and compare — headers carry
   information the UI deliberately doesn't show you.
3. **Map the auth flow end-to-end** before attacking any single step:
   signup → login → any second factor → forgot password → OTP → reset.
   Real account-takeover chains almost always cross two or three of these
   steps, not just one.
4. **View source on every form.** Client-side JavaScript validation and
   hidden form fields are worth reading line by line — they often tell you
   exactly what the server is (wrongly) trusting.
5. **Test the obvious stuff too.** Rate limits, IDOR by incrementing an ID,
   a cookie you can just... edit. Real targets still have these.

---

## Doing XSS from the terminal — a proper walkthrough

You don't need a browser to find or prove most of these. Here's the
generalizable method.

### 1. Find a reflection point
Any GET parameter, POST field, or header value that shows up somewhere in
a later response is a candidate. Start by sending something harmless but
unique and see if it comes back:
```bash
curl -s "http://192.168.x.x:5000/some-endpoint?param=UNIQUESTRING123" | grep "UNIQUESTRING123"
```
If it reflects, move to a real payload.

### 2. Confirm it reflects *unescaped*
This is the whole ballgame. Compare:
```html
<!-- vulnerable -->
<div>UNIQUESTRING123<script>alert(1)</script></div>

<!-- safe -->
<div>UNIQUESTRING123&lt;script&gt;alert(1)&lt;/script&gt;</div>
```
`grep` for the raw tag, not just your marker string:
```bash
curl -s "http://192.168.x.x:5000/some-endpoint?param=<script>alert(1)</script>" \
  | grep -o '<script>alert(1)</script>'
```
A match means it came back raw. No match means it's encoded (safe) or the
input was stripped/filtered somewhere — test that next.

### 3. If it's filtered, find what's blocked vs. what's missed
Send a few different payload shapes and diff the output:
```bash
curl -s "http://192.168.x.x:5000/endpoint?q=<script>x</script>" | grep -o "endpoint.*"
curl -s "http://192.168.x.x:5000/endpoint?q=<img src=x onerror=alert(1)>" | grep -o "endpoint.*"
curl -s "http://192.168.x.x:5000/endpoint?q=<svg onload=alert(1)>" | grep -o "endpoint.*"
curl -s "http://192.168.x.x:5000/endpoint?q=<details open ontoggle=alert(1)>" | grep -o "endpoint.*"
```
Whichever one survives intact tells you exactly what the filter's
blacklist covers and what it forgot. Blacklists almost always forget
*something* — an uncommon tag, an uncommon event handler, a case variant.

### 4. Test headers the same way `curl -H` lets you
Any header can carry a payload — the server can't tell the difference
between a "real" header value and one you typed:
```bash
curl -s -H "Referer: <script>alert(1)</script>" http://192.168.x.x:5000/some-page
curl -s -A "<img src=x onerror=alert(1)>" http://192.168.x.x:5000/some-page
curl -s -H "X-Forwarded-For: 1.1.1.1<svg onload=alert(1)>" http://192.168.x.x:5000/some-page
```
Headers logged to an admin/ops page you can't directly reach on your own
are classic **stored** XSS — the "victim" is whoever opens that page, not
you. You may need to trigger the logging request first, then separately
load the page that renders the log.

### 5. Test what client-side JS won't let you type
Any form with JS-enforced character restrictions can be skipped entirely
by hitting the endpoint directly — the browser's checks never run if you
never load the browser:
```bash
curl -s -X POST http://192.168.x.x:5000/some-form \
  -d 'field=valid-looking-prefix"><script>alert(1)</script>&other_field=x'
```
Always **view-source the real form first** to get the exact field names —
don't guess them.

### 6. Prove execution, not just reflection
`grep` matching raw `<script>` tells you the payload *landed* unescaped.
It doesn't tell you it *ran*. To actually confirm:
- Open the response in a real browser and watch for the `alert()` dialog.
- Check DevTools Console for a CSP block — a raw reflection can still be
  neutralized by a Content-Security-Policy header.
- For pages you can't personally load (an internal log a bot/admin views),
  swap `alert(1)` for something you can independently verify received a
  hit, and only trust it once you've seen that hit.

### 7. Check response headers on *every* successful exploit
This is specifically relevant here: once you believe you've triggered a
bug — auth bypass, IDOR, injection, whatever — always run the triggering
request through `curl -i` or `curl -v` and read every header in the
response, not just the body. Don't assume a 200 status with a normal-
looking page means "nothing interesting happened."

---

## General technique reminders (not specific to this app)

- **`curl -i`** shows status + headers + body together — your default for
  "did something change server-side that the page doesn't show me."
- **`curl -c cookies.txt`** / **`curl -b cookies.txt`** to save/reuse a
  session across requests — most multi-step flows here need this.
- **`curl -X POST -d 'a=b&c=d'`** to hit form endpoints directly, bypassing
  any client-side JS.
- **`curl -H "Content-Type: application/json" -d '{"a":"b"}'`** for JSON
  APIs — check the real Content-Type in the browser's Network tab first.
- Loop constructs (`for i in $(seq 1 20); do curl ...; done`) are how you
  actually test whether something is rate-limited — one request never
  tells you that.

Good luck — 29 flags, `/flags` to track progress, no shortcuts in the
README on purpose.
