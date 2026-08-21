# TrailNest Gear — XSS Practice Lab

A small, realistic-looking outdoor-gear storefront built entirely as a **local
XSS training target**. Every bug below is intentional and lives in `app.py` /
`templates/*.html`. Nothing here talks to the internet — run it on
`127.0.0.1` only.

## Run it

```bash
pip install flask --break-system-packages
python3 app.py
```

Open `http://127.0.0.1:5000`. Use Burp/Caido as a proxy for everything below —
several of these bugs only show up once you stop trusting the browser UI and
start crafting raw requests.

### Reaching it from another device on your network

The app binds `0.0.0.0`, so it's also reachable at your machine's LAN
address:
```bash
hostname -I        # or: ip a
```
Find the `192.168.x.x` entry, then browse to `http://192.168.x.x:5000` from
your Kali VM, phone, or a second box. Useful for practicing multi-machine
scenarios — e.g. running Burp on one device against the app on another, or
testing bug #1/#2 (cache- and header-stored XSS) where "the visitor who
triggers it" being a genuinely separate device makes the stored-XSS story
more realistic than two tabs on the same machine.

⚠️ **`debug=True` means the Werkzeug interactive debugger is live on that
port.** On localhost that's harmless; exposed on a LAN, *anyone* who can
reach `192.168.x.x:5000` and trigger an unhandled exception gets a debugger
console with arbitrary Python execution — that's a real RCE, not a training
one. Fine on a home network you trust, but flip `debug=False` before
running this on anything shared (campus wifi, a co-working space, etc.), and
never forward the port past your router.

---

## 1. Cache-stored XSS — `/search?q=`

`SEARCH_CACHE` is a shared, in-memory list that every visitor's homepage
reads from (`Trending on TrailNest`). It has a 90-second TTL and no
per-user scoping — the closest single-process approximation of a real
edge/page cache (Varnish, Cloudflare cache, a Redis-backed fragment cache).

- Submit a payload once via search, and it sits live on the homepage for
  everyone until the TTL expires or `/admin/cache/flush` is hit.
- This maps to real bug classes: **cache poisoning** and **stored XSS via a
  shared rendering cache** — the kind of bug where "the request that plants
  it" and "the request that triggers it" are two different users, which is
  exactly why cache-based stored XSS pays well on programs that cache
  personalized or search-driven fragments.

Starter payload:
```
/search?q=<img src=x onerror=alert(document.domain)>
```

There's also a naive blacklist filter (`naive_script_filter`) on this
endpoint that strips the literal substring `<script` (case-insensitive) and
nothing else. It's a stand-in for the WAF/regex filters you'll actually meet
in the wild. Because `<img onerror>` doesn't contain `<script`, it already
bypasses it — but try breaking the filter itself too:
```
<ScRiPt>alert(1)</scRipt>          # case bypass if you close/reopen differently
<scr<script>ipt>alert(1)</scr</script>ipt>   # nested-tag bypass — filter runs once, non-recursively
<svg onload=alert(1)>
<body onload=alert(1)>
<a href=javascript:alert(1)>click</a>
```

## 2. Header-based stored XSS — `/admin/logs`

Every hit on `/product/<id>` logs raw `User-Agent`, `Referer`,
`X-Forwarded-For`, and `Accept-Language` into `REQUEST_LOG`, which
`/admin/logs` renders unescaped. No auth on the admin route either — a
second bug worth noting separately (broken access control), but the payload
itself is the header-XSS part.

```bash
curl -s http://127.0.0.1:5000/product/1001 \
  -A '<img src=x onerror=alert(document.cookie)>' \
  -H 'X-Forwarded-For: 1.1.1.1<svg onload=alert(2)>' \
  -H 'Accept-Language: en<script>alert(3)</script>'
```
Then load `/admin/logs`. This is the real-world pattern behind bugs found in
support dashboards, WAF/analytics log viewers, and abuse-report tooling that
render raw request metadata for a human reviewer — the "victim" is whoever
opens the internal tool, not the attacker.

## 3. Reflected header XSS — `/product/<id>` (Referer)

Same product page also echoes the *current* request's `Referer` directly
back to the requester ("You arrived here from: …"), no logging required:
```bash
curl -s http://127.0.0.1:5000/product/1001 -H 'Referer: <script>alert(1)</script>'
```
In the real world you can't always set an arbitrary `Referer` cross-origin
(browsers control it), so this class usually gets chained with an
open-redirect, a meta-refresh page you control, or a `rel` attribute trick —
good one to practice alongside bug #6.

## 4. DOM-based XSS via `location.hash` — `/product/<id>#...`

The "recently viewed" widget on the product page reads
`window.location.hash` client-side and drops it straight into `innerHTML`.
This never touches the server or the logs — pure client-side sink.
```
http://127.0.0.1:5000/product/1001#<img src=x onerror=alert(document.domain)>
```
Because it's a fragment, this is the one you'll deliver via a link (email,
DM, QR code) rather than find in any server log — a good reminder to always
check `#` and client-side routers, not just query strings.

## 5. Client-side-only validation bypass — `/signup` → `/profile`

The signup form restricts the email field to `[A-Za-z0-9.@]` **in
JavaScript only**. `EMAIL_SERVER_REGEX` on the server is real, but it's
built without `^`/`$` anchors, so `re.search()` just needs to find *a*
matching substring anywhere in the value — the full raw string (payload
included) still gets stored and later rendered unescaped on `/profile`.

Skip the browser entirely and hit the endpoint directly:
```bash
curl -s -X POST http://127.0.0.1:5000/signup \
  -d 'email=a@b.com"><script>alert(document.domain)</script>&password=demo1234&display_name=x' \
  -c cookies.txt
curl -s -b cookies.txt http://127.0.0.1:5000/profile
```
This is the single most common real-world "restricted input field" bug:
the restriction is enforced on the client, not the server. When a target
genuinely does validate email format server-side too, look for:
- a **different** endpoint that writes the same field without the check
  (e.g. a profile-*update* API vs. the signup form)
- unanchored/partial regexes (`re.search` vs `re.fullmatch`, missing `^$`,
  a regex that validates the *local part* but not what follows a rejected
  match)
- normalization order bugs — validated before decoding, rendered after
  decoding (double-encoding, Unicode normalization, IDN homograph tricks)
- the field being valid *as an email* but still exploitable in a non-HTML
  sink downstream — a mail template, a CSV export opened in Excel (formula
  injection), a log line parsed by another tool

## 6. Open redirect + reflected XSS — `/redirect?next=`

`next` drives both an HTML meta-refresh and a human-readable message,
neither encoded:
```
/redirect?next="><script>alert(1)</script>
```
Also plainly abusable as an open redirect on its own (`?next=https://evil.example`).
Chain it with bug #3: host the redirect on a page you control that sets a
crafted `Referer` on the next hop.

## 7. Reflected XSS — `/error?msg=`

The warm-up. No filtering at all:
```
/error?msg=<script>alert(1)</script>
```

## 8. Host-header trust → reflected XSS — `/reset-password`

Mirrors the very common "build absolute URLs from
`X-Forwarded-Host`/`Host` behind a reverse proxy" pattern. The header is
trusted and rendered unescaped into the "reset link" shown to the user:
```bash
curl -s http://127.0.0.1:5000/reset-password \
  -H 'X-Forwarded-Host: evil.com"><script>alert(document.domain)</script>'
```
In production this class usually shows up as password-reset-link
poisoning (attacker-controlled host ends up in an email sent to a victim) —
here it's simplified to a direct reflection so you can see the raw
mechanic before chasing the email-delivery version.

---

## On "balancing the payload"

A payload is "balanced" when it's the minimum that (a) survives whatever
filter/encoding is in front of it and (b) still executes in the actual
output context. Match the payload to the sink, in this order:

1. **Confirm the sink first.** View source / dev tools on the reflection.
   Are you inside a raw HTML body, an attribute value, a `<script>` string,
   an HTML comment, a JS template literal, a JSON blob later parsed by JS?
   Each needs a different escape sequence, not more angle brackets.
2. **Start minimal.** `"><svg onload=alert(1)>` before you reach for a full
   `<script>` tag — shorter payloads survive more filters and length caps,
   and event-handler attributes don't get blocked by naive `<script`
   blacklists (see bug #1).
3. **Add only what the filter forces you to add.** If `<` and `>` are
   stripped but attributes aren't, you may not need a tag at all — an
   existing attribute you can break into (`" autofocus onfocus=alert(1) x="`)
   is quieter than a new element.
4. **Encode one layer at a time.** HTML-entity encode, then URL-encode only
   if the value crosses a URL boundary, then check what the *server*
   decodes before validating vs. what it decodes before rendering — bugs
   live in that gap (validate-before-decode, render-after-decode).
5. **Prove impact, don't just pop an alert.** Once `alert(1)` fires, swap in
   something that demonstrates real impact for the report: `alert(document.domain)`
   to show origin, `fetch('/admin/logs').then(...)` to show data exfil,
   or a cookie read where cookies aren't `httpOnly`.

## Notes for write-ups

For each bug above, a solid H1-style report has: the exact request
(method, path, headers, body), the exact sink (view-source snippet), the
payload, a screenshot/PoC of execution, and the realistic impact (session
hijack, account takeover via stored XSS in an admin panel, phishing via
open-redirect chain, etc.) — practice writing that up for each of the eight
here before you take the same structure to a live program.
