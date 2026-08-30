# NexusCloud 2026 — Stored XSS CTF Lab

A modern cloud SaaS platform built as a Stored XSS capture-the-flag. Client-side JavaScript blocks suspicious inputs in the browser, but the server has **no server-side validation** — so intercepting the request with Burp Suite or curl bypasses everything.

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000` in your browser.

**Admin login:** `admin` / `NexusCloud#2026`

---

## How It Works

Every form on this site has **client-side JavaScript validation** that blocks XSS patterns like `<script>`, `<img>`, event handlers, etc. If you type a payload directly in the browser, you get an alert popup and the form won't submit.

**The catch:** the server never validates anything. If you intercept the request (Burp Suite, curl, Postman) and modify the POST body to include your payload, it gets stored and executes when an admin views it.

---

## 3 Stored XSS Challenges

### 1. Support Ticket System
- **Where:** `/ticket/create` → submit → admin views at `/admin/ticket/<id>`
- **Sink fields:** `subject`, `details`
- **Flag header:** `X-Flag-Ticket-XSS`
- **How:** Intercept `POST /ticket/create`, inject payload into `details` field

### 2. Workspace Webhook Settings
- **Where:** `/settings/org` → submit → admin views at `/admin/audit-logs`
- **Sink fields:** `notification_header`, `custom_metadata`
- **Flag header:** `X-Flag-Org-XSS`
- **How:** Intercept `POST /settings/org`, inject payload into `notification_header`

### 3. OAuth App Registration
- **Where:** `/developer/apps/register` → submit → admin views at `/admin/apps/<id>`
- **Sink fields:** `app_name`, `app_description`
- **Flag header:** `X-Flag-App-XSS`
- **How:** Intercept `POST /developer/apps/register`, inject payload into `app_description`

---

## Example Exploitation (curl)

```bash
# Step 1: Submit a ticket with XSS payload (bypasses client-side JS)
curl -X POST http://localhost:5000/ticket/create \
  -d 'subject=Test Ticket' \
  -d 'category=Technical Support' \
  -d 'urgency=Medium' \
  -d 'details=<img src=x onerror=alert(document.cookie)>'

# Step 2: Login as admin and view the ticket — payload executes!
curl -b cookies.txt http://localhost:5000/admin/login -d 'username=admin&password=NexusCloud#2026' -c cookies.txt
curl -b cookies.txt http://localhost:5000/admin/ticket/1 -i

# Step 3: Check response headers for the flag!
```

---

## Finding Flags

Flags are in **HTTP response headers** on the request that triggers the XSS. Use `curl -i` or check Burp Suite's response tab.

| Challenge | Flag Header | Flag Value |
|-----------|-------------|------------|
| Ticket XSS | `X-Flag-Ticket-XSS` | `VERAFI{st0r3d_xss_t1ck3t_byp4ss_2026}` |
| Org Settings XSS | `X-Flag-Org-XSS` | `VERAFI{d0m_st0r3d_xss_w3bh00k_m3t4d4t4}` |
| OAuth App XSS | `X-Flag-App-XSS` | `VERAFI{04uth_4pp_st0r3d_xss_2026}` |

Submit found flags at `/flags` to track progress.

---

## Project Structure

```
nexuscloud-ctf-2026/
├── app.py                  # Flask app with all routes & vulnerable sinks
├── requirements.txt        # Python dependencies
├── start.bat               # Windows quick-start
├── README.md               # This file
├── static/
│   └── style.css           # 2026 SaaS dark theme
├── templates/
│   ├── base.html           # Layout with navbar & footer
│   ├── index.html          # Landing page
│   ├── create_ticket.html  # Support ticket form (client-side validation)
│   ├── org_settings.html   # Webhook settings form (client-side validation)
│   ├── register_app.html   # OAuth app form (client-side validation)
│   ├── thank_you.html      # Submission confirmation
│   ├── admin_login.html    # Admin auth
│   ├── admin_dashboard.html# Admin overview
│   ├── view_ticket.html    # XSS sink 1 (|safe filter)
│   ├── admin_audit_logs.html # XSS sink 2 (|safe filter)
│   ├── view_app.html       # XSS sink 3 (|safe filter)
│   └── flags.html          # CTF flag tracker
└── data/                   # Auto-created JSON storage
```

---

## Learning Objectives

- Understand why client-side validation alone is not security
- Practice request interception with Burp Suite / curl
- Learn how stored XSS executes in admin panels
- Get comfortable reading raw HTTP responses for flags

---

## Disclaimer

This is for **authorized educational use only**. Never deploy vulnerable apps to public servers.
