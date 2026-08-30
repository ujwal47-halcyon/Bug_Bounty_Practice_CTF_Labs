"""
NexusCloud (2026 CTF Edition) — Stored XSS Lab with Client-Side Validation Bypass.

⚠️ FOR LOCAL, AUTHORIZED PRACTICE ONLY. Every bug here is intentional.
Never deploy this outside a network you control.

Run:
    pip install -r requirements.txt
    python app.py
Then browse to http://localhost:5000 (or http://127.0.0.1:5000)

CTF Flag System:
    When you successfully inject a Stored XSS payload (by bypassing client-side validation
    via request interception), viewing or processing the payload returns a CTF flag
    in the HTTP Response Headers (X-Flag-*) as well as recording it!
"""

import json
import os
import secrets
from datetime import datetime
from flask import Flask, request, render_template, redirect, session, jsonify, url_for, make_response

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Data paths
DATA_DIR = 'data'
TICKETS_FILE = os.path.join(DATA_DIR, 'tickets.json')
ORG_FILE = os.path.join(DATA_DIR, 'org_settings.json')
APPS_FILE = os.path.join(DATA_DIR, 'oauth_apps.json')
FLAGS_SUBMITTED_FILE = os.path.join(DATA_DIR, 'submitted_flags.json')

os.makedirs(DATA_DIR, exist_ok=True)

# Admin credentials
ADMIN_USER = 'admin'
ADMIN_PASS = 'NexusCloud#2026'

# CTF Flags Definition
FLAGS = {
    "ticket_stored_xss": "VERAFI{st0r3d_xss_t1ck3t_byp4ss_2026}",
    "org_stored_xss":    "VERAFI{d0m_st0r3d_xss_w3bh00k_m3t4d4t4}",
    "app_stored_xss":    "VERAFI{04uth_4pp_st0r3d_xss_2026}"
}

def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_json(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def is_xss_payload(val):
    """Utility helper to detect if payload was successfully injected."""
    if not isinstance(val, str):
        return False
    lower = val.lower()
    return any(p in lower for p in ['<script', '<img', '<svg', '<iframe', 'javascript:', 'onerror=', 'onload=', 'onclick='])

@app.route('/')
def index():
    """Main SaaS Landing Page."""
    return render_template('index.html')

@app.route('/ticket/create', methods=['GET', 'POST'])
def create_ticket():
    """
    VULNERABLE SINK 1: Support Ticket System.
    Client-side JS blocks <script>, <iframe>, event handlers.
    Bypassing client-side JS allows injecting stored XSS into details or subject!
    """
    if request.method == 'POST':
        subject = request.form.get('subject', '')
        category = request.form.get('category', 'Technical Support')
        urgency = request.form.get('urgency', 'Medium')
        details = request.form.get('details', '')

        tickets = load_json(TICKETS_FILE)
        new_id = len(tickets) + 1
        ticket = {
            'id': new_id,
            'subject': subject,
            'category': category,
            'urgency': urgency,
            'details': details,
            'status': 'Open',
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'submitted_by': 'dev_team@company.com'
        }
        tickets.append(ticket)
        save_json(TICKETS_FILE, tickets)

        resp = make_response(render_template('thank_you.html', 
                            title="Ticket Submitted", 
                            message=f"Support ticket #{new_id} has been logged. Admin staff will review it shortly."))
        
        # If payload was injected via request bypass
        if is_xss_payload(details) or is_xss_payload(subject):
            resp.headers['X-Flag-Ticket-XSS'] = FLAGS['ticket_stored_xss']

        return resp

    return render_template('create_ticket.html')

@app.route('/settings/org', methods=['GET', 'POST'])
def org_settings():
    """
    VULNERABLE SINK 2: Organization Webhook Settings.
    Client-side validation requires standard text.
    Intercepting & modifying request allows stored XSS in header/webhook name.
    """
    org_data = load_json(ORG_FILE)
    if isinstance(org_data, list):
        org_data = {
            "org_name": "Acme Corp Enterprise",
            "webhook_url": "https://api.acme.internal/webhook",
            "notification_header": "X-Nexus-Auth",
            "custom_metadata": "Default Enterprise Config"
        }

    if request.method == 'POST':
        org_data = {
            "org_name": request.form.get('org_name', ''),
            "webhook_url": request.form.get('webhook_url', ''),
            "notification_header": request.form.get('notification_header', ''),
            "custom_metadata": request.form.get('custom_metadata', ''),
            "updated_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        save_json(ORG_FILE, org_data)

        resp = make_response(render_template('org_settings.html', org=org_data, success=True))
        if is_xss_payload(org_data['notification_header']) or is_xss_payload(org_data['custom_metadata']):
            resp.headers['X-Flag-Org-XSS'] = FLAGS['org_stored_xss']
        return resp

    return render_template('org_settings.html', org=org_data)

@app.route('/developer/apps/register', methods=['GET', 'POST'])
def register_app():
    """
    VULNERABLE SINK 3: OAuth App Registration.
    Client-side validation restricts app description and redirect URIs.
    Bypassing JS stores malicious XSS string into admin integration portal.
    """
    if request.method == 'POST':
        app_name = request.form.get('app_name', '')
        redirect_uri = request.form.get('redirect_uri', '')
        app_description = request.form.get('app_description', '')

        apps = load_json(APPS_FILE)
        new_app = {
            'id': len(apps) + 1,
            'app_name': app_name,
            'redirect_uri': redirect_uri,
            'app_description': app_description,
            'client_id': secrets.token_hex(8),
            'status': 'Pending Approval',
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        apps.append(new_app)
        save_json(APPS_FILE, apps)

        resp = make_response(render_template('thank_you.html', 
                            title="OAuth App Registered", 
                            message="Your application is pending Admin approval."))
        if is_xss_payload(app_description) or is_xss_payload(app_name):
            resp.headers['X-Flag-App-XSS'] = FLAGS['app_stored_xss']
        return resp

    return render_template('register_app.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin Login Portal."""
    if request.method == 'POST':
        user = request.form.get('username', '')
        pwd = request.form.get('password', '')
        if user == ADMIN_USER and pwd == ADMIN_PASS:
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html', error="Invalid admin credentials.")
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin Overview Portal."""
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    tickets = load_json(TICKETS_FILE)
    apps = load_json(APPS_FILE)
    org = load_json(ORG_FILE)
    return render_template('admin_dashboard.html', tickets=tickets, apps=apps, org=org)

@app.route('/admin/ticket/<int:tid>')
def view_ticket(tid):
    """
    ADMIN EXECUTION ZONE FOR SINK 1 (Ticket Stored XSS).
    Renders user's unescaped details via |safe Jinja2 filter.
    """
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    tickets = load_json(TICKETS_FILE)
    ticket = next((t for t in tickets if t['id'] == tid), None)
    if not ticket:
        return "Ticket not found", 404
    
    resp = make_response(render_template('view_ticket.html', ticket=ticket))
    if is_xss_payload(ticket.get('details', '')) or is_xss_payload(ticket.get('subject', '')):
        resp.headers['X-Flag-Ticket-XSS'] = FLAGS['ticket_stored_xss']
    return resp

@app.route('/admin/audit-logs')
def admin_audit_logs():
    """
    ADMIN EXECUTION ZONE FOR SINK 2 (Org Metadata Stored XSS).
    Renders organization settings without escaping.
    """
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    org = load_json(ORG_FILE)
    resp = make_response(render_template('admin_audit_logs.html', org=org))
    if isinstance(org, dict):
        if is_xss_payload(org.get('notification_header', '')) or is_xss_payload(org.get('custom_metadata', '')):
            resp.headers['X-Flag-Org-XSS'] = FLAGS['org_stored_xss']
    return resp

@app.route('/admin/apps/<int:aid>')
def view_app(aid):
    """
    ADMIN EXECUTION ZONE FOR SINK 3 (OAuth App Stored XSS).
    Renders app registration description unescaped.
    """
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    apps = load_json(APPS_FILE)
    app_item = next((a for a in apps if a['id'] == aid), None)
    if not app_item:
        return "App not found", 404
    
    resp = make_response(render_template('view_app.html', app_item=app_item))
    if is_xss_payload(app_item.get('app_description', '')) or is_xss_payload(app_item.get('app_name', '')):
        resp.headers['X-Flag-App-XSS'] = FLAGS['app_stored_xss']
    return resp

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('index'))

@app.route('/flags', methods=['GET', 'POST'])
def flags_tracker():
    """CTF Flag Tracker & Submission Page."""
    submitted = load_json(FLAGS_SUBMITTED_FILE)
    if not isinstance(submitted, list):
        submitted = []
    
    message = None
    if request.method == 'POST':
        flag_input = request.form.get('flag', '').strip()
        matched_key = None
        for key, val in FLAGS.items():
            if val == flag_input:
                matched_key = key
                break
        
        if matched_key:
            if flag_input not in submitted:
                submitted.append(flag_input)
                save_json(FLAGS_SUBMITTED_FILE, submitted)
                message = f"🎉 Correct Flag! Solved: {matched_key.replace('_', ' ').title()}"
            else:
                message = "ℹ️ Flag already submitted!"
        else:
            message = "❌ Invalid Flag format or value."

    return render_template('flags.html', total=len(FLAGS), submitted=submitted, flags_dict=FLAGS, message=message)

if __name__ == '__main__':
    print("=" * 70)
    print("NexusCloud 2026 — Stored XSS CTF Lab")
    print("=" * 70)
    print("\n🌐 Running locally at: http://localhost:5000")
    print(f"\n🔑 Admin Credentials:")
    print(f"   Username: {ADMIN_USER}")
    print(f"   Password: {ADMIN_PASS}")
    print("\n🎯 Goal: Bypass client-side form validation to inject Stored XSS!")
    print("=" * 70)
    app.run(debug=True, host='0.0.0.0', port=5000)
