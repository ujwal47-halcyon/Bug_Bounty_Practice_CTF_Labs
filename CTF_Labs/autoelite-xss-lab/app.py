"""
AutoElite Motors — deliberately vulnerable car dealership for bug bounty practice.

⚠️ FOR LOCAL, AUTHORIZED PRACTICE ONLY. The bugs below are intentional.
Never deploy this outside a network you control.

Run:
    pip install flask
    python app.py
Then browse to http://10.170.65.14:5000
"""

import json
import os
from datetime import datetime
import secrets

from flask import Flask, request, render_template, redirect, session, jsonify, url_for

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Data storage paths
DATA_DIR = 'data'
FEEDBACK_FILE = os.path.join(DATA_DIR, 'feedback.json')
CONTACTS_FILE = os.path.join(DATA_DIR, 'contacts.json')
ADMIN_SESSION_FILE = os.path.join(DATA_DIR, 'admin_sessions.json')

# Create data directory
os.makedirs(DATA_DIR, exist_ok=True)

# Admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'

# Car inventory
CARS = {
    "101": {"make": "BMW", "model": "M4 Competition", "year": 2024, "price": 78500,
            "mileage": 2100, "fuel": "Petrol", "desc": "Twin-Turbo 6-Cylinder, 503 HP, 0-60 in 3.4s."},
    "102": {"make": "Mercedes-Benz", "model": "GLE 450", "year": 2024, "price": 69900,
            "mileage": 5200, "fuel": "Petrol", "desc": "Luxury SUV with Premium Package and advanced safety."},
    "103": {"make": "Tesla", "model": "Model S Plaid", "year": 2024, "price": 108490,
            "mileage": 800, "fuel": "Electric", "desc": "1,020 HP, 405 mile range, Full Self-Driving."},
    "104": {"make": "Porsche", "model": "911 Turbo S", "year": 2024, "price": 207000,
            "mileage": 1500, "fuel": "Petrol", "desc": "640 HP, All-Wheel Drive, legendary performance."},
    "105": {"make": "Audi", "model": "RS7 Sportback", "year": 2024, "price": 116500,
            "mileage": 3200, "fuel": "Petrol", "desc": "591 HP V8 Twin-Turbo, sport luxury sedan."},
    "106": {"make": "Lucid", "model": "Air Dream Edition", "year": 2024, "price": 169000,
            "mileage": 600, "fuel": "Electric", "desc": "1,111 HP, 516 mile range, luxury electric."},
}


def load_data(filename):
    """Load JSON data from file."""
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    return []


def save_data(filename, data):
    """Save data to JSON file."""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)


@app.route("/")
def home():
    """Main landing page with car inventory."""
    return render_template("home.html", cars=CARS)


@app.route("/car/<cid>")
def car_detail(cid):
    """Individual car detail page."""
    car = CARS.get(cid)
    if not car:
        return redirect("/")
    return render_template("car_detail.html", car=car, cid=cid)


@app.route("/contact")
def contact():
    """Contact form page."""
    return render_template("contact.html")


@app.route("/submit-contact", methods=["POST"])
def submit_contact():
    """
    VULNERABLE: No sanitization of user input.
    Stores raw HTML/JavaScript that will execute when admin views it.
    """
    contact_data = {
        'id': len(load_data(CONTACTS_FILE)) + 1,
        'name': request.form.get('name', ''),
        'email': request.form.get('email', ''),
        'phone': request.form.get('phone', ''),
        'interested_car': request.form.get('interested_car', 'General Inquiry'),
        'message': request.form.get('message', ''),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'unread'
    }

    contacts = load_data(CONTACTS_FILE)
    contacts.append(contact_data)
    save_data(CONTACTS_FILE, contacts)

    return render_template("thank_you.html",
                         message="Thank you for contacting us! Our sales team will get back to you within 24 hours.")


@app.route("/feedback")
def feedback():
    """Customer feedback form page."""
    return render_template("feedback.html")


@app.route("/submit-feedback", methods=["POST"])
def submit_feedback():
    """
    VULNERABLE: No sanitization - blind XSS opportunity.
    Admin reviews these in the dashboard.
    """
    feedback_data = {
        'id': len(load_data(FEEDBACK_FILE)) + 1,
        'name': request.form.get('name', ''),
        'email': request.form.get('email', ''),
        'rating': request.form.get('rating', ''),
        'experience': request.form.get('experience', ''),
        'comments': request.form.get('comments', ''),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'reviewed': False
    }

    feedback_list = load_data(FEEDBACK_FILE)
    feedback_list.append(feedback_data)
    save_data(FEEDBACK_FILE, feedback_list)

    return render_template("thank_you.html",
                         message="Thank you for your feedback! Our team will review it shortly.")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Admin authentication endpoint."""
    if request.method == "POST":
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error='Invalid credentials')

    return render_template('admin_login.html')


@app.route("/admin/dashboard")
def admin_dashboard():
    """
    Admin dashboard showing all submissions.
    VULNERABLE: Renders user input without sanitization.
    """
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    feedback_list = load_data(FEEDBACK_FILE)
    contacts = load_data(CONTACTS_FILE)

    return render_template('admin_dashboard.html',
                         feedback=feedback_list,
                         contacts=contacts)


@app.route("/admin/view-feedback/<int:feedback_id>")
def view_feedback(feedback_id):
    """
    View individual feedback - BLIND XSS SINK.
    VULNERABLE: Uses |safe filter to render raw HTML.
    """
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    feedback_list = load_data(FEEDBACK_FILE)
    feedback_item = next((f for f in feedback_list if f['id'] == feedback_id), None)

    if feedback_item:
        # Mark as reviewed
        feedback_item['reviewed'] = True
        save_data(FEEDBACK_FILE, feedback_list)
        return render_template('view_feedback.html', feedback=feedback_item)

    return 'Feedback not found', 404


@app.route("/admin/view-contact/<int:contact_id>")
def view_contact(contact_id):
    """
    View individual contact - BLIND XSS SINK.
    VULNERABLE: Uses |safe filter to render raw HTML.
    """
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    contacts = load_data(CONTACTS_FILE)
    contact_item = next((c for c in contacts if c['id'] == contact_id), None)

    if contact_item:
        # Mark as read
        contact_item['status'] = 'read'
        save_data(CONTACTS_FILE, contacts)
        return render_template('view_contact.html', contact=contact_item)

    return 'Contact not found', 404


@app.route("/admin/logout")
def admin_logout():
    """Admin logout endpoint."""
    session.pop('admin', None)
    session.pop('admin_username', None)
    return redirect(url_for('home'))


@app.route("/api/search")
def api_search():
    """
    VULNERABLE: Reflected XSS in JSON response.
    The query parameter is reflected without sanitization.
    """
    query = request.args.get('q', '')
    results = []

    # Search cars
    if query:
        for cid, car in CARS.items():
            if query.lower() in f"{car['make']} {car['model']}".lower():
                results.append({
                    'id': cid,
                    'make': car['make'],
                    'model': car['model'],
                    'year': car['year'],
                    'price': car['price']
                })

    # VULNERABLE: Direct reflection of user input
    return jsonify({
        'query': query,
        'count': len(results),
        'results': results
    })


if __name__ == "__main__":
    # Initialize empty data files
    if not os.path.exists(FEEDBACK_FILE):
        save_data(FEEDBACK_FILE, [])
    if not os.path.exists(CONTACTS_FILE):
        save_data(CONTACTS_FILE, [])

    print("=" * 70)
    print("AutoElite Motors - Bug Bounty Practice Lab")
    print("=" * 70)
    print("\n🚗 Car Dealership with Intentional Vulnerabilities")
    print(f"\n🌐 Server running at: http://10.170.65.14:5000")
    print(f"\n🔑 Admin Credentials:")
    print(f"   Username: {ADMIN_USERNAME}")
    print(f"   Password: {ADMIN_PASSWORD}")
    print(f"\n🐛 Vulnerabilities to practice:")
    print("   1. Blind XSS in contact form (stored)")
    print("   2. Blind XSS in feedback form (stored)")
    print("   3. Reflected XSS in search API")
    print("   4. Stored XSS triggers in admin panel")
    print(f"\n⚠️  FOR EDUCATIONAL USE ONLY - DO NOT DEPLOY PUBLICLY")
    print("=" * 70)
    print()

    app.run(debug=True, host="0.0.0.0", port=5000)
