from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import json
import os
from datetime import datetime
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DATA_DIR = 'data'
REVIEWS_FILE = os.path.join(DATA_DIR, 'reviews.json')
SUPPORT_FILE = os.path.join(DATA_DIR, 'support_tickets.json')
COMMENTS_FILE = os.path.join(DATA_DIR, 'comments.json')

os.makedirs(DATA_DIR, exist_ok=True)

def init_data_files():
    for file_path in [REVIEWS_FILE, SUPPORT_FILE, COMMENTS_FILE]:
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                json.dump([], f)

init_data_files()

def load_data(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except:
        return []

def save_data(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)

# Admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'SecurePass2026!'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/products')
def products():
    return render_template('products.html')

@app.route('/product/<product_id>')
def product_detail(product_id):
    comments = load_data(COMMENTS_FILE)
    product_comments = [c for c in comments if c.get('product_id') == product_id]
    return render_template('product_detail.html', product_id=product_id, comments=product_comments)

@app.route('/product/<product_id>/comment', methods=['POST'])
def add_comment(product_id):
    comments = load_data(COMMENTS_FILE)

    # VULNERABILITY: No input sanitization - Stored XSS
    new_comment = {
        'id': len(comments) + 1,
        'product_id': product_id,
        'username': request.form.get('username', ''),
        'rating': request.form.get('rating', '5'),
        'comment': request.form.get('comment', ''),
        'timestamp': datetime.now().isoformat(),
        'verified_purchase': request.form.get('verified') == 'on'
    }

    comments.append(new_comment)
    save_data(COMMENTS_FILE, comments)

    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/reviews')
def reviews():
    return render_template('reviews.html')

@app.route('/reviews/submit', methods=['POST'])
def submit_review():
    reviews = load_data(REVIEWS_FILE)

    # VULNERABILITY: No input sanitization - Stored XSS
    new_review = {
        'id': len(reviews) + 1,
        'name': request.form.get('name', ''),
        'email': request.form.get('email', ''),
        'product': request.form.get('product', ''),
        'rating': request.form.get('rating', '5'),
        'title': request.form.get('title', ''),
        'review': request.form.get('review', ''),
        'timestamp': datetime.now().isoformat(),
        'status': 'pending'
    }

    reviews.append(new_review)
    save_data(REVIEWS_FILE, reviews)

    return redirect(url_for('reviews'))

@app.route('/support')
def support():
    return render_template('support.html')

@app.route('/support/submit', methods=['POST'])
def submit_support():
    tickets = load_data(SUPPORT_FILE)

    # VULNERABILITY: No input sanitization - Stored XSS
    new_ticket = {
        'id': len(tickets) + 1,
        'name': request.form.get('name', ''),
        'email': request.form.get('email', ''),
        'subject': request.form.get('subject', ''),
        'priority': request.form.get('priority', 'medium'),
        'message': request.form.get('message', ''),
        'timestamp': datetime.now().isoformat(),
        'status': 'open'
    }

    tickets.append(new_ticket)
    save_data(SUPPORT_FILE, tickets)

    return redirect(url_for('support'))

@app.route('/api/search')
def api_search():
    query = request.args.get('q', '')

    # VULNERABILITY: Reflected XSS in API response
    results = {
        'query': query,  # No sanitization
        'results': [],
        'timestamp': datetime.now().isoformat()
    }

    # Search through reviews
    reviews = load_data(REVIEWS_FILE)
    for review in reviews:
        if query.lower() in review.get('review', '').lower() or query.lower() in review.get('title', '').lower():
            results['results'].append({
                'type': 'review',
                'title': review.get('title'),
                'excerpt': review.get('review')[:100]
            })

    return jsonify(results)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error='Invalid credentials')

    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    reviews = load_data(REVIEWS_FILE)
    tickets = load_data(SUPPORT_FILE)
    comments = load_data(COMMENTS_FILE)

    return render_template('admin_dashboard.html',
                         reviews=reviews,
                         tickets=tickets,
                         comments=comments)

@app.route('/admin/review/<int:review_id>')
def view_review(review_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    reviews = load_data(REVIEWS_FILE)
    review = next((r for r in reviews if r['id'] == review_id), None)

    if not review:
        return redirect(url_for('admin_dashboard'))

    # VULNERABILITY: Template will render this with |safe filter
    return render_template('view_review.html', review=review)

@app.route('/admin/ticket/<int:ticket_id>')
def view_ticket(ticket_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    tickets = load_data(SUPPORT_FILE)
    ticket = next((t for t in tickets if t['id'] == ticket_id), None)

    if not ticket:
        return redirect(url_for('admin_dashboard'))

    # VULNERABILITY: Template will render this with |safe filter
    return render_template('view_ticket.html', ticket=ticket)

@app.route('/admin/comment/<int:comment_id>')
def view_comment(comment_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    comments = load_data(COMMENTS_FILE)
    comment = next((c for c in comments if c['id'] == comment_id), None)

    if not comment:
        return redirect(url_for('admin_dashboard'))

    # VULNERABILITY: Template will render this with |safe filter
    return render_template('view_comment.html', comment=comment)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 TechNova 2026 CTF Lab Starting...")
    print("="*60)
    print(f"📍 Running at: http://localhost:5000")
    print(f"🔑 Admin Login: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    print("="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
