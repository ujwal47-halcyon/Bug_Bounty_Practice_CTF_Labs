from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import json
import os
from datetime import datetime
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DATA_DIR = 'data'
COURSES_FILE = os.path.join(DATA_DIR, 'course_reviews.json')
INSTRUCTORS_FILE = os.path.join(DATA_DIR, 'instructor_applications.json')
FORUM_FILE = os.path.join(DATA_DIR, 'forum_posts.json')
QA_FILE = os.path.join(DATA_DIR, 'course_qa.json')
FEEDBACK_FILE = os.path.join(DATA_DIR, 'platform_feedback.json')

os.makedirs(DATA_DIR, exist_ok=True)

def init_data_files():
    for file_path in [COURSES_FILE, INSTRUCTORS_FILE, FORUM_FILE, QA_FILE, FEEDBACK_FILE]:
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
ADMIN_USERNAME = 'instructor@skillforge.io'
ADMIN_PASSWORD = 'Teach2026Secure!'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/courses')
def courses():
    return render_template('courses.html')

@app.route('/course/<course_id>')
def course_detail(course_id):
    reviews = load_data(COURSES_FILE)
    course_reviews = [r for r in reviews if r.get('course_id') == course_id]

    qa_posts = load_data(QA_FILE)
    course_qa = [q for q in qa_posts if q.get('course_id') == course_id]

    return render_template('course_detail.html', course_id=course_id, reviews=course_reviews, qa_posts=course_qa)

@app.route('/course/<course_id>/review', methods=['POST'])
def submit_course_review(course_id):
    reviews = load_data(COURSES_FILE)

    # VULNERABILITY: No input sanitization - Stored XSS
    new_review = {
        'id': len(reviews) + 1,
        'course_id': course_id,
        'student_name': request.form.get('student_name', ''),
        'rating': request.form.get('rating', '5'),
        'review_title': request.form.get('review_title', ''),
        'review_text': request.form.get('review_text', ''),
        'completed': request.form.get('completed') == 'on',
        'timestamp': datetime.now().isoformat(),
        'status': 'pending'
    }

    reviews.append(new_review)
    save_data(COURSES_FILE, reviews)

    return redirect(url_for('course_detail', course_id=course_id))

@app.route('/course/<course_id>/ask', methods=['POST'])
def submit_question(course_id):
    qa_posts = load_data(QA_FILE)

    # VULNERABILITY: No input sanitization - Stored XSS
    new_question = {
        'id': len(qa_posts) + 1,
        'course_id': course_id,
        'student_name': request.form.get('student_name', ''),
        'question_title': request.form.get('question_title', ''),
        'question_text': request.form.get('question_text', ''),
        'timestamp': datetime.now().isoformat(),
        'status': 'unanswered'
    }

    qa_posts.append(new_question)
    save_data(QA_FILE, qa_posts)

    return redirect(url_for('course_detail', course_id=course_id))

@app.route('/become-instructor')
def become_instructor():
    return render_template('become_instructor.html')

@app.route('/become-instructor/apply', methods=['POST'])
def apply_instructor():
    applications = load_data(INSTRUCTORS_FILE)

    # VULNERABILITY: No input sanitization - Stored XSS
    new_application = {
        'id': len(applications) + 1,
        'full_name': request.form.get('full_name', ''),
        'email': request.form.get('email', ''),
        'bio': request.form.get('bio', ''),
        'expertise': request.form.get('expertise', ''),
        'experience': request.form.get('experience', ''),
        'linkedin': request.form.get('linkedin', ''),
        'portfolio': request.form.get('portfolio', ''),
        'teaching_philosophy': request.form.get('teaching_philosophy', ''),
        'timestamp': datetime.now().isoformat(),
        'status': 'pending'
    }

    applications.append(new_application)
    save_data(INSTRUCTORS_FILE, applications)

    return redirect(url_for('become_instructor'))

@app.route('/community')
def community():
    forum_posts = load_data(FORUM_FILE)
    return render_template('community.html', posts=forum_posts[-10:][::-1])

@app.route('/community/post', methods=['POST'])
def create_forum_post():
    forum_posts = load_data(FORUM_FILE)

    # VULNERABILITY: No input sanitization - Stored XSS
    new_post = {
        'id': len(forum_posts) + 1,
        'author': request.form.get('author', ''),
        'title': request.form.get('title', ''),
        'content': request.form.get('content', ''),
        'category': request.form.get('category', ''),
        'timestamp': datetime.now().isoformat()
    }

    forum_posts.append(new_post)
    save_data(FORUM_FILE, forum_posts)

    return redirect(url_for('community'))

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/feedback/submit', methods=['POST'])
def submit_feedback():
    feedback_list = load_data(FEEDBACK_FILE)

    # VULNERABILITY: No input sanitization - Stored XSS
    new_feedback = {
        'id': len(feedback_list) + 1,
        'name': request.form.get('name', ''),
        'email': request.form.get('email', ''),
        'feedback_type': request.form.get('feedback_type', ''),
        'subject': request.form.get('subject', ''),
        'message': request.form.get('message', ''),
        'timestamp': datetime.now().isoformat(),
        'status': 'new'
    }

    feedback_list.append(new_feedback)
    save_data(FEEDBACK_FILE, feedback_list)

    return redirect(url_for('feedback'))

@app.route('/api/search')
def api_search():
    query = request.args.get('q', '')

    # VULNERABILITY: Reflected XSS in API response
    results = {
        'query': query,  # No sanitization
        'results': [],
        'timestamp': datetime.now().isoformat()
    }

    # Search through forum posts
    forum_posts = load_data(FORUM_FILE)
    for post in forum_posts:
        if query.lower() in post.get('title', '').lower() or query.lower() in post.get('content', '').lower():
            results['results'].append({
                'type': 'forum_post',
                'title': post.get('title'),
                'excerpt': post.get('content')[:100]
            })

    return jsonify(results)

@app.route('/instructor/login', methods=['GET', 'POST'])
def instructor_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['instructor'] = True
            return redirect(url_for('instructor_dashboard'))
        else:
            return render_template('instructor_login.html', error='Invalid credentials')

    return render_template('instructor_login.html')

@app.route('/instructor/logout')
def instructor_logout():
    session.pop('instructor', None)
    return redirect(url_for('index'))

@app.route('/instructor/dashboard')
def instructor_dashboard():
    if not session.get('instructor'):
        return redirect(url_for('instructor_login'))

    reviews = load_data(COURSES_FILE)
    applications = load_data(INSTRUCTORS_FILE)
    forum_posts = load_data(FORUM_FILE)
    qa_posts = load_data(QA_FILE)
    feedback_list = load_data(FEEDBACK_FILE)

    return render_template('instructor_dashboard.html',
                         reviews=reviews,
                         applications=applications,
                         forum_posts=forum_posts,
                         qa_posts=qa_posts,
                         feedback_list=feedback_list)

@app.route('/instructor/review/<int:review_id>')
def view_review(review_id):
    if not session.get('instructor'):
        return redirect(url_for('instructor_login'))

    reviews = load_data(COURSES_FILE)
    review = next((r for r in reviews if r['id'] == review_id), None)

    if not review:
        return redirect(url_for('instructor_dashboard'))

    # VULNERABILITY: Template will render this with |safe filter
    return render_template('view_review.html', review=review)

@app.route('/instructor/application/<int:app_id>')
def view_application(app_id):
    if not session.get('instructor'):
        return redirect(url_for('instructor_login'))

    applications = load_data(INSTRUCTORS_FILE)
    application = next((a for a in applications if a['id'] == app_id), None)

    if not application:
        return redirect(url_for('instructor_dashboard'))

    # VULNERABILITY: Template will render this with |safe filter
    return render_template('view_application.html', application=application)

@app.route('/instructor/forum-post/<int:post_id>')
def view_forum_post(post_id):
    if not session.get('instructor'):
        return redirect(url_for('instructor_login'))

    forum_posts = load_data(FORUM_FILE)
    post = next((p for p in forum_posts if p['id'] == post_id), None)

    if not post:
        return redirect(url_for('instructor_dashboard'))

    # VULNERABILITY: Template will render this with |safe filter
    return render_template('view_forum_post.html', post=post)

@app.route('/instructor/question/<int:qa_id>')
def view_question(qa_id):
    if not session.get('instructor'):
        return redirect(url_for('instructor_login'))

    qa_posts = load_data(QA_FILE)
    question = next((q for q in qa_posts if q['id'] == qa_id), None)

    if not question:
        return redirect(url_for('instructor_dashboard'))

    # VULNERABILITY: Template will render this with |safe filter
    return render_template('view_question.html', question=question)

@app.route('/instructor/feedback/<int:feedback_id>')
def view_feedback(feedback_id):
    if not session.get('instructor'):
        return redirect(url_for('instructor_login'))

    feedback_list = load_data(FEEDBACK_FILE)
    feedback = next((f for f in feedback_list if f['id'] == feedback_id), None)

    if not feedback:
        return redirect(url_for('instructor_dashboard'))

    # VULNERABILITY: Template will render this with |safe filter
    return render_template('view_feedback.html', feedback=feedback)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🎓 SkillForge XSS Lab Starting...")
    print("="*60)
    print(f"📍 Running at: http://localhost:5000")
    print(f"🔑 Instructor Login: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    print("="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
