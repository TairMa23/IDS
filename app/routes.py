from collections import defaultdict
from flask import Flask, jsonify, render_template, request, session, redirect, url_for
import os

app = Flask(__name__)

# Global variable to store traffic summary
traffic_summary = defaultdict(int)

# Secret key for session management
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')  # Use environment variable for production


def login_required(f):
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


@login_required
@app.route('/')
def home():
    # Redirect to login page if not logged in
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html')


@app.route('/logs')
@login_required
def get_logs():
    if not os.path.exists('logs/alerts.log'):
        return jsonify({'logs': []})

    with open('logs/alerts.log', 'r') as file:
        logs = file.readlines()
    return jsonify({'logs': logs})


@app.route('/traffic_summary')
@login_required
def traffic_summary_page():
    return render_template('traffic_summary.html')


@app.route('/api/traffic_summary')
@login_required
def get_traffic_summary():
    global traffic_summary
    return jsonify(dict(traffic_summary))


def update_traffic_summary(packet):
    global traffic_summary
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        traffic_summary[src_ip] += 1


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin_password"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('home'))
        else:
            return "שם משתמש או סיסמה שגויים, נסה שנית.", 401
    return render_template('login.html')
