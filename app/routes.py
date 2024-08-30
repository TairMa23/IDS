from flask import Flask, jsonify, render_template
import os

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/logs')
def get_logs():
    if not os.path.exists('logs/alerts.log'):
        return jsonify({'logs': []})

    with open('logs/alerts.log', 'r') as file:
        logs = file.readlines()
    return jsonify({'logs': logs})
