from flask import Flask, render_template, jsonify
import json, os

app = Flask(__name__, template_folder='templates', static_folder='static')

def load_results():
    path = os.path.join(os.path.dirname(__file__), 'latest_results.json')
    if not os.path.exists(path):
        return []
    with open(path,'r') as f:
        return json.load(f)

@app.route('/api/results')
def api_results():
    return jsonify(load_results())

@app.route('/')
def index():
    results = load_results()
    return render_template('index.html', results=results)
