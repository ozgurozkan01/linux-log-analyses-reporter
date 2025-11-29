import sys
import os
import math
from flask import Flask, render_template, request, jsonify

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

from source import db
import utils 

app = Flask(__name__)

@app.route('/api/live-stats')
def live_stats():
    return jsonify(utils.get_live_system_stats())

@app.route('/logs')
def logs_page():
    params = {
        'severity': request.args.get('severity'),
        'keyword': request.args.get('keyword'),
        'start_date': request.args.get('start_date'),
        'end_date': request.args.get('end_date'),
        'page': request.args.get('page', 1, type=int),
        'per_page': 25
    }
    
    events, total_count = db.advanced_filter_events(**params)
    total_pages = math.ceil(total_count / params['per_page'])
    
    return render_template('logs.html', 
                           events=events, 
                           current_page=params['page'], 
                           total_pages=total_pages,
                           total_count=total_count)

@app.route('/')
def index():
    data, analytics = utils.fetch_and_normalize_data()
    
    data['collector_status'] = utils.check_collector_status()
    analytics['top_processes'] = utils.get_top_processes()
    score = data['metrics']['risk_score']
    
    risk_class = "bg-success"
    if   score >= 30: risk_class = "bg-warning"
    elif score >= 60: risk_class = "bg-danger"

    return render_template('index.html', 
                           data=data, 
                           analytics=analytics,  
                           risk_class=risk_class)

if __name__ == '__main__':
    try:
        db.init_db()
        print("[INFO] Database connection successfully.")
    except Exception as e:
        print(f"[ERROR] Database ERROR: {e}")

    app.run(debug=True, port=5000)