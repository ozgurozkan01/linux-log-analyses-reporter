import sys
import os
import json
import psutil
import datetime
from flask import Flask, render_template, request, jsonify

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

from source import db  

app = Flask(__name__)

@app.route('/api/live-stats')
def live_stats():
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory().percent
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())

    now = datetime.datetime.now()
    uptime_delta = now - boot_time
    uptime_str = str(uptime_delta).split('.')[0]
    
    return jsonify({
        'cpu': cpu,
        'ram': ram,
        'uptime': uptime_str
    })

@app.route('/logs')
def logs_page():
    severity = request.args.get('severity')
    keyword = request.args.get('keyword')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    events = db.advanced_filter_events(
        start_date=start_date,
        end_date=end_date,
        severity=severity,
        keyword=keyword
    )
    
    return render_template('logs.html', events=events)

@app.route('/')
def index():
    data = None
    try:
        data = db.get_dashboard_data()
    except Exception as e:
        print(f"[HATA] Veri çekilemedi: {e}")

    if not data or not data.get('metrics'):
        data = {
            'sys_info': {
                'hostname': 'Veri Bekleniyor...', 
                'ip_address': '-', 
                'os': '-', 
                'uptime': '-'
            },
            'metrics': {
                'risk_score': 0, 
                'cpu_usage': 0, 
                'ram_usage': 0, 
                'disk_usage': 0, 
                'open_ports': 0, 
                'failed_logins': 0
            },
            'history': [],
            'alerts': [],
            'events': []
        }

    if data and data.get('metrics') and data['metrics'].get('port_details'):
        try:
            data['metrics']['port_list'] = json.loads(data['metrics']['port_details'])
        except Exception:
            data['metrics']['port_list'] = []
    else:
        if data and data.get('metrics'):
            data['metrics']['port_list'] = []

    if data['history']:
        chart_labels = [row['timestamp'].split(' ')[1] for row in data['history']]
        chart_risk = [row['risk_score'] for row in data['history']]
    else:
        chart_labels = ["-", "-", "-", "-", "-"]
        chart_risk = [0, 0, 0, 0, 0]

    score = data['metrics']['risk_score']
    risk_class = "bg-success"
    status_text = "GÜVENLİ"
    
    if score >= 30: 
        risk_class = "bg-warning"; status_text = "DİKKAT"
    if score >= 60: 
        risk_class = "bg-danger"; status_text = "TEHLİKE"

    return render_template('index.html', 
                           data=data, 
                           risk_class=risk_class, 
                           status_text=status_text,
                           chart_labels=chart_labels,
                           chart_risk=chart_risk)

if __name__ == '__main__':
    try:
        db.init_db()
        print("[INFO] Database connection successfully.")
    except Exception as e:
        print(f"[ERROR] Database ERROR: {e}")

    app.run(debug=True, port=5000)