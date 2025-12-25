# app.py 

import sys
import os
import db
import math
from typing import Final
from services import system_monitor, dashboard_service, core_utils
from flask import Flask, render_template, jsonify, request

current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
template_dir = os.path.join(root_dir, 'web', 'templates')
static_dir = os.path.join(root_dir, 'web', 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

@app.route('/api/live-stats')
def live_stats():
    return jsonify(system_monitor.get_live_system_stats())

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
    
    firewall_event_types = ['NETFILTER', 'PORT_SCAN', 'CRITICAL_PORT', 'FLOOD_DETECTED']
    
    events, total_count = db.advanced_filter_events(event_types_exclude=firewall_event_types, **params)
    
    total_pages = math.ceil(total_count / params['per_page'])

    dashboard_data, _ = dashboard_service.fetch_and_normalize_data()

    return render_template('logs.html', 
                           events=events, 
                           current_page=params['page'], 
                           total_pages=total_pages,
                           total_count=total_count,
                           data=dashboard_data)

@app.route('/api/resolve_alert/<int:alert_id>', methods=['POST'])
def resolve_alert(alert_id):
    try:
        data = request.get_json() or {}
        note = data.get('note', 'Manuel olarak kapatıldı.')
        
        success = db.update_alert_status(alert_id, 'CLOSED', note)
        
        if success:
            return jsonify({"success": True, "message": "Alert resolved"}), 200
        else:
            return jsonify({"success": False, "message": "Database error"}), 500
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/resolution')
def history_page():
    alerts = db.get_resolved_alerts()
    data, _ = dashboard_service.fetch_and_normalize_data()
    
    return render_template('resolution.html', alerts=alerts, data=data)

@app.route('/api/firewall_stats')
def api_firewall_stats():
    try:
        stats = db.get_firewall_stats() 
        return jsonify(stats)
    except Exception as e:
        print(f"[API ERROR] Firewall stats hatası: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/fwstream')
def firewall_stream_page():
    firewall_stats = db.get_firewall_stats() 
    raw_events = db.get_latest_firewall_logs(limit=50) 
    live_events = dashboard_service.enrich_events_with_geo(raw_events)
    dashboard_data, _ = dashboard_service.fetch_and_normalize_data()

    return render_template('firewall_stream.html', 
                           events=live_events, 
                           stats=firewall_stats, 
                           data=dashboard_data)

@app.route('/')
def index():
    data, analytics = dashboard_service.fetch_and_normalize_data()
    data['collector_status'] = core_utils.check_collector_status()
    analytics['top_processes'] = system_monitor.get_top_processes()
    
    analytics['firewall_stats'] = db.get_firewall_stats() 
    
    score = data['metrics']['risk_score']
    risk_class = "bg-success"
    if score >= 30: risk_class = "bg-warning"
    elif score >= 60: risk_class = "bg-danger"

    return render_template('dashboard.html', 
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