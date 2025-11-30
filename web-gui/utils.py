import os
import psutil
import datetime
import subprocess
import json 

from typing import Final
from source import db

CURRENT_DIR    : Final = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT   : Final = os.path.dirname(CURRENT_DIR)
COLLECTOR_PATH : Final = os.path.join(PROJECT_ROOT, "source", "collector.py")
CURSOR_FILE    : Final = os.path.join(PROJECT_ROOT, "source", "last_scan_cursor.txt")


def get_live_system_stats():
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory().percent
    processes = get_top_processes() 
    last_scan_time = get_last_scan_time()

    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime_str = str(datetime.datetime.now() - boot_time).split('.')[0]
    
    return {'cpu': cpu, 'ram': ram, 'uptime': uptime_str, 'processes': processes, 'last_scan': last_scan_time}

def check_collector_status():
    file_exists = os.path.isfile(COLLECTOR_PATH)
    cron_exists = False
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.splitlines():
                if COLLECTOR_PATH in line and not line.strip().startswith("#"):
                    cron_exists = True
                    break
    except Exception:
        pass

    return file_exists and cron_exists

def fetch_and_normalize_data():
    try:
        raw_data = db.get_dashboard_data() or {}
        analytics_db = db.get_analytics_data() or {}
        heatmap = db.get_heatmap_data() or []
        firewall = db.get_firewall_stats() or {'allow': 0, 'deny': 0}
        volume = db.get_log_volume_stats() or []
    except Exception:
        return {}, {}

    data = {
        'sys_info': raw_data.get('sys_info') or {'hostname': '-', 'ip_address': '-', 'uptime': '-'},
        'metrics': raw_data.get('metrics') or {'risk_score': 0, 'cpu_usage': 0, 'ram_usage': 0, 'disk_usage': 0, 'open_ports': 0, 'failed_logins': 0},
        'alerts': raw_data.get('alerts') or [],
        'anomalies': [{'title': a['title'], 'desc': a['description']} for a in (raw_data.get('alerts') or []) if a['level'] == 'CRITICAL'],
        'last_scan': get_last_scan_time(),
        'collector_status': check_collector_status() 
    }

    try:
        if raw_data.get('metrics') and raw_data['metrics'].get('port_details'):
            data['metrics']['port_list'] = json.loads(raw_data['metrics']['port_details'])
        else:
            data['metrics']['port_list'] = []
    except:
        data['metrics']['port_list'] = []
    
    analytics = {
        'top_ips': analytics_db.get('top_ips', []),
        'heatmap_data': heatmap,
        'volume_labels': ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"],
        'volume_data': volume,
        'firewall_stats': firewall
    }

    risk_score = data['metrics']['risk_score']
    if risk_score > 0:
        failed_contrib = min((data['metrics']['failed_logins'] * 5), 50)
        anomaly_contrib = min((len(data['alerts']) * 10), 50)
        data['risk_breakdown'] = {'failed_auth_pct': int(failed_contrib), 'anomaly_pct': int(anomaly_contrib)}
    else:
        data['risk_breakdown'] = {'failed_auth_pct': 0, 'anomaly_pct': 0}

    return data, analytics

def get_top_processes(limit=8):
    process_map = {}
    cpu_count = psutil.cpu_count() or 1

    try:
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent']):
            try:
                p_info = proc.info
                raw_cpu = p_info['cpu_percent']

                if not raw_cpu or raw_cpu <= 0.0:
                    continue
                
                name = p_info['name'] or "Unknown"
                if name == "code": name = "VS Code"
                if name == "gnome-shell": name = "Gnome Shell"
                
                normalized_cpu = raw_cpu / cpu_count

                if name in process_map:
                    process_map[name]['cpu_percent'] += normalized_cpu
                    process_map[name]['count'] += 1
                else:
                    process_map[name] = {
                        'pid': p_info['pid'], 
                        'name': name,
                        'username': p_info['username'],
                        'cpu_percent': normalized_cpu,
                        'count': 1
                    }
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
    except Exception:
        return []
    
    grouped_procs = list(process_map.values())
    
    for p in grouped_procs:
        p['cpu_percent'] = round(p['cpu_percent'], 1)
        if p['count'] > 1:
            p['name'] = f"{p['name']} ({p['count']}x)"

    return sorted(grouped_procs, key=lambda x: x['cpu_percent'], reverse=True)[:limit]


def get_last_scan_time():
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE, 'r') as f:
                return f.read().strip()
        except Exception:
            return "Read Error"
    else:
        return "Not Found"