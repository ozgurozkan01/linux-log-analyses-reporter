
import db
import psutil
import socket

from datetime import datetime

from services import network_scanner
from services import system_monitor
from services import firewall_manager
from services import core_utils


def fetch_and_normalize_data():
    try:
        raw_data = db.get_dashboard_data() or {}
        analytics_db = db.get_analytics_data() or {}
        heatmap = db.get_heatmap_data() or []
        firewall = db.get_firewall_stats() or {'allow': 0, 'deny': 0}
        volume = db.get_log_volume_stats() or []
    except Exception as e:
        print(f"DB Error: {e}")
        raw_data, analytics_db, heatmap, firewall, volume = {}, {}, [], {}, []

    sys_info_current = raw_data.get('sys_info') or {}
    
    public_ip_info = network_scanner.get_public_ip()

    if public_ip_info:
        net_info = {
            'public_ip': public_ip_info['ip'],
            'country_name': public_ip_info['country_name'],
            'country_code': public_ip_info['country_code'],
            'local_ip': network_scanner.get_local_ip(),
            'dns': network_scanner.get_primary_dns()
        }
    else:
        net_info = {
            'public_ip': 'Offline',
            'country_name': None,
            'country_code': None,
            'local_ip': network_scanner.get_local_ip(),
            'dns': network_scanner.get_primary_dns()
        }

    sys_info_current['ip_address'] = network_scanner.get_local_ip()
    
    dns_list = network_scanner.get_primary_dns()
    sys_info_current['dns'] = dns_list[0] if dns_list else "Local (Stub)"

    if not sys_info_current.get('hostname'):
        sys_info_current['hostname'] = socket.gethostname()

    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        sys_info_current['uptime'] = str(datetime.now() - boot_time).split('.')[0]
    except:
        sys_info_current['uptime'] = "Unknown"
    
    try:
        sys_info_current['username'] = os.getlogin()
    except:
        sys_info_current['username'] = "root"

    try:
        ufw_data = firewall_manager.get_ufw_details()
        ufw_rules = firewall_manager.get_ufw_rules_list()
    except Exception as e:
        print(f"UFW Data Fetch Error: {e}")
        ufw_data = {}
        ufw_rules = {}

    data = {
        'sys_info': sys_info_current,
        'net_info': net_info,
        'firewall_info': ufw_data,
        'firewall_rules': ufw_rules, 
        'metrics': raw_data.get('metrics') or {
            'risk_score': 0, 
            'cpu_usage': 0, 
            'ram_usage': 0, 
            'disk_usage': 0, 
            'open_ports': 0, 
            'failed_logins': 0
        },
        'alerts': raw_data.get('alerts') or [],
        'anomalies': [{'title': a['title'], 'desc': a['description'], 'time': a.get('timestamp', '')} for a in (raw_data.get('alerts') or []) if a.get('level') == 'CRITICAL'],
        'last_scan': core_utils.get_last_scan_time(),
        'collector_status': core_utils.check_collector_status() 
    }

    try:
        live_ports = network_scanner.get_live_port_data()
        
        data['metrics']['port_list'] = {
            'port_list': live_ports,
            'exposed_details': []
        }
    except Exception as e:
        print(f"Port Scan Error: {e}")
        data['metrics']['port_list'] = {'port_list': []}

    
    analytics = {
        'top_ips': analytics_db.get('top_ips', []),
        'heatmap_data': heatmap,
        'volume_labels': ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"],
        'volume_data': volume,
        'firewall_stats': firewall,
        'top_processes': system_monitor.get_top_processes(),
        
        'audit_log': [
            {'user': 'root', 'cmd': 'systemctl restart nginx', 'ip': '192.168.1.5', 'time': '10:45'},
            {'user': 'zgr', 'cmd': 'vim /etc/passwd', 'ip': '192.168.1.20', 'time': '10:30'}
        ],
        'blocked_countries': [
            {'code': 'CN', 'name': 'China', 'count': 1204, 'percent': 85, 'color': 'danger'},
            {'code': 'RU', 'name': 'Russia', 'count': 842, 'percent': 65, 'color': 'warning'},
            {'code': 'US', 'name': 'USA', 'count': 112, 'percent': 15, 'color': 'secondary'}
            
        ]
    }

    try:
        risk_score = int(data['metrics'].get('risk_score', 0))
        if risk_score > 0:
            failed_login_count = int(data['metrics'].get('failed_logins', 0))
            alert_count = len(data['alerts'])
            
            failed_contrib = min((failed_login_count * 5), 50)
            anomaly_contrib = min((alert_count * 10), 50)
            
            data['risk_breakdown'] = {'failed_auth_pct': int(failed_contrib), 'anomaly_pct': int(anomaly_contrib)}
        else:
            data['risk_breakdown'] = {'failed_auth_pct': 0, 'anomaly_pct': 0}
    except:
        data['risk_breakdown'] = {'failed_auth_pct': 0, 'anomaly_pct': 0}

    return data, analytics

def enrich_events_with_geo(events):
    enriched = []
    for event in events:
        event_dict = dict(event)
        
        ip = event_dict.get('src_ip')
        event_dict['geo'] = network_scanner.get_ip_location(ip)
        
        enriched.append(event_dict)
    return enriched