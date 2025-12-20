# utils.py

from common_libs import *
from config import Config
import urllib.request
import subprocess
import db
import requests
import ipaddress

CURRENT_DIR    : Final = Config.SOURCE_DIR
PROJECT_ROOT   : Final = Config.ROOT_DIR
COLLECTOR_PATH : Final = Config.COLLECTOR_PATH

CURSOR_FILE    : Final = Config.CURSOR_FILE
LOOKBACK_MINUTES = Config.LOOKBACK_MINUTES

def is_root():
    if os.geteuid() != 0:
        print("[ERROR] This script should run with root permissions.")
        print("Otherwise, access to the file is blocked.")
        sys.exit(1)

def update_cursor():
    try:
        with open(CURSOR_FILE, 'w') as f:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(now_str)
    except Exception as e:
        print(f"[ERROR] Could not update cursor file: {e}")


def get_firewall_stats():
    """
    Firewall loglarını analiz ederek Dashboard ve FW Stream için
    gerekli tüm istatistikleri üretir.
    """
    stats = {
        'traffic_labels': [],
        'traffic_values': [],
        'traffic_baseline': [],
        'network_analysis': {
            'internal': {'total': 0, 'allow': 0, 'block': 0, 'drop': 0},
            'external': {'total': 0, 'allow': 0, 'block': 0, 'drop': 0}
        },
        'actions': {'ALLOW': 0, 'BLOCK': 0},
        'scan_types': {},       
        'top_ports': [],
        'repeated_offenders': [],
        'geo_stats': {'Internal': 0, 'External': 0}
    }

    try:
        logs = db.query_all("SELECT * FROM firewall_logs WHERE timestamp > datetime('now', '-24 hours') ORDER BY timestamp ASC")

        hourly_traffic = {}
        
        for log in logs:
            try:
                ts_str = log['timestamp']
                if '.' in ts_str: ts_str = ts_str.split('.')[0]
                dt = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                
                if dt > datetime.now() - timedelta(hours=12):
                    hour_key = dt.strftime('%H:00')
                    hourly_traffic[hour_key] = hourly_traffic.get(hour_key, 0) + 1
            except:
                continue

            ip = log['src_ip']
            action = log['action'].upper()
            if action in ['DENY', 'REJECT']: action = 'BLOCK'
            
            if action in ['ALLOW', 'BLOCK']:
                stats['actions'][action] = stats['actions'].get(action, 0) + 1

            is_internal = False
            try:
                if ip and ip != '0.0.0.0':
                    if ipaddress.ip_address(ip).is_private:
                        is_internal = True
            except:
                pass 

            target_group = 'internal' if is_internal else 'external'
            
            stats['network_analysis'][target_group]['total'] += 1
            
            if action == 'ALLOW':
                stats['network_analysis'][target_group]['allow'] += 1
            elif action == 'BLOCK':
                stats['network_analysis'][target_group]['block'] += 1
            elif action == 'DROP':
                stats['network_analysis'][target_group]['drop'] += 1
            else:
                stats['network_analysis'][target_group]['block'] += 1

        sorted_hours = sorted(hourly_traffic.keys())
        stats['traffic_labels'] = sorted_hours
        stats['traffic_values'] = [hourly_traffic[h] for h in sorted_hours]
        stats['traffic_baseline'] = [int(v * 0.8) for v in stats['traffic_values']] # Yapay baseline

        stats['geo_stats']['Internal'] = stats['network_analysis']['internal']['total']
        stats['geo_stats']['External'] = stats['network_analysis']['external']['total']

        port_rows = db.query_all("""
            SELECT dst_port, count(*) as count 
            FROM firewall_logs 
            WHERE action IN ('BLOCK', 'DROP', 'DENY') AND timestamp > datetime('now', '-24 hours')
            GROUP BY dst_port ORDER BY count DESC LIMIT 5
        """)
        stats['top_ports'] = [dict(row) for row in port_rows]

        offender_rows = db.query_all("""
            SELECT src_ip, count(*) as count, max(timestamp) as last_seen
            FROM firewall_logs 
            WHERE action IN ('BLOCK', 'DROP', 'DENY') AND timestamp > datetime('now', '-24 hours')
            GROUP BY src_ip ORDER BY count DESC LIMIT 10
        """)
        
        for row in offender_rows:
            itype = 'External'
            try:
                if ipaddress.ip_address(row['src_ip']).is_private: itype = 'Internal'
            except: pass
            
            stats['repeated_offenders'].append({
                'ip': row['src_ip'],
                'count': row['count'],
                'type': itype,
                'last_seen': str(row['last_seen']).split('.')[0]
            })

    except Exception as e:
        print(f"[ERROR] get_firewall_stats failed: {e}")
    
    return stats

def get_live_system_stats():
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory().percent
    processes = get_top_processes() 
    last_scan_time = get_last_scan_time()

    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime_str = str(datetime.now() - boot_time).split('.')[0]
    
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

import psutil
import socket
import json
from datetime import datetime
import os

def get_service_name(port, protocol='tcp'):
    try:
        return socket.getservbyport(port, protocol).upper()
    except:
        return "UNKNOWN"

def get_ip_risk_score(ip):
    if ip in ['0.0.0.0', '::']: return 3
    if not ip.startswith('127.') and not ip.startswith('192.168.') and not ip.startswith('10.'): return 3
    if ip.startswith('192.168.') or ip.startswith('10.'): return 2
    return 1

def get_live_port_data():
    grouped_ports = {} 

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            port = conn.laddr.port
            ip = conn.laddr.ip
            
            service = get_service_name(port)
            if port == 3306: service = "MYSQL DATABASE"
            if port == 5432: service = "POSTGRESQL"
            if port == 53: service = "DOMAIN (DNS)"
            if port == 80 or port == 443: service = "WEB SERVER"
            if port == 22: service = "SSHD"

            if port not in grouped_ports:
                grouped_ports[port] = {
                    'port': port,
                    'service': service,
                    'status': 'ACTIVE',
                    'ips': [] 
                }
            
            if ip not in grouped_ports[port]['ips']:
                grouped_ports[port]['ips'].append(ip)
    
    result_list = list(grouped_ports.values())
    
    for item in result_list:
        item['ips'].sort(key=get_ip_risk_score, reverse=True)

    result_list.sort(key=lambda x: x['port'])
    
    return result_list

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
    
    public_ip_info = get_public_ip()

    if public_ip_info:
        net_info = {
            'public_ip': public_ip_info['ip'],
            'country_name': public_ip_info['country_name'],
            'country_code': public_ip_info['country_code'],
            'local_ip': get_local_ip(),
            'dns': get_primary_dns()
        }
    else:
        net_info = {
            'public_ip': 'Offline',
            'country_name': None,
            'country_code': None,
            'local_ip': get_local_ip(),
            'dns': get_primary_dns()
        }

    sys_info_current['ip_address'] = get_local_ip()
    
    dns_list = get_primary_dns()
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

    data = {
        'sys_info': sys_info_current,
        'net_info': net_info, # Burası artık yeni yapıyla uyumlu!
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
        'last_scan': get_last_scan_time(),
        'collector_status': check_collector_status() 
    }

    try:
        live_ports = get_live_port_data()
        
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
        'top_processes': get_top_processes(),
        
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

def get_top_processes(limit=8):
    process_map = {}
    cpu_count = psutil.cpu_count() or 1

    try:
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
            try:
                p_info = proc.info
                raw_cpu = p_info['cpu_percent']
                raw_mem = p_info['memory_percent'] or 0.0

                if (raw_cpu is None or raw_cpu <= 0.0) and raw_mem <= 0.0:
                    continue
                
                name = p_info['name'] or "Unknown"
                if name == "code": name = "VS Code"
                if name == "gnome-shell": name = "Gnome Shell"
                
                normalized_cpu = raw_cpu / cpu_count if raw_cpu else 0

                if name in process_map:
                    process_map[name]['cpu_percent'] += normalized_cpu
                    process_map[name]['memory_percent'] += raw_mem
                    process_map[name]['count'] += 1
                else:
                    process_map[name] = {
                        'pid': p_info['pid'], 
                        'name': name,
                        'username': p_info['username'],
                        'cpu_percent': normalized_cpu,
                        'memory_percent': raw_mem,
                        'count': 1
                    }
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
    except Exception as e:
        print(f"Process error: {e}")
        return []
    
    grouped_procs = list(process_map.values())
    
    for p in grouped_procs:
        p['cpu_percent'] = round(p['cpu_percent'], 1)
        p['memory_percent'] = round(p['memory_percent'], 1) 
        
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

def get_linux_distro_details():
    try:
        os_name = "Linux"
        os_version = ""
        
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("NAME="):
                        os_name = line.split("=")[1].strip().strip('"')
                    elif line.startswith("VERSION_ID="):
                        os_version = line.split("=")[1].strip().strip('"')
        
        return os_name, os_version
    except Exception:
        return "Linux", "Unknown"

def collect_system_status():
    try:
        hostname = socket.gethostname()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(('8.8.8.8', 1))
            ip_address = s.getsockname()[0]
        except Exception:
            ip_address = '127.0.0.1'
        finally:
            s.close()

        distro_name, distro_version = get_linux_distro_details()
        kernel = platform.release()
        arch = platform.machine()
        
        os_info = f"{distro_name} {distro_version} ({arch}) - Kernel: {kernel}"

        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_str = str(datetime.now() - boot_time).split('.')[0]

        db.insert_system_info(hostname, ip_address, os_info, uptime_str)
        print(f"[SYSTEM] {hostname} ({ip_address}) | OS: {os_info} | Uptime: {uptime_str}")

    except Exception as e:
        print(f"[ERROR] System information could not be read: {e}")


def get_since_timestamp():
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE, 'r') as f:
                last_time = f.read().strip()
                if last_time:
                    return last_time
        except Exception:
            pass
    return f"{LOOKBACK_MINUTES} minutes ago"

def collect_performance():
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    connections = psutil.net_connections(kind='inet')
    
    port_data_list = []
    seen_ports = set()

    risk_definitions = {
        3306: "MySQL Database: Exposing a database to the internet is highly risky and can lead to data breaches.",
        5432: "PostgreSQL Database: Public access can allow attackers to attempt brute-force logins.",
        6379: "Redis: Often unsecured, exposing it can lead to data theft or ransomware attacks.",
        27017: "MongoDB: Misconfigured instances are a common target for data exfiltration.",
        22: "SSH Service: Should be protected by a firewall and strong passwords if exposed.",
        3389: "RDP Service: A primary target for ransomware. Never expose without a VPN."
    }
    
    exposed_port_details = []

    for conn in connections:
        if conn.status != 'LISTEN':
            continue
            
        port = conn.laddr.port
        bind_ip = conn.laddr.ip
        
        if port in seen_ports:
            continue
        seen_ports.add(port)
        
        if port in risk_definitions:
            service_name = risk_definitions[port].split(':')[0]
        else:
            try:
                service_name = socket.getservbyport(port, 'tcp').upper()
            except:
                service_name = "UNKNOWN"
            
        is_exposed = bind_ip in ['0.0.0.0', '::']
        status = "EXPOSED" if is_exposed else "LISTEN"
        
        if is_exposed:
            port_info = {
                "port": port,
                "service": service_name,
                "explanation": risk_definitions.get(port, f"Port {port} ({service_name}) is open to all network interfaces.")
            }
            exposed_port_details.append(port_info)

        port_data_list.append({
            "port": port,
            "service": service_name,
            "status": status,
            "bind_ip": bind_ip
        })
    
    port_data_list.sort(key=lambda x: x['port'])
    open_ports_count = len(port_data_list) 
    
    final_port_package = {
        "port_list": port_data_list,
        "exposed_details": exposed_port_details
    }
    port_details_json = json.dumps(final_port_package)

    print(f"[PERFORMANCE] CPU: %{cpu} | RAM: %{ram} | Disk: %{disk} | Ports: {open_ports_count}")
    
    return cpu, ram, disk, open_ports_count, port_details_json

def calculate_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"[ERROR] Hash calculation error for {filepath}: {e}")
        return None

def find_renamed_file(target_inode, search_roots=None):
    if search_roots is None:
        search_roots = ["/home", "/tmp", "/etc", "/var", "/root", "/opt"]

    print(f"\n[DEBUG] DEDEKTİF: Inode {target_inode} için tüm sistem taranıyor...")
    
    try:
        target_inode = int(target_inode)
        
        for root_dir in search_roots:
            if not os.path.exists(root_dir): 
                continue
            
            for current_root, dirs, files in os.walk(root_dir, followlinks=True):
                
                if any(skip in current_root for skip in ["/proc", "/sys", "/dev", "/run", "/snap", "/.cache", "/.local"]):
                    continue
                
                if "Downloads" in current_root:
                    print(f"[DEBUG] -> Downloads klasörüne girildi: {current_root}")

                for name in files:
                    try:
                        full_path = os.path.join(current_root, name)
                        
                        if os.stat(full_path).st_ino == target_inode:
                            print(f"[DEBUG] BINGO! BULUNDU: {full_path}")
                            return full_path
                            
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
                        
    except Exception as e:
        print(f"[ERROR] Dedektif hata aldi: {e}")
    
    print("[DEBUG] Dedektif aradı ama bulamadı (Dosya silinmiş veya Inode değişmiş).")
    return None

def get_public_ip():
    public_ip = None
    
    try:
        response_ip = requests.get('https://api.ipify.org', timeout=5)
        response_ip.raise_for_status()
        public_ip = response_ip.text
    except requests.exceptions.RequestException:
        return None

    try:
        response_geo = requests.get(f'http://ip-api.com/json/{public_ip}', timeout=5)
        response_geo.raise_for_status()
        geo_data = response_geo.json()

        if geo_data.get('status') == 'success':
            return {
                'ip': public_ip,
                'country_name': geo_data.get('country'),
                'country_code': geo_data.get('countryCode')
            }
        else:
            return {
                'ip': public_ip,
                'country_name': 'N/A',
                'country_code': None
            }
            
    except requests.exceptions.RequestException:
        return {
            'ip': public_ip,
            'country_name': 'N/A',
            'country_code': None
        }

def get_primary_dns():
    dns_servers = []
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    ip = line.split()[1]
                    dns_servers.append(ip)
    except Exception:
        pass
    
    if dns_servers:
        return ", ".join(dns_servers[:2]) 
    return "Local (Stub)"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'