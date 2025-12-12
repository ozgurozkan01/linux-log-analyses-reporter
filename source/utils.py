# utils.py

import os
import psutil
import subprocess
import json 
import sys
import socket
import platform
from pathlib import Path
from typing import Final
from datetime import datetime

try:
    from config import Config
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from config import Config

try:
    import db
except ImportError:
    from source import db

CURRENT_DIR    : Final = Config.SOURCE_DIR
PROJECT_ROOT   : Final = Config.ROOT_DIR
COLLECTOR_PATH : Final = os.path.join(Config.SOURCE_DIR, "agent.py")

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

    connections = [p for p in psutil.net_connections() if p.status == 'LISTEN']
    
    port_data_list = []
    seen_ports = set() 

    for conn in connections:
        port = conn.laddr.port
        
        if port in seen_ports:
            continue
        
        seen_ports.add(port)
        
        try:
            service_name = socket.getservbyport(port, 'tcp')
        except:
            service_name = "Unknown"

        port_data_list.append({
            "port": port,
            "service": service_name
        })
    
    port_data_list.sort(key=lambda x: x['port'])
    open_ports_count = len(port_data_list) 
    port_details_json = json.dumps(port_data_list)

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