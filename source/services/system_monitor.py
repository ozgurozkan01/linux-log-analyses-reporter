
import db
import socket
import psutil
import os
import json
from datetime import datetime

# Services
from services import core_utils

def get_live_system_stats():
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory().percent
    processes = get_top_processes() 
    last_scan_time = core_utils.get_last_scan_time()

    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime_str = str(datetime.now() - boot_time).split('.')[0]
    
    return {'cpu': cpu, 'ram': ram, 'uptime': uptime_str, 'processes': processes, 'last_scan': last_scan_time}

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