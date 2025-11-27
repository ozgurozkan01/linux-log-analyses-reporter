import sys
import os
import time
import socket
import platform
import psutil       
import subprocess   
import re         
import risk_engine   
import json
from datetime import datetime

try:
    import db
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    import db

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CURSOR_FILE = os.path.join(BASE_DIR, "last_scan_cursor.txt")
LOOKBACK_MINUTES = 30

def is_root():
    if os.geteuid() != 0:
        print("[ERROR] This script should run with root permissions.")
        print("Otherwise, access to the file is blocked.")
        sys.exit(1)

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

        os_info = f"{platform.system()} {platform.release()}"
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_str = str(datetime.now() - boot_time).split('.')[0]

        db.insert_system_info(hostname, ip_address, os_info, uptime_str)
        print(f"[SYSTEM] {hostname} ({ip_address}) | Uptime: {uptime_str}")

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

def update_cursor():
    try:
        with open(CURSOR_FILE, 'w') as f:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(now_str)
    except Exception as e:
        print(f"[ERROR] Could not update cursor file: {e}")


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

def analyze_ssh_logs():
    failed_count = 0
    events = []
    
    since_time = get_since_timestamp()
    
    cmd = f"journalctl -u ssh -u sshd --since '{since_time}' --no-pager"
    
    print(f"[LOG] Analyzing logs since: {since_time}")

    try:
        raw_output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
        
        regex_ip = re.compile(r'from (\d+\.\d+\.\d+\.\d+)')
        regex_user = re.compile(r'for (invalid user )?(\w+)')

        for line in raw_output.split('\n'):
            line = line.strip()
            if not line: continue

            if "Failed password" in line:
                failed_count += 1
                
                ip_match = regex_ip.search(line)
                user_match = regex_user.search(line)
                
                src_ip = ip_match.group(1) if ip_match else "Unknown"
                username = user_match.group(2) if user_match else "Unknown"

                events.append({
                    "type": "AUTH_FAILURE",
                    "source": src_ip,
                    "user": username,
                    "severity": "WARNING",
                    "msg": "Invalid SSH attempt"
                })

            elif "Accepted password" in line or "Accepted publickey" in line:
                ip_match = regex_ip.search(line)
                user_match = regex_user.search(line)
                
                user_match_success = re.search(r'for (\w+) from', line)
                
                src_ip = ip_match.group(1) if ip_match else "Local"
                username = user_match_success.group(1) if user_match_success else "Unknown"

                events.append({
                    "type": "AUTH_SUCCESS",
                    "source": src_ip,
                    "user": username,
                    "severity": "INFO",
                    "msg": "Valid SSH login"
                })

    except subprocess.CalledProcessError:
        print("[ERROR] journalctl command failed to execute.")
    except Exception as e:
        print(f"[ERROR] Log analysis error: {e}")

    return failed_count, events

def analyze_sudo_logs():
    events = []
    
    since_time = get_since_timestamp()
    
    cmd = f"journalctl _COMM=sudo --since '{since_time}' --no-pager"
    
    print(f"[LOG] Analyzing SUDO commands since: {since_time}")
    
    try:
        raw_output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
        
        rgx_user = re.compile(r'sudo:\s+(\w+)\s+:\s+TTY=')
        
        rgx_command = re.compile(r'COMMAND=(.+)')

        for line in raw_output.split('\n'):
            if "COMMAND=" in line:
                user_match = rgx_user.search(line)
                cmd_match = rgx_command.search(line)
                
                user = user_match.group(1).strip() if user_match else "root"
                full_command = cmd_match.group(1).strip() if cmd_match else "unknown"
                
                clean_command = full_command
                if "/" in full_command:
                    clean_command = full_command

                severity = "INFO"
                msg_prefix = "Sudo Command"
                
                if "rm " in full_command or "mv " in full_command or "dd " in full_command:
                    severity = "WARNING"
                    msg_prefix = "Critical File Operation"
                
                elif "passwd" in full_command or "chmod" in full_command or "chown" in full_command:
                    severity = "WARNING"
                    msg_prefix = "Privilege Change"
                
                elif "vim" in full_command or "nano" in full_command or "cat" in full_command:
                     if "/etc/shadow" in full_command or "/etc/passwd" in full_command:
                         severity = "CRITICAL"
                         msg_prefix = "Sensitive File Access"
                     else:
                         severity = "INFO"

                events.append({
                    "type": "SUDO_EXEC",
                    "source": "Local",
                    "user": user,
                    "severity": severity,
                    "msg": f"{msg_prefix}: {clean_command}"
                })

    except Exception as e:
        print(f"[ERROR] Sudo log analysis failed: {e}")

    return events

def run():
    is_root()

    print("\n--- MiniSIEM Collector Starting... ---\n")

    db.init_db()
    collect_system_status()
    cpu, ram, disk, ports, port_details = collect_performance()
    failed_logins, logs = analyze_ssh_logs()
    risk_score, generated_alerts = risk_engine.calculate_risk(failed_logins, ports, cpu, ram, disk)
    
    print(f"\n[RESULT] Risk Score: {risk_score}/100")
    print("[DB] Data being recorded...")
    
    db.insert_metrics(failed_logins, ports, port_details, cpu, ram, disk, risk_score)
    
    for log in logs:
        db.insert_event(log['type'], log['source'], log['user'], log['severity'], log['msg'])
        if log['severity'] in ['WARNING', 'CRITICAL']:
            print(f"   >>> Incident Detected: {log['msg']} ({log['source']})")

    for alert in generated_alerts:
        db.insert_alert(alert[0], alert[1], alert[2])
        print(f"   !!! ALARM ACTIVATED: {alert[1]}")

    update_cursor()
    print("\n--- Process Complete ---")

if __name__ == "__main__":
    run()