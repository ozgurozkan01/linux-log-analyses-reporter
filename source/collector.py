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
import shutil
import binascii 
from collections import defaultdict, deque
from datetime import datetime, timedelta


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

    cmd = [
        "journalctl",
        "-u", "ssh", 
        "-u", "sshd", 
        "--since", since_time,
        "--no-pager",
        "--output=short-iso"
    ]
    
    print(f"[LOG] Analyzing SSH logs since: {since_time}")
    
    BRUTE_FORCE_WINDOW = 300 
    BRUTE_FORCE_THRESHOLD = 5

    fail_tracker = defaultdict(deque)

    try:
        raw_output = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL
        ).decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[ERROR] Journalctl failed: {e}")
        return 0, []

    rgx_ip = re.compile(r'from\s+([0-9a-fA-F:\.]+(?:%[a-zA-Z0-9]+)?)')
    rgx_user_fail = re.compile(r'for\s+(?:invalid user\s+)?([\w\.-]+)')
    rgx_user_succ = re.compile(r'for\s+([\w\.-]+)\s+from')

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            ts_str = line.split(' ')[0]
            ts_str = ts_str.split('+')[0].split('.')[0]
            current_ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
        except:
            current_ts = datetime.now()

        if "Failed password" in line:
            ip_match = rgx_ip.search(line)
            user_match = rgx_user_fail.search(line)

            src_ip = ip_match.group(1) if ip_match else "Unknown"
            username = user_match.group(1) if user_match else "Unknown"

            fail_tracker[src_ip].append(current_ts)

            while fail_tracker[src_ip]:
                if (current_ts - fail_tracker[src_ip][0]).total_seconds() > BRUTE_FORCE_WINDOW:
                    fail_tracker[src_ip].popleft()
                else:
                    break

            recent_fails = len(fail_tracker[src_ip])

            severity = "WARNING"
            msg = "Invalid SSH attempt"

            if recent_fails >= BRUTE_FORCE_THRESHOLD:
                severity = "CRITICAL"
                msg = f"Brute Force Detected ({recent_fails} attempts in 5min)"

            events.append({
                "type": "AUTH_FAILURE",
                "source": src_ip,
                "user": username,
                "severity": severity,
                "msg": f"{msg} at {ts_str}"
            })

        elif "Accepted password" in line or "Accepted publickey" in line:
            ip_match = rgx_ip.search(line)
            user_match = rgx_user_succ.search(line)

            src_ip = ip_match.group(1) if ip_match else "Local"
            username = user_match.group(1) if user_match else "Unknown"

            severity = "INFO"
            msg = "Valid SSH login"

            recent_fails = len(fail_tracker.get(src_ip, []))

            if recent_fails >= BRUTE_FORCE_THRESHOLD:
                severity = "CRITICAL"
                msg = "SUCCESSFUL LOGIN AFTER BRUTE FORCE ATTACK!"
                fail_tracker[src_ip].clear()

            events.append({
                "type": "AUTH_SUCCESS",
                "source": src_ip,
                "user": username,
                "severity": severity,
                "msg": f"{msg} at {ts_str}"
            })

    failed_count = sum(1 for e in events if e["type"] == "AUTH_FAILURE")
    
    return failed_count, events


def analyze_sudo_logs():
    events = []
    since_time = get_since_timestamp()
    
    cmd = ["journalctl", "-t", "sudo", "--since", since_time, "--no-pager", "--output=short-iso"]
    
    print(f"[LOG] Analyzing SUDO commands (Context-Aware) since: {since_time}")
    
    last_sudo_map = defaultdict(lambda: datetime.min)
    
    NORMAL_COOLDOWN = 10
    CRITICAL_COOLDOWN = 2

    try:
        raw_output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[ERROR] Journalctl error: {e}")
        return []

    rgx_meta = re.compile(r'sudo\[(\d+)\]:\s+(\S+)\s+:')
    rgx_command = re.compile(r'COMMAND=(.+)$')
    
    rgx_sensitive = re.compile(r'(/etc/shadow|/etc/passwd|/etc/sudoers|\.ssh/id_rsa|\.bash_history)')

    for line in raw_output.splitlines():
        line = line.strip()
        if not line or "COMMAND=" not in line: continue

        try:
            ts_str = line.split(' ')[0][:19]
            current_ts = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S')
        except:
            current_ts = datetime.now()

        meta_match = rgx_meta.search(line)
        cmd_match = rgx_command.search(line)
        
        pid = meta_match.group(1) if meta_match else "N/A"
        user = meta_match.group(2).strip() if meta_match else "unknown"
        full_command = cmd_match.group(1).strip() if cmd_match else "unknown"
        
        parts = full_command.split()
        binary = parts[0]
        if "/" in binary:
            binary = binary.split("/")[-1]
        
        args = " ".join(parts[1:]) 

        severity = "INFO"
        tags = []
        
        gtfobins_risky = ['find', 'awk', 'nmap', 'man', 'less', 'more', 'vi', 'vim', 'gdb', 'tar', 'zip']
        
        if binary in gtfobins_risky:
            if any(x in args for x in ['-exec', 'system', 'spawn', '!/bin/sh', '--interactive']):
                severity = "CRITICAL"
                tags.append("SHELL_ESCAPE_ATTEMPT")
            elif binary in ['vi', 'vim']:
                if rgx_sensitive.search(args):
                    severity = "CRITICAL"
                    tags.append("SENSITIVE_EDIT")
                else:
                    severity = "HIGH" 
                    tags.append("UNSAFE_EDITOR")
            else:
                severity = "INFO"
                tags.append("SYSTEM_TOOL")

        elif binary in ['bash', 'sh', 'zsh', 'su']:
            severity = "CRITICAL"
            tags.append("DIRECT_SHELL_ACCESS")

        elif binary in ['cat', 'head', 'tail', 'grep']:
            if rgx_sensitive.search(args):
                severity = "CRITICAL"
                tags.append("SENSITIVE_READ")
            elif "/root/" in args:
                severity = "WARNING" 
                tags.append("ROOT_DIR_ACCESS")
            else:
                severity = "INFO"
                tags.append("FILE_READ")

        elif binary in ['rm', 'dd', 'mkfs', 'fdisk', 'shred']:
            severity = "WARNING"
            tags.append("DESTRUCTIVE_OP")

        elif binary in ['wget', 'curl', 'nc', 'netcat', 'socat']:
            severity = "HIGH"
            tags.append("NETWORK_TOOL")
        elif binary in ['passwd', 'useradd', 'usermod', 'chmod', 'chown']:
            severity = "WARNING"
            tags.append("PRIVILEGE_MOD")

        if not tags:
            tags.append("GENERAL_SUDO")

        wait_time = CRITICAL_COOLDOWN if severity == "CRITICAL" else NORMAL_COOLDOWN
        
        cooldown_key = (user, full_command)
        
        if (current_ts - last_sudo_map[cooldown_key]).total_seconds() < wait_time:
            continue
        
        last_sudo_map[cooldown_key] = current_ts

        msg_prefix = " + ".join(tags)
        events.append({
            "type": "SUDO_EXEC",
            "source": "Local",
            "user": user,
            "severity": severity,
            "msg": f"[{msg_prefix}] (PID:{pid}): {full_command}"
        })

    return events

def analyze_audit_logs():
    events = []
    
    if shutil.which("ausearch") is None:
        return events

    start_time = (datetime.now() - timedelta(minutes=LOOKBACK_MINUTES + 1)).strftime("%H:%M:%S")
    
    cmd = ["ausearch", "-ts", start_time, "-i", "--input-logs"]

    print(f"[LOG] Auditd logları analiz ediliyor ({start_time} tarihinden beri)...")

    rgx_exe = re.compile(r'exe="([^"]+)"')
    rgx_cmd = re.compile(r'proctitle="?([^"]+)"?') 
    rgx_auid = re.compile(r'auid=(\S+)')
    rgx_uid = re.compile(r'uid=(\S+)')
    rgx_path = re.compile(r'name="([^"]+)"')

    suspicious_bins_regex = re.compile(r'\b(nc|ncat|netcat|nmap|tcpdump|wireshark|gdb|strace|ftpd|socat)\b')
    
    webshell_regex = re.compile(r'(?x)' 
        r'\b('
        r'(?:python[23]?|perl|ruby|lua|php[578]?)\s+-[cer]|'  
        r'(?:bash|sh|zsh|dash|ksh)\s+-[ic]|'                   
        r'/dev/(?:tcp|udp)/\d{1,3}\.\d{1,3}|'                  
        r'base64\s+-(?:d|D|decode)|'                           
        r'(?:wget|curl|fetch)\s+http'                          
        r')'
    )
    
    recon_regex = re.compile(r'\b(whoami|id|uname -a|cat /etc/issue)\b')
    
    critical_files = {'/etc/shadow', '/etc/passwd', '/etc/sudoers', '/var/log/auth.log'}

    try:
        raw_output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
        
        dedup_map = {}

        for line in raw_output.splitlines():
            line = line.strip()
            if not line: continue
            
            if "type=EXECVE" in line or "type=SYSCALL" in line:
                
                exe_match = rgx_exe.search(line)
                cmd_match = rgx_cmd.search(line)
                auid_match = rgx_auid.search(line)
                uid_match = rgx_uid.search(line)
                
                exe_path = exe_match.group(1) if exe_match else "unknown"
                raw_cmd = cmd_match.group(1) if cmd_match else exe_path
                
                try:
                    if len(raw_cmd) > 2 and all(c in '0123456789ABCDEFabcdef' for c in raw_cmd) and len(raw_cmd) % 2 == 0:
                        full_cmd = binascii.unhexlify(raw_cmd).decode('utf-8', errors='ignore')
                    else:
                        full_cmd = raw_cmd
                except:
                    full_cmd = raw_cmd

                full_cmd = full_cmd.replace("\x00", " ")

                auid = auid_match.group(1) if auid_match else "unset"
                uid = uid_match.group(1) if uid_match else "unset"

                if "collector.py" in full_cmd or "ausearch" in full_cmd:
                    continue

                risk_score = 1
                alert_type = "PROCESS_EXEC"
                details = []

                if suspicious_bins_regex.search(full_cmd):
                    risk_score = max(risk_score, 4)
                    alert_type = "HACKING_TOOL"
                    details.append("Suspicious Binary Detected")
                
                elif webshell_regex.search(full_cmd):
                    risk_score = max(risk_score, 4)
                    alert_type = "WEBSHELL_ACT"
                    details.append("Reverse Shell/Payload Signature")

                elif recon_regex.search(full_cmd):
                    risk_score = max(risk_score, 2)
                    if risk_score < 3: alert_type = "RECONNAISSANCE"
                    details.append("Enumeration Command")

                if "rm " in full_cmd and "/var/log" in full_cmd:
                    risk_score = max(risk_score, 4)
                    alert_type = "LOG_WIPING"
                    details.append("Evidence Destruction Attempt")
                
                if uid == "root" and auid != "root" and auid != "unset" and auid != "4294967295":
                    risk_score = max(risk_score, 4)
                    alert_type = "PRIV_ESCALATION"
                    details.append(f"User {auid} became ROOT")

                severity_map = {1: "INFO", 2: "WARNING", 3: "HIGH", 4: "CRITICAL"}
                severity = severity_map[risk_score]
                
                msg_body = f"{alert_type}: {full_cmd}"
                if details:
                    msg_body += f" ({', '.join(details)})"

                event_key = f"{auid}:{full_cmd}:{alert_type}"
                
                dedup_map[event_key] = {
                    "type": alert_type,
                    "source": "Auditd",
                    "user": f"{auid}->{uid}",
                    "severity": severity,
                    "msg": msg_body
                }

            elif "type=PATH" in line:
                name_match = rgx_path.search(line)
                if name_match:
                    filename = name_match.group(1)
                    if filename in critical_files:
                        dedup_map[f"file:{filename}"] = {
                            "type": "FILE_INTEGRITY",
                            "source": "Auditd",
                            "user": "kernel",
                            "severity": "HIGH",
                            "msg": f"Critical File Access: {filename}"
                        }

        events = list(dedup_map.values())

    except Exception as e:
        print(f"[ERROR] Auditd analiz hatası: {e}")

    return events

def analyze_firewall_logs():
    events = []
    since_time = get_since_timestamp()
    
    cmd = f"journalctl -k --since '{since_time}' --no-pager --output=short-iso"
    
    critical_ports = {'22','23','53','80','443','445','1433','3306','3389'}
    
    TIME_WINDOW = 30 
    HIT_THRESHOLD = 20 
    UNIQUE_PORT_THRESHOLD = 5
    COOLDOWN = 60

    patterns = {
        'src': re.compile(r'SRC=([0-9a-fA-F:\.]+)'),
        'dst': re.compile(r'DST=([0-9a-fA-F:\.]+)'),
        'spt': re.compile(r'SPT=(\d+)'),
        'dpt': re.compile(r'DPT=(\d+)'),
        'proto': re.compile(r'PROTO=([A-Z0-9]+)'),
        'in_if': re.compile(r'IN=([\w\d\.\-]+)'),
        'mac': re.compile(r'MAC=([0-9A-Fa-f:\.]+)'),
        'flags_hex': re.compile(r'FLAGS=0x([0-9A-Fa-f]+)'),
        'kernel_ts': re.compile(r'^\s*\[\s*(\d+\.\d+)\]'),
        'keywords': re.compile(r'\b(SYN|FIN|RST|ACK|PSH|URG)\b')
    }

    flag_map = {0x01:'FIN', 0x02:'SYN', 0x04:'RST', 0x08:'PSH', 0x10:'ACK', 0x20:'URG'}
    
    scan_tracker = defaultdict(lambda: deque(maxlen=1000))
    last_event_map = defaultdict(lambda: datetime.min)

    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time())
    except:
        boot_time = datetime.now()

    try:
        raw_output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
    except:
        return []

    for line in raw_output.splitlines():
        if not line.strip(): continue
        
        if not any(k in line for k in ('BLOCK','DROP','REJECT','DENY','UFW','IN=')): continue

        current_ts = datetime.now()
        ts_parsed = False
        
        try:
            ts_str = line.split(' ')[0]
            if '+' in ts_str: ts_str = ts_str.split('+')[0]
            current_ts = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S')
            ts_parsed = True
        except:
            pass

        if not ts_parsed:
            k_match = patterns['kernel_ts'].search(line)
            if k_match:
                uptime_seconds = float(k_match.group(1))
                current_ts = boot_time + timedelta(seconds=uptime_seconds)

        data = {}
        for k, rgx in patterns.items():
            m = rgx.search(line)
            data[k] = m.group(1) if m else None

        src_ip = data['src']
        if not src_ip: continue

        protocol = data['proto'] if data['proto'] else "UNKNOWN"
        flags = []
        
        if protocol == 'TCP':
            hex_match = patterns['flags_hex'].search(line)
            if hex_match:
                fv = int(hex_match.group(1), 16)
                for bit, name in flag_map.items():
                    if fv & bit: flags.append(name)
            flags += patterns['keywords'].findall(line)
            flags = list(set(flags))

        is_blocked = any(x in line for x in ["DROP","BLOCK","REJECT","DENY","UFW"])
        action = "BLOCK" if is_blocked else "LOG"

        dst_port = data['dpt']
        if dst_port or protocol == 'ICMP':
            track_port = dst_port if dst_port else "0"
            
            scan_tracker[src_ip].append((track_port, current_ts))
            
            while scan_tracker[src_ip]:
                oldest_port, oldest_ts = scan_tracker[src_ip][0]
                if (current_ts - oldest_ts).total_seconds() > TIME_WINDOW:
                    scan_tracker[src_ip].popleft()
                else:
                    break

        recent_hits = list(scan_tracker[src_ip])
        hit_count = len(recent_hits)
        unique_ports = len(set(p for p,t in recent_hits))

        severity = "INFO"
        event_type = "NETFILTER"
        desc = f"{protocol} Traffic Observed"

        if unique_ports >= UNIQUE_PORT_THRESHOLD:
            severity = "CRITICAL"
            event_type = "PORT_SCAN"
            desc = f"Port Scan Detected ({unique_ports} unique ports)"
        
        elif hit_count >= HIT_THRESHOLD:
            severity = "HIGH"
            event_type = "FLOOD_DETECTED"
            if protocol == 'ICMP':
                desc = f"ICMP Ping Flood Detected ({hit_count} packets)"
            elif protocol == 'UDP':
                desc = f"UDP Flood Detected ({hit_count} packets)"
            else:
                desc = f"High Traffic Dropped ({hit_count} packets)"
        
        elif dst_port in critical_ports and is_blocked:
            severity = "WARNING"
            event_type = "CRITICAL_PORT"
            desc = f"Blocked Access to Critical Port {dst_port}/{protocol}"
        
        elif protocol == 'TCP':
            if {"FIN","PSH","URG"}.issubset(flags):
                severity = "WARNING"
                event_type = "XMAS_SCAN"
                desc = "Xmas Scan Signature Detected"
            elif not flags:
                severity = "WARNING"
                event_type = "NULL_SCAN"
                desc = "Null Scan Signature Detected"
            elif hit_count > 20 and "SYN" in flags and "ACK" not in flags:
                severity = "HIGH"
                event_type = "SYN_FLOOD"
                desc = f"SYN Flood Pattern ({hit_count} packets)"

        if severity == "INFO" and action != "BLOCK":
            continue

        cooldown_key = (src_ip, event_type)
        if (current_ts - last_event_map[cooldown_key]).total_seconds() < COOLDOWN:
            continue
        
        last_event_map[cooldown_key] = current_ts

        flag_str = f"FLAGS={','.join(flags)} " if flags else ""
        full_msg = (
            f"{desc} | ACTION={action} SRC={src_ip} DST={data['dst']} "
            f"DPT={dst_port} PROTO={protocol} IF={data['in_if']} "
            f"{flag_str}MAC={data['mac']}"
        )

        events.append({
            "type": event_type,
            "source": src_ip,
            "user": "kernel",
            "severity": severity,
            "msg": full_msg
        })

    return events

def run():
    is_root()

    print("\n--- MiniSIEM Collector Starting... ---\n")

    db.init_db()
    collect_system_status()
    
    cpu, ram, disk, ports, port_details = collect_performance()
    failed_logins, ssh_events = analyze_ssh_logs()
    sudo_events = analyze_sudo_logs()
    audit_events = analyze_audit_logs()
    firewall_events = analyze_firewall_logs() 

    risk_score, generated_alerts = risk_engine.calculate_risk(failed_logins, ports, cpu, ram, disk)
    
    print(f"\n[RESULT] Risk Score: {risk_score}/100")
    print("[DB] Data being recorded...")
    
    db.insert_metrics(failed_logins, ports, port_details, cpu, ram, disk, risk_score)
    
    all_events = ssh_events + sudo_events + audit_events + firewall_events
    
    for log in all_events:
        db.insert_event(log['type'], log['source'], log['user'], log['severity'], log['msg'])
        
        if log['type'] in ["NETFILTER", "PORT_SCAN", "FLOOD_DETECTED", "CRITICAL_PORT", "XMAS_SCAN", "NULL_SCAN", "SYN_FLOOD"]:
            action = "ALLOW"
            if "ACTION=BLOCK" in log['msg']: action = "BLOCK"
            elif "ACTION=DROP" in log['msg']: action = "DROP"
            
            protocol = "TCP"
            if "PROTO=UDP" in log['msg']: protocol = "UDP"
            elif "PROTO=ICMP" in log['msg']: protocol = "ICMP"
            
            src = log['source']
            
            dst_port = 0
            import re
            port_match = re.search(r'DPT=(\d+)', log['msg'])
            if port_match:
                dst_port = int(port_match.group(1))
            
            db.insert_firewall_log(action, protocol, src, dst_port)

        if log['severity'] in ['WARNING', 'CRITICAL', 'HIGH']:
            print(f"   >>> ALERT: {log['msg']} ({log['user']})")

    for alert in generated_alerts:
        db.insert_alert(alert[0], alert[1], alert[2])
        print(f"   !!! ALARM ACTIVATED: {alert[1]}")

    db.maintenance(retention_days=7)

    update_cursor()
    print("\n--- Process Complete ---")

if __name__ == "__main__":
    run()