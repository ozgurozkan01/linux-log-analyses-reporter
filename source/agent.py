# agent.py

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
import hashlib
import difflib
import utils
import concurrent.futures
import db
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

try:
    from config import Config
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from config import Config


def analyze_ssh_logs():
    failed_count = 0
    events = []
    
    MAX_EVENTS = Config.SSH_MAX_EVENTS
    BRUTE_FORCE_WINDOW = Config.SSH_BRUTE_FORCE_WINDOW
    BRUTE_FORCE_THRESHOLD = Config.SSH_BRUTE_FORCE_THRESHOLD

    since_time = utils.get_since_timestamp()

    cmd = [
        "journalctl",
        "-u", "ssh", 
        "-u", "sshd", 
        "--since", since_time,
        "--no-pager",
        "--output=short-iso"
    ]
    
    print(f"[LOG] Analyzing SSH logs since: {since_time}")
    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] START --- analyze_ssh_logs ---\n")

    fail_tracker = defaultdict(deque)

    rgx_ip = re.compile(r'from\s+([0-9a-fA-F:\.]+(?:%[a-zA-Z0-9]+)?)')
    rgx_user_fail = re.compile(r'for\s+(?:invalid user\s+)?([\w\.-]+)')
    rgx_user_succ = re.compile(r'for\s+([\w\.-]+)\s+from')

    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1) as proc:
            
            for line in proc.stdout:
                if "password" not in line and "publickey" not in line:
                    continue

                if len(events) >= MAX_EVENTS:
                    break

                line = line.strip()
                if not line: continue

                try:
                    ts_str = line.split()[0] 
                    current_ts = datetime.fromisoformat(ts_str)
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

                    if recent_fails >= BRUTE_FORCE_THRESHOLD:
                        severity = "CRITICAL"
                        msg = f"Brute Force Detected ({recent_fails} attempts)"
                        event_type = "SSH_BRUTE_FORCE"
                    else:
                        severity = "HIGH"
                        msg = "Invalid SSH attempt"
                        event_type = "SSH_AUTH_FAIL"

                    details_str = (
                        f"Event Type: {event_type}\n"
                        f"User: {username}\n"
                        f"Source IP: {src_ip}\n"
                        f"Protocol: SSH (Port 22)\n"
                        f"Attempt Count: {recent_fails}\n"
                        f"Analysis: {msg}\n"
                    )

                    events.append({
                        "type": event_type,
                        "source": src_ip,
                        "user": username,
                        "severity": severity,
                        "msg": f"{msg} from {src_ip}",
                        "details": details_str
                    })

                elif "Accepted password" in line or "Accepted publickey" in line:
                    ip_match = rgx_ip.search(line)
                    user_match = rgx_user_succ.search(line)

                    src_ip = ip_match.group(1) if ip_match else "Local"
                    username = user_match.group(1) if user_match else "Unknown"

                    severity = "INFO"
                    msg = "Valid SSH login"
                    event_type = "SSH_AUTH_SUCCESS"

                    recent_fails = len(fail_tracker.get(src_ip, []))
                    if recent_fails >= BRUTE_FORCE_THRESHOLD:
                        severity = "CRITICAL"
                        msg = "SUCCESSFUL LOGIN AFTER BRUTE FORCE ATTACK!"
                        event_type = "SSH_COMPROMISE"
                        fail_tracker[src_ip].clear()

                    details_str = (
                        f"Event Type: {event_type}\n"
                        f"User: {username}\n"
                        f"Source IP: {src_ip}\n"
                        f"Protocol: SSH\n"
                        f"Analysis: Access granted.\n"
                    )

                    events.append({
                        "type": event_type,
                        "source": src_ip,
                        "user": username,
                        "severity": severity,
                        "msg": f"{msg} for {username}",
                        "details": details_str
                    })

    except Exception as e:
        print(f"[ERROR] SSH Log Processing Failed: {e}")
        return 0, []

    failed_count = sum(1 for e in events if "FAIL" in e["type"] or "BRUTE" in e["type"])
    
    return failed_count, events

def analyze_sudo_logs():
    events = []
    
    MAX_EVENTS = Config.SUDO_MAX_EVENTS
    SENSITIVE_FILES = Config.SUDO_SENSITIVE_FILES
    NORMAL_COOLDOWN = Config.SUDO_NORMAL_COOLDOWN
    CRITICAL_COOLDOWN = Config.SUDO_CRITICAL_COOLDOWN
    since_time = utils.get_since_timestamp()
    
    cmd = ["journalctl", "-t", "sudo", "--since", since_time, "--no-pager", "--output=short-iso"]
    
    print(f"[LOG] Analyzing SUDO commands (High Performance Mode) since: {since_time}")
    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] START --- analyze_sudo_logs ---")

    last_sudo_map = defaultdict(lambda: datetime.min)

    rgx_meta = re.compile(r'sudo\[(\d+)\]:\s+(\S+)\s+:')
    
    gtfobins_risky = {'find', 'awk', 'nmap', 'man', 'less', 'more', 'vi', 'vim', 'gdb', 'tar', 'zip'}
    priv_escalation_bins = {'chmod', 'chown', 'chgrp', 'passwd', 'useradd', 'usermod'}
    shell_bins = {'bash', 'sh', 'zsh', 'su'}
    net_bins = {'wget', 'curl', 'nc', 'netcat', 'socat'}
    read_bins = {'cat', 'head', 'tail', 'grep', 'more', 'less'}

    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1) as proc:
            
            for line in proc.stdout:
                
                if "COMMAND=" not in line:
                    continue

                if len(events) >= MAX_EVENTS:
                    break

                if len(last_sudo_map) > 5000:
                    last_sudo_map.clear()

                line = line.strip()

                try:
                    ts_str = line.split()[0]
                    current_ts = datetime.fromisoformat(ts_str).replace(tzinfo=None)
                except:
                    current_ts = datetime.now().replace(tzinfo=None)

                meta_match = rgx_meta.search(line)
                
                try:
                    cmd_part = line.split("COMMAND=", 1)[1].strip()
                except IndexError:
                    continue

                pid = meta_match.group(1) if meta_match else "N/A"
                user = meta_match.group(2).strip() if meta_match else "unknown"
                full_command = cmd_part
                
                parts = full_command.split()
                if not parts: continue
                
                binary = parts[0]
                if "/" in binary: binary = binary.split("/")[-1]
                
                args = " ".join(parts[1:]) 

                severity = "INFO"
                event_type = "GENERAL_SUDO"

                if binary in gtfobins_risky and any(x in args for x in ['-exec', 'system', 'spawn', '!/bin/sh', '--interactive']):
                    severity = "CRITICAL"
                    event_type = "SHELL_ESCAPE_ATTEMPT"
                
                elif binary in ['vi', 'vim', 'nano'] and any(s in args for s in SENSITIVE_FILES):
                    severity = "CRITICAL"
                    event_type = "SENSITIVE_EDIT"
                
                elif binary in shell_bins:
                    severity = "CRITICAL"
                    event_type = "DIRECT_SHELL_ACCESS"

                elif binary in read_bins and any(s in args for s in SENSITIVE_FILES):
                    severity = "CRITICAL"
                    event_type = "SENSITIVE_READ"

                elif binary in priv_escalation_bins:
                    severity = "HIGH"
                    event_type = "PRIVILEGE_MODIFICATION"

                elif binary in ['vi', 'vim', 'nano']:
                    severity = "HIGH"
                    event_type = "UNSAFE_EDITOR"

                elif binary in net_bins:
                    severity = "HIGH"
                    event_type = "NETWORK_TOOL"
                
                elif "/root/" in args:
                    severity = "WARNING"
                    event_type = "ROOT_DIR_ACCESS"

                elif binary in ['rm', 'dd', 'mkfs', 'fdisk', 'shred']:
                    severity = "WARNING"
                    event_type = "DESTRUCTIVE_OP"

                wait_time = CRITICAL_COOLDOWN if severity == "CRITICAL" else NORMAL_COOLDOWN
                cooldown_key = (user, full_command)
                
                if (current_ts - last_sudo_map[cooldown_key]).total_seconds() < wait_time:
                    continue
                last_sudo_map[cooldown_key] = current_ts

                details_str = (
                    f"Event Type: {event_type}\n"
                    f"User: {user}\n"
                    f"Command: {full_command}\n"
                    f"PID: {pid}\n"
                    f"Binary: {binary}\n"
                    f"Severity: {severity}\n"
                )

                events.append({
                    "type": event_type,
                    "source": "Local",
                    "user": user,
                    "severity": severity,
                    "msg": f"[{event_type}] {full_command}",
                    "details": details_str
                })

    except Exception as e:
        print(f"[ERROR] Sudo Log Processing Failed: {e}")
        return []

    return events

def analyze_audit_logs():
    events = []
    
    if shutil.which("ausearch") is None:
        print("[ERROR] 'ausearch' komutu bulunamadı. Auditd yüklü mü?")
        return events

    cmd = ["ausearch", "-k", "process_monitor", "-i", "-ts", "recent"]

    print(f"[LOG] Auditd logları analiz ediliyor (Process Monitor)...")
    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] START --- analyze_audit_logs ---\n") # <-- ADD THIS LINE

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
    
    perm_mod_regex = re.compile(r'\b(chmod|chown|chgrp)\b')
    
    critical_files = {'/etc/shadow', '/etc/passwd', '/etc/sudoers', '/var/log/auth.log'}

    try:
        raw_output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
        
        if len(raw_output) < 10:
            print("[DEBUG] Auditd log çıktısı boş veya çok kısa.")
        
        dedup_map = {}

        for line in raw_output.splitlines():
            line = line.strip()
            if not line: continue
            
            if "type=SYSCALL" in line or "type=EXECVE" in line:
                
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

                if "collector.py" in full_cmd or "ausearch" in full_cmd or "agent.py" in full_cmd:
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

                elif perm_mod_regex.search(full_cmd):
                    risk_score = max(risk_score, 3)
                    alert_type = "PERM_MODIFICATION"
                    details.append("Critical Permission/Ownership Change")

                if "rm " in full_cmd and "/var/log" in full_cmd:
                    risk_score = max(risk_score, 4)
                    alert_type = "LOG_WIPING"
                    details.append("Evidence Destruction Attempt")
                
                if uid == "root" and auid != "root" and auid != "unset" and auid != "4294967295":
                    risk_score = max(risk_score, 4)
                    alert_type = "PRIV_ESCALATION"
                    details.append(f"User {auid} became ROOT")

                severity_map = {1: "INFO", 2: "WARNING", 3: "HIGH", 4: "CRITICAL"}
                severity = severity_map.get(risk_score, "INFO")
                
                msg_body = f"{alert_type}: {full_cmd}"
                if details:
                    msg_body += f" ({', '.join(details)})"

                event_key = f"{auid}:{full_cmd}:{alert_type}"
                
                dedup_map[event_key] = {
                    "type": alert_type,
                    "source": "Auditd",
                    "user": f"{auid}->{uid}",
                    "severity": severity,
                    "msg": msg_body,
                    "details": "\n".join(details) if details else "Process execution logged via Auditd"
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
                            "msg": f"Critical File Access: {filename}",
                            "details": f"Direct file access detected by kernel audit.\nFile: {filename}"
                        }

        events = list(dedup_map.values())

    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return [] 
        print(f"[ERROR] Auditd komut hatası: {e}")
        return []
        
    except Exception as e:
        print(f"[ERROR] Auditd genel hata: {e}")
        return []

    return events

def analyze_file_integrity():
    events = []
    
    CRITICAL_FILES = Config.FIM_TARGETS
    SAFE_CHANGES = Config.FIM_SAFE_CHANGES
    MAX_FILE_SIZE = Config.FIM_MAX_FILE_SIZE

    print("[LOG] FIM (File Integrity Monitoring) scanning...")
    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] START --- analyze_fim_logs ---\n")

    start_time = time.time()

    for filepath in CRITICAL_FILES:
        event_time = datetime.now(timezone.utc).isoformat()

        if not os.path.exists(filepath):
            stored_data = db.get_file_baseline(filepath)
            
            if stored_data:
                old_inode = stored_data['inode']
                new_path = utils.find_renamed_file(old_inode) 
                
                if new_path:
                    old_dir, old_name = os.path.split(filepath)
                    new_dir, new_name = os.path.split(new_path)
                    
                    try:
                        new_stat = os.stat(new_path)
                        new_uid = new_stat.st_uid
                        new_gid = new_stat.st_gid
                        new_perms = oct(new_stat.st_mode)[-3:]
                    except:
                        new_uid, new_gid, new_perms = "Unknown", "Unknown", "Unknown"

                    new_hash = "Unknown"
                    try:
                        sha256_hash = hashlib.sha256()
                        with open(new_path, "rb") as f:
                            for byte_block in iter(lambda: f.read(4096), b""):
                                sha256_hash.update(byte_block)
                        new_hash = sha256_hash.hexdigest()
                    except Exception as e:
                        print(f"[ERROR] Hash calculation failed during rename check: {e}")

                    event_type = "FIM_TRACKING"
                    status_desc = "Inode match found."

                    if old_dir == new_dir and old_name != new_name:
                        msg = f"FILE RENAMED: {old_name} -> {new_name}"
                        event_type = "FIM_RENAME"
                    elif old_dir != new_dir:
                        msg = f"FILE MOVED: {filepath} -> {new_path}"
                        event_type = "FIM_MOVED"

                    details_str = (
                        f"Event Type: {event_type}\n"
                        f"Original Path: {filepath}\n"
                        f"New Path: {new_path}\n"
                        f"Inode: {old_inode} (Preserved)\n"
                        f"UID: {new_uid}\n"        
                        f"GID: {new_gid}\n"        
                        f"Old Permissions: {stored_data['perms']}\n"  
                        f"New Permissions: {new_perms}\n"             
                        f"Old Hash: {stored_data['hash']}\n"          
                        f"New Hash: {new_hash}\n"                     
                        f"Analysis: {status_desc}"
                    )
                    
                    events.append({
                        "timestamp": event_time, "type": event_type, "source": "Local/FIM",
                        "user": "System", "severity": "HIGH", "msg": msg, "details": details_str
                    })
                    
                else:
                    msg = f"CRITICAL FILE MISSING: {filepath}"

                    last_uid = stored_data.get('uid', 'N/A')
                    last_gid = stored_data.get('gid', 'N/A')
                    last_perms = stored_data.get('permissions', 'N/A')
                    if last_perms == 'N/A': 
                        last_perms = stored_data.get('perms', 'N/A')

                    details_str = (
                        f"Event Type: FIM_MISSING\n"
                        f"Original Path: {filepath}\n"
                        f"Inode: {old_inode}\n"            
                        f"UID: {last_uid}\n"               
                        f"GID: {last_gid}\n"               
                        f"Old Permissions: {last_perms}\n" 
                        f"Analysis: File has been permanently removed from disk.\n"
                    )
                    events.append({
                        "timestamp": event_time, "type": "FIM_MISSING", "source": "Local/FIM",
                        "user": "System", "severity": "CRITICAL", "msg": msg, "details": details_str
                    })
            continue

        try:
            file_stat = os.stat(filepath)
            current_perms = oct(file_stat.st_mode)[-3:]
            current_uid = file_stat.st_uid
            current_gid = file_stat.st_gid
            current_inode = file_stat.st_ino
            current_mtime = file_stat.st_mtime
            
            stored_data = db.get_file_baseline(filepath)

            if  stored_data and stored_data['inode'] == current_inode and stored_data.get('mtime') == current_mtime and stored_data.get('perms') == current_perms and stored_data.get('uid') == current_uid and stored_data.get('gid') == current_gid:        

                print(f"   [FAST SKIP] {filepath} (No changes)") 
                continue

            print(f"   [HEAVY SCAN] {filepath} (Calculating Hash...)")

            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            current_hash = sha256_hash.hexdigest()

            current_content = ""
            is_binary_or_large = False
            if file_stat.st_size > MAX_FILE_SIZE:
                current_content = "[INFO] File too large"
                is_binary_or_large = True
            else:
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='strict') as f:
                        current_content = f.read()
                except:
                    current_content = "[INFO] Binary"
                    is_binary_or_large = True

            if stored_data is None:
                db.update_file_baseline(filepath, current_hash, current_content, current_perms, current_uid, current_gid, current_inode, current_mtime)
                continue

            base_severity = "CRITICAL"
            if filepath in SAFE_CHANGES: base_severity = "INFO"

            if stored_data['inode'] != current_inode:
                msg = f"FILE REPLACEMENT DETECTED: {filepath}"
                details_str = (
                    f"Event Type: FIM_INODE_CHANGE\n"
                    f"Original Path: {filepath}\n"
                    f"UID: {current_uid}\n"        
                    f"GID: {current_gid}\n"        
                    f"Old Inode: {stored_data['inode']}\n" 
                    f"New Inode: {current_inode}\n"       
                    f"Old Permissions: {stored_data['perms']}\n"
                    f"New Permissions: {current_perms}\n"
                    f"Analysis: File deleted and recreated (Inode mismatch).\n"
                )
                events.append({
                    "timestamp": event_time, "type": "FIM_INODE_CHANGE", "source": "Local/FIM",
                    "user": "System", "severity": base_severity, "msg": msg, "details": details_str
                })
                db.update_file_baseline(filepath, current_hash, current_content, current_perms, current_uid, current_gid, current_inode, current_mtime)

            elif current_hash != stored_data['hash']:
                msg = f"FILE CONTENT CHANGED: {filepath}"
                
                diff_output = "No readable text diff available."
                if not is_binary_or_large:
                    old_content = stored_data['content'] if stored_data['content'] else ""
                    diff = list(difflib.unified_diff(
                        old_content.splitlines(), current_content.splitlines(), 
                        lineterm='', n=3
                    ))
                    if len(diff) > 2:
                        diff_output = "\n".join(diff[2:])

                details_str = (
                    f"Event Type: FIM_CONTENT_CHANGE\n"
                    f"Original Path: {filepath}\n"
                    f"UID: {current_uid}\n"
                    f"GID: {current_gid}\n"
                    f"Inode: {current_inode}\n"                 
                    f"Old Permissions: {stored_data['perms']}\n"  
                    f"New Permissions: {current_perms}\n"        
                    f"Old Hash: {stored_data['hash']}\n"
                    f"New Hash: {current_hash}\n"
                    f"Analysis: File content modified.\n"
                    f"---DIFF START---\n{diff_output}\n---DIFF END---"
                )

                events.append({
                    "timestamp": event_time, "type": "FIM_CONTENT_CHANGE", "source": "Local/FIM",
                    "user": "System", "severity": base_severity, "msg": msg, "details": details_str
                })
                db.update_file_baseline(filepath, current_hash, current_content, current_perms, current_uid, current_gid, current_inode, current_mtime)

            elif (current_perms != stored_data['perms'] or current_uid != stored_data['uid'] or current_gid != stored_data['gid']):
                
                msg = f"FILE METADATA CHANGED: {filepath}"
                
                details_str = (
                    f"Event Type: FIM_METADATA_CHANGE\n"
                    f"Original Path: {filepath}\n"
                    f"UID: {current_uid} (Old: {stored_data['uid']})\n"
                    f"GID: {current_gid} (Old: {stored_data['gid']})\n"
                    f"Inode: {current_inode}\n"
                    f"Old Permissions: {stored_data['perms']}\n"
                    f"New Permissions: {current_perms}\n"
                    f"Old Hash: {stored_data['hash']}\n"
                    f"New Hash: {current_hash}\n"
                    f"Analysis: Ownership or permissions modified.\n"
                )
                
                events.append({
                    "timestamp": event_time, "type": "FIM_PERM_CHANGE", "source": "Local/FIM",
                    "user": "System", "severity": "WARNING", "msg": msg, "details": details_str
                })

                db.update_file_baseline(filepath, current_hash, current_content, current_perms, current_uid, current_gid, current_inode, current_mtime)

        except Exception as e:
            print(f"[ERROR] FIM check failed for {filepath}: {e}")


    end_time = time.time()
    duration = end_time - start_time
    print(f"[RESULT] FIM Scan Completed in {duration:.4f} seconds.\n")
    
    return events

def analyze_firewall_logs():
    events = []
    since_time = utils.get_since_timestamp()
    
    cmd = f"journalctl -k --since '{since_time}' --no-pager --output=short-iso"
    
    critical_ports = Config.FW_CRITICAL_PORTS
    TIME_WINDOW = Config.FW_TIME_WINDOW
    HIT_THRESHOLD = Config.FW_HIT_THRESHOLD
    UNIQUE_PORT_THRESHOLD = Config.FW_UNIQUE_PORT_THRESHOLD
    COOLDOWN = Config.FW_COOLDOWN

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
    utils.is_root()
    print("\n--- MiniSIEM Collector Starting... ---\n")

    db.init_db()
    utils.collect_system_status()
    
    cpu, ram, disk, ports, port_details = utils.collect_performance()

    failed_logins = 0
    ssh_events = []
    sudo_events = []
    firewall_events = []
    fim_events = []
    audit_events = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        print("[LOG] Starting parallel log analysis...")
        
        future_ssh = executor.submit(analyze_ssh_logs)
        future_sudo = executor.submit(analyze_sudo_logs)
        future_firewall = executor.submit(analyze_firewall_logs)
        future_fim = executor.submit(analyze_file_integrity)
        future_audit = executor.submit(analyze_audit_logs)

        try:
            failed_logins, ssh_events = future_ssh.result()
            print(f"[RESULT] SSH analysis complete. Found {len(ssh_events)} events.")
        except Exception as e:
            print(f"[ERROR] The SSH analysis task failed: {e}")

        try:
            sudo_events = future_sudo.result()
            print(f"[RESULT] Sudo analysis complete. Found {len(sudo_events)} events.")
        except Exception as e:
            print(f"[ERROR] The Sudo analysis task failed: {e}")
            
        try:
            firewall_events = future_firewall.result()
            print(f"[RESULT] Firewall analysis complete. Found {len(firewall_events)} events.")
        except Exception as e:
            print(f"[ERROR] The Firewall analysis task failed: {e}")
            
        try:
            fim_events = future_fim.result()
            print(f"[RESULT] FIM analysis complete. Found {len(fim_events)} events.")
        except Exception as e:
            print(f"[ERROR] The FIM analysis task failed: {e}")

        try:
            audit_events = future_audit.result()
            print(f"[RESULT] Auditd analysis complete. Found {len(audit_events)} events.")
        except Exception as e:
            print(f"[ERROR] The Auditd analysis task failed: {e}")

    print(f"\n[LOG] All analysis tasks finished.")
    
    if audit_events:
        print(f"[DEBUG] {len(audit_events)} Audit Events were captured.")
        for evt in audit_events:
            print(f"   -> {evt['type']} | {evt['severity']} | {evt['msg']}")

    events_for_risk_calc = audit_events + fim_events + ssh_events + sudo_events
    
    risk_score, risk_engine_alerts = risk_engine.calculate_risk(
        failed_logins, ports, cpu, ram, disk, events_for_risk_calc
    )

    print(f"\n[RESULT] Risk Score: {risk_score}/100")
    print("[DB] Data being recorded...")
    
    db.insert_metrics(failed_logins, ports, port_details, cpu, ram, disk, risk_score)
    
    all_events = ssh_events + sudo_events + audit_events + firewall_events + fim_events
    
    for log in all_events:
        db.insert_event(log['type'], log['source'], log['user'], log['severity'], log['msg'])
        
        if log['type'] in ["NETFILTER", "PORT_SCAN", "FLOOD_DETECTED", "CRITICAL_PORT", "XMAS_SCAN", "NULL_SCAN", "SYN_FLOOD"]:
            action = "BLOCK" if "ACTION=BLOCK" in log['msg'] or "ACTION=DROP" in log['msg'] else "ALLOW"
            protocol = "UDP" if "PROTO=UDP" in log['msg'] else ("ICMP" if "PROTO=ICMP" in log['msg'] else "TCP")
            src = log['source']
            dst_port = 0
            try:
                import re
                port_match = re.search(r'DPT=(\d+)', log['msg'])
                if port_match: dst_port = int(port_match.group(1))
            except: pass
            db.insert_firewall_log(action, protocol, src, dst_port)
    
    detailed_sources = fim_events + ssh_events + sudo_events + audit_events
    print(f"[DEBUG] Alarm control is being performed. Total candidate events: {len(detailed_sources)}")

    for evt in detailed_sources:
        if evt['severity'] in ['CRITICAL', 'HIGH', 'WARNING']:
            display_title = evt['msg']
            if len(display_title) > 60: display_title = display_title[:57] + "..."
            
            details_content = evt.get('details', 'No detailed breakdown available.')

            event_score = risk_engine.RISK_SCORES.get(evt['type'], risk_engine.SEVERITY_SCORES.get(evt['severity'], 0))

            db.insert_alert(
                level=evt['severity'],
                title=display_title,
                description=f"Detected by {evt['type']} module on {evt['source']}",
                details=details_content,
                score=event_score
            )
            print(f"   >>> [ALARM CREATED] {evt['type']}: {display_title}")

            try:
                import notifier 
                notifier.send_discord_alert(
                    title=display_title,
                    description=f"Source: {evt['source']} | Type: {evt['type']}",
                    level=evt['severity'],
                    details=details_content
                )
            except ImportError:
                pass
            except Exception as e:
                print(f"[WARNING] Notification could not be sent: {e}")

    for ra in risk_engine_alerts:
        score_val = ra.get('score_impact')

        db.insert_alert(
            level=ra['level'].upper(),
            title=ra['title'],
            description=ra['msg'], 
            details=ra.get('details'),
            score=score_val  
        )

        print(f"   !!! [SYSTEM ALARM] {ra['title']} (Impact Score: {score_val})")
        
        if ra['level'].upper() in ['CRITICAL', 'HIGH']:
            try:
                import notifier
                notifier.send_discord_alert(
                    title=ra['title'],
                    description=ra['msg'],
                    level=ra['level'].upper(),
                    details=ra.get('details', 'Risk threshold exceeded.')
                )
            except ImportError:
                pass 
            except Exception as e:
                print(f"[WARNING] Notification error: {e}")

    db.maintenance(retention_days=7)
    utils.update_cursor()
    print("\n--- Process Complete ---")

if __name__ == "__main__":
    run()