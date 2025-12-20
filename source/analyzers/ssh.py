import re
import socket
import subprocess
from datetime import datetime
from collections import defaultdict, deque
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from config import Config
import utils
import common_libs

def analyze_ssh_logs():
    failed_count = 0
    events = []
    
    MAX_EVENTS = Config.SSH_MAX_EVENTS
    BRUTE_FORCE_WINDOW = Config.SSH_BRUTE_FORCE_WINDOW
    BRUTE_FORCE_THRESHOLD = Config.SSH_BRUTE_FORCE_THRESHOLD

    since_time = utils.get_since_timestamp()
    
    cmd = Config.CMD_SSH_BASE + ["--since", since_time]
    
    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] START --- analyze_ssh_logs ---\n")

    fail_tracker = defaultdict(deque)
    alerted_sessions = set() 

    rgx_ts = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^ ]*)')
    rgx_ip = re.compile(r'from\s+([0-9a-fA-F:\.]+(?:%[a-zA-Z0-9]+)?)')
    rgx_user_fail = re.compile(r'for\s+(?:invalid user\s+)?([\w\.-]+)\s+from')
    rgx_user_succ = re.compile(r'for\s+([\w\.-]+)\s+from')
    
    current_host = socket.gethostname()

    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1) as proc:
            
            for line in proc.stdout:
                if "password" not in line and "publickey" not in line:
                    continue

                if len(events) >= MAX_EVENTS:
                    break

                line = line.strip()
                if not line: continue

                ts_match = rgx_ts.match(line)
                if ts_match:
                    try:
                        current_ts = datetime.fromisoformat(ts_match.group(1))
                    except ValueError:
                        continue
                else:
                    continue 

                ip_match = rgx_ip.search(line)
                src_ip = ip_match.group(1) if ip_match else "Unknown"

                if src_ip in ["::1", "127.0.0.1", "localhost"]:
                    src_ip = "LOCALHOST"

                if "Failed password" in line:
                    user_match = rgx_user_fail.search(line)
                    username = user_match.group(1) if user_match else "Unknown"

                    session_key = (src_ip, username)
                    
                    fail_tracker[session_key].append(current_ts)

                    while fail_tracker[session_key]:
                        if (current_ts - fail_tracker[session_key][0]).total_seconds() > BRUTE_FORCE_WINDOW:
                            fail_tracker[session_key].popleft()
                        else:
                            break
                    
                    if not fail_tracker[session_key]:
                        del fail_tracker[session_key]
                        if session_key in alerted_sessions:
                            alerted_sessions.discard(session_key)
                        continue

                    recent_fails = len(fail_tracker[session_key])

                    if recent_fails >= BRUTE_FORCE_THRESHOLD:
                        if session_key not in alerted_sessions:
                            severity = "CRITICAL"
                            msg = f"Brute Force Detected ({recent_fails} attempts)"
                            event_type = "SSH_BRUTE_FORCE"
                            alerted_sessions.add(session_key)
                        else:
                            severity = "HIGH" 
                            msg = f"Brute Force Continuing ({recent_fails} attempts)"
                            event_type = "SSH_BRUTE_FORCE_ONGOING"
                    else:
                        severity = "HIGH"
                        msg = "Invalid SSH attempt"
                        event_type = "SSH_AUTH_FAIL"

                    details_str = (
                        f"Event Type: {event_type}\n"
                        f"User: {username}\n"
                        f"Source IP: {src_ip}\n"
                        f"Attempt Count: {recent_fails}\n"
                        f"Window: {BRUTE_FORCE_WINDOW}s\n"
                    )

                    events.append({
                        "type": event_type,
                        "source": src_ip,
                        "user": username,
                        "severity": severity,
                        "msg": f"{msg} user={username} src={src_ip}",
                        "details": details_str,
                        "timestamp": current_ts.isoformat(),
                        "host": current_host,
                        "raw_log": line
                    })

                elif "Accepted password" in line or "Accepted publickey" in line:
                    user_match = rgx_user_succ.search(line)
                    username = user_match.group(1) if user_match else "Unknown"
                    
                    session_key = (src_ip, username)

                    severity = "INFO"
                    msg = "Valid SSH login"
                    event_type = "SSH_AUTH_SUCCESS"
                    
                    if session_key in fail_tracker and len(fail_tracker[session_key]) >= BRUTE_FORCE_THRESHOLD:
                        severity = "CRITICAL"
                        msg = "SUCCESSFUL LOGIN AFTER BRUTE FORCE ATTACK!"
                        event_type = "SSH_COMPROMISE"
                        
                        fail_tracker[session_key].clear()
                        del fail_tracker[session_key]
                        if session_key in alerted_sessions:
                            alerted_sessions.discard(session_key)

                    details_str = (
                        f"Event Type: {event_type}\n"
                        f"User: {username}\n"
                        f"Source IP: {src_ip}\n"
                        f"Analysis: Access granted.\n"
                    )

                    events.append({
                        "type": event_type,
                        "source": src_ip,
                        "user": username,
                        "severity": severity,
                        "msg": f"{msg} for {username}",
                        "details": details_str,
                        "timestamp": current_ts.isoformat(),
                        "host": current_host,
                        "raw_log": line
                    })

    except Exception as e:
        print(f"[ERROR] SSH Log Processing Failed: {e}")
        return 0, []

    failed_count = sum(1 for e in events if "FAIL" in e["type"] or "BRUTE" in e["type"])
    
    return failed_count, events
