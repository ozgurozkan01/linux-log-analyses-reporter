import re
import socket
import subprocess
from datetime import datetime
from collections import defaultdict
import shlex
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from config import Config
from services import core_utils

def analyze_sudo_logs():
    events = []
    
    MAX_EVENTS = Config.SUDO_MAX_EVENTS
    SENSITIVE_FILES = Config.SUDO_SENSITIVE_FILES
    NORMAL_COOLDOWN = Config.SUDO_NORMAL_COOLDOWN
    CRITICAL_COOLDOWN = Config.SUDO_CRITICAL_COOLDOWN
    MITRE_MAPPING = Config.SUDO_MITRE_MAPPING

    gtfobins_risky = Config.SUDO_GTFOBINS_RISKY
    priv_escalation_bins = Config.SUDO_PRIV_ESCALATION
    shell_bins = Config.SUDO_SHELL_BINS
    net_bins = Config.SUDO_NET_BINS
    read_bins = Config.SUDO_READ_BINS
    service_accounts = Config.SUDO_SERVICE_ACCOUNTS
    
    editor_bins = getattr(Config, 'SUDO_EDITORS', Config.SUDO_EDITOR_BINS)
    destructive_bins = getattr(Config, 'SUDO_DESTRUCTIVE_BINS', Config.SUDO_DESTRUCTIVE_BINS)

    since_time = core_utils.get_since_timestamp()
    cmd = Config.CMD_SUDO_BASE + ["--since", since_time]
    
    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] START --- analyze_sudo_logs ---")

    last_sudo_map = defaultdict(lambda: datetime.min)
    
    rgx_ts = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^ ]*)')
    rgx_meta = re.compile(r'sudo\[(\d+)\]:\s+([a-zA-Z0-9_\-\.]+(?:@[a-zA-Z0-9_\-\.]+)?)\s+:')
    
    current_host = socket.gethostname()

    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1) as proc:
            
            for line in proc.stdout:
                if "COMMAND=" not in line: continue
                if len(events) >= MAX_EVENTS: break

                if len(last_sudo_map) > 5000: last_sudo_map.clear()
                line = line.strip()

                ts_match = rgx_ts.match(line)
                if ts_match:
                    try:
                        current_ts = datetime.fromisoformat(ts_match.group(1)).replace(tzinfo=None)
                    except ValueError:
                        continue 
                else:
                    continue

                meta_match = rgx_meta.search(line)
                try:
                    cmd_part = line.split("COMMAND=", 1)[1].strip()
                except IndexError:
                    continue

                pid = meta_match.group(1) if meta_match else "N/A"
                user = meta_match.group(2).strip() if meta_match else "unknown"
                full_command = cmd_part
                
                try:
                    parts = shlex.split(full_command)
                except ValueError:
                    parts = full_command.split()
                
                if not parts: continue
                
                binary = parts[0]
                if "/" in binary: binary = binary.split("/")[-1]
                
                args = " ".join(parts[1:]) 

                severity = "INFO"
                event_type = "GENERAL_SUDO"
                suspicion_note = ""

                if "TTY=unknown" in line:
                    severity = "CRITICAL"
                    event_type = "NON_INTERACTIVE_SUDO"
                    suspicion_note = "Script or exploit execution detected (No TTY)"

                elif "NOPASSWD" in line:
                    severity = "CRITICAL"
                    event_type = "SUDO_NOPASSWD"
                    suspicion_note = "Command executed without password prompt"
                
                elif binary == 'sudoedit' and any(s in args for s in SENSITIVE_FILES):
                    severity = "CRITICAL"
                    event_type = "SUDOEDIT_SENSITIVE_EDIT"
                    suspicion_note = "Sensitive configuration editing via sudoedit"

                elif binary == 'sudo' and ('-E' in parts or '--preserve-env' in parts):
                    severity = "HIGH"
                    event_type = "SUDO_ENV_PRESERVE"
                    suspicion_note = "Environment variables preserved manually (potential bypass)"

                elif user in service_accounts and (binary in shell_bins or binary in net_bins or binary in destructive_bins):
                    severity = "CRITICAL"
                    event_type = "SERVICE_ACCOUNT_ABUSE"

                elif (binary in shell_bins or binary == 'su') and any(x in args for x in ['-', '-i', '-l']):
                    severity = "CRITICAL"
                    event_type = "SUDO_INTERACTIVE_ROOT"

                elif binary in shell_bins and '-c' in parts:
                    severity = "HIGH"
                    event_type = "SCRIPT_EXECUTION"
                    suspicion_note = "Direct shell command execution via flag -c"

                elif binary == 'env' and any(x in args for x in ['bash', 'sh', 'LD_PRELOAD', 'PATH=']):
                    severity = "CRITICAL"
                    event_type = "ENV_ESCAPE"

                elif binary in destructive_bins and any(x in args for x in ['/var/log', '.bash_history', 'audit.log']):
                    severity = "CRITICAL"
                    event_type = "AUTHORIZED_LOG_WIPING"

                elif binary in ['crontab', 'systemctl', 'update-rc.d', 'chkconfig'] and any(x in args for x in ['-e', 'enable', 'install']):
                    severity = "CRITICAL"
                    event_type = "PERSISTENCE_MODIFICATION"

                elif binary in ['chmod', 'chown'] and ('+s' in args or '4755' in args):
                    severity = "CRITICAL"
                    event_type = "SUID_ABUSE"

                elif binary in priv_escalation_bins:
                    severity = "CRITICAL" 
                    event_type = "PRIV_ESCALATION_AUTH"

                elif binary in net_bins:
                    if any(x in args for x in ['-e', '/bin/sh', '/bin/bash', 'exec']):
                        severity = "CRITICAL"
                        event_type = "SUDO_REVERSE_SHELL"
                    else:
                        severity = "HIGH"
                        event_type = "SUDO_NET_PIVOT"

                elif binary in editor_bins:
                    is_sensitive = any(s in args for s in SENSITIVE_FILES)
                    if is_sensitive:
                        severity = "CRITICAL"
                        event_type = "SENSITIVE_EDIT"
                    elif any(x in args for x in ['!sh', '!/bin', ':shell']):
                        severity = "CRITICAL"
                        event_type = "EDITOR_ESCAPE"
                    else:
                        severity = "HIGH"
                        event_type = "UNSAFE_EDITOR"

                elif binary in gtfobins_risky:
                    if any(x in args for x in ['-exec', 'system', 'spawn', '!/bin/sh', '--interactive']):
                        severity = "CRITICAL"
                        event_type = "SHELL_ESCAPE_ATTEMPT"
                    else:
                        severity = "WARNING"
                        event_type = "GTFOBINS_BINARY"

                elif binary in shell_bins:
                    if event_type == "GENERAL_SUDO": 
                        severity = "CRITICAL"
                        event_type = "DIRECT_SHELL_ACCESS"

                elif binary in read_bins and any(s in args for s in SENSITIVE_FILES):
                    severity = "CRITICAL"
                    event_type = "SUDO_SENSITIVE_READ"
                
                elif "/root" in args:
                    if severity in ["INFO", "WARNING"]:
                        severity = "WARNING"
                        event_type = "ROOT_DIR_ACCESS"

                wait_time = CRITICAL_COOLDOWN if severity == "CRITICAL" else NORMAL_COOLDOWN
                cooldown_key = (user, event_type, binary)
                
                if (current_ts - last_sudo_map[cooldown_key]).total_seconds() < wait_time:
                    continue
                last_sudo_map[cooldown_key] = current_ts

                mitre_id = MITRE_MAPPING.get(event_type, "T1078") 

                details_str = (
                    f"Event Type: {event_type}\n"
                    f"MITRE ATT&CK: {mitre_id}\n"
                    f"User: {user}\n"
                    f"PID: {pid}\n" 
                    f"Command: {full_command}\n"
                    f"Binary: {binary}\n"
                    f"Suspicion: {suspicion_note if suspicion_note else 'Policy Violation'}\n"
                    f"Context: TTY={('unknown' if 'TTY=unknown' in line else 'interactive')}\n"
                )

                events.append({
                    "type": event_type,
                    "source": "Local",
                    "user": user,
                    "severity": severity,
                    "msg": f"[{event_type}] {full_command}",
                    "details": details_str,
                    "timestamp": current_ts.isoformat(),
                    "host": current_host,
                    "raw_log": line,
                    "mitre": mitre_id
                })

    except Exception as e:
        print(f"[ERROR] Sudo Log Processing Failed: {e}")
        return []

    return events
