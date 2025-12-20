import re
import socket
import subprocess
from datetime import datetime
from collections import defaultdict, deque
import shutil
import os
import sys
import binascii

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from config import Config
import utils


def analyze_audit_logs():
    events = []
    
    if shutil.which("ausearch") is None:
        print("[ERROR] 'ausearch' komutu bulunamadı. Auditd yüklü mü?")
        return events

    cmd = Config.CMD_AUDIT_FULL

    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] START --- analyze_audit_logs ---\n") # <-- ADD THIS LINE

    rgx_exe = re.compile(r'exe="([^"]+)"')
    rgx_cmd = re.compile(r'proctitle="?([^"]+)"?') 
    rgx_auid = re.compile(r'auid=(\S+)')
    rgx_uid = re.compile(r'uid=(\S+)')
    rgx_path = re.compile(r'name="([^"]+)"')

    suspicious_bins_regex = re.compile(r'\b(' + '|'.join(Config.AUDIT_SUSPICIOUS_BINS) + r')\b')
    webshell_regex = re.compile(Config.AUDIT_WEBSHELL_PATTERN)
    recon_regex = re.compile(r'\b(' + '|'.join(map(re.escape, Config.AUDIT_RECON_COMMANDS)) + r')\b')
    perm_mod_regex = re.compile(r'\b(' + '|'.join(Config.AUDIT_PERM_MOD_CMDS) + r')\b')
    critical_files = Config.AUDIT_CRITICAL_FILES

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
                    if "+s" in full_cmd or "u+s" in full_cmd:
                        risk_score = max(risk_score, 3) 
                        alert_type = "SUID_BIT_SET"     
                    else:
                        risk_score = max(risk_score, 2) 
                        alert_type = "FS_PERM_CHANGE"   
                    
                    details.append("Permission/Ownership Modification")

                if "rm " in full_cmd and "/var/log" in full_cmd:
                    risk_score = max(risk_score, 4)
                    alert_type = "LOG_WIPING_ATTEMPT"
                    details.append("Evidence Destruction Attempt")
                
                if uid == "root" and auid != "root" and auid != "unset" and auid != "4294967295":
                    risk_score = max(risk_score, 4)
                    alert_type = "PRIV_ESCALATION_EXEC"
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
                            "type": "KERNEL_FILE_ACCESS",
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
