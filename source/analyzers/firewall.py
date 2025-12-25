import re
import socket
import subprocess
import psutil
from datetime import datetime, timedelta
from collections import defaultdict, deque
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from config import Config
from services import core_utils
import db

def analyze_firewall_logs():
    since_time = core_utils.get_since_timestamp()
    
    cmd = Config.CMD_FIREWALL_TEMPLATE.format(since_time)
    
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
    except subprocess.CalledProcessError as e:
        print(f"HATA: Firewall logları alınamadı. Çıktı: {e.output.decode('utf-8', errors='ignore')}")
        return []
    except Exception as e:
        print(f"Beklenmedik hata: {e}")
        return []
    
    for line in raw_output.splitlines():
        if not line.strip(): continue
        
        if not any(k in line for k in ('BLOCK','DROP','REJECT','DENY','UFW','IN=', 'ALLOW', 'AUDIT')): continue

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

        is_allowed = "ALLOW" in line or "AUDIT" in line or "ACCEPT" in line

        if is_allowed:
            action = "ALLOW"
        elif any(x in line for x in ["BLOCK", "DROP", "REJECT", "DENY"]):
            action = "BLOCK"
        else:
            action = "BLOCK"

        dst_port_val = 0
        if data['dpt'] and data['dpt'].isdigit():
            dst_port_val = int(data['dpt'])

        try:
            db.insert_firewall_log(
                action=action,
                protocol=protocol,
                src_ip=src_ip,
                dst_port=dst_port_val,
                direction='INBOUND'
            )
        except Exception as e:
            pass

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
        
        elif dst_port in critical_ports and action == "BLOCK":
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

        db.insert_event(
            event_type=event_type,
            source=src_ip,
            username="kernel",
            severity=severity,
            message=full_msg
        )

    return []