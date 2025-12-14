# risk_engine.py

SEVERITY_SCORES = {
    "CRITICAL": 15,
    "HIGH": 8,
    "WARNING": 5,
    "INFO": 0
}

RISK_SCORES = {
    "DIRECT_SHELL_ACCESS"       : 60,
    "WEBSHELL_ACT"              : 50,
    "LOG_WIPING"                : 40,
    "PRIV_ESCALATION"           : 35,
    "SSH_BRUTE_FORCE"           : 30,
    "PRIVILEGE_MODIFICATION"    : 30,
    "FIM_MISSING"               : 25,
    "HACKING_TOOL"              : 25,
    "SHELL_ESCAPE_ATTEMPT"      : 25,
    "UNSAFE_EDITOR"             : 25,
    "SENSITIVE_EDIT"            : 20,
    "NETWORK_TOOL"              : 20,
    "FIM_CONTENT_CHANGE"        : 15,
    "SSH_COMPROMISE"            : 15,
    "DESTRUCTIVE_OP"            : 15,
    "RECONNAISSANCE"            : 10,
    "SENSITIVE_READ"            : 10,
    "PERM_MODIFICATION"         : 10,
    "ROOT_DIR_ACCESS"           : 10,
    "FIM_PERM_CHANGE"           : 5,
    "SSH_AUTH_FAIL"             : 2
}

SYSTEM_ANOMALY_SCORES = {
    "AUTH_CRITICAL": {
        "score": 40, 
        "level": "CRITICAL", 
        "title": "High Failed Login Rate"
    },
    "AUTH_WARNING": {
        "score": 10, 
        "level": "WARNING",  
        "title": "Suspicious Login Activity"
    },
    "CPU_CRITICAL": {
        "score": 25, 
        "level": "CRITICAL", 
        "title": "Critical CPU Usage"
    },
    "RAM_WARNING": {
        "score": 15, 
        "level": "WARNING",  
        "title": "High RAM Usage"
    },
    "DISK_CRITICAL": {
        "score": 15, 
        "level": "CRITICAL", 
        "title": "Disk Space Critical"
    },
    "NET_WARNING": {
        "score": 15, 
        "level": "WARNING",  
        "title": "Abnormal Network Ports"
    }
}

def calculate_risk(failed_logins, open_ports, cpu, ram, disk, security_events):

    score = 0
    anomalies = []
    
    if failed_logins > 10:
        rule = SYSTEM_ANOMALY_SCORES["AUTH_CRITICAL"]
        score += rule['score']
        anomalies.append({
            "level": rule['level'].upper(),
            "title": rule['title'],
            "msg": f"URGENT: {failed_logins} failed login attempts detected.",
            "time": "System Metric",
            "count": failed_logins,
            "score_impact": rule['score'] 
        })

    if cpu > 90:
        rule = SYSTEM_ANOMALY_SCORES["CPU_CRITICAL"]
        score += rule['score']
        anomalies.append({
            "level": rule['level'].upper(),
            "title": rule['title'],
            "msg": f"CPU spiking at {cpu}%!",
            "time": "System Metric",
            "count": 1,
            "score_impact": rule['score']
        })
    
    if ram > 90:
        rule = SYSTEM_ANOMALY_SCORES["RAM_WARNING"]
        score += rule['score']
        anomalies.append({
            "level": rule['level'].upper(),
            "title": rule['title'],
            "msg": f"Memory usage: {ram}%",
            "time": "System Metric",
            "count": 1,
            "score_impact": rule['score']
        })

    if disk > 95:
        rule = SYSTEM_ANOMALY_SCORES["DISK_CRITICAL"]
        score += rule['score']
        anomalies.append({
            "level": rule['level'].upper(),
            "title": rule['title'],
            "msg": "Disk >95% full.",
            "time": "System Metric",
            "count": 1,
            "score_impact": rule['score']
        })

    if open_ports > 15:
        rule = SYSTEM_ANOMALY_SCORES["NET_WARNING"]
        score += rule['score']
        anomalies.append({
            "level": rule['level'].upper(),
            "title": rule['title'],
            "msg": f"Open ports count: {open_ports}",
            "time": "Network Metric",
            "count": open_ports,
            "score_impact": rule['score']
        })

    grouped_events = {}

    for event in security_events:
        etype = event.get('type').upper()
        severity = event.get('severity', 'INFO').upper()
        
        detected_reason = ""
        current_score = 0

        if etype in RISK_SCORES:
            current_score = RISK_SCORES[etype]
            detected_reason = etype
        
        else:
            current_score = SEVERITY_SCORES.get(severity, 0)
            detected_reason = f"Generic {severity}"

        if current_score == 0:
            continue

        if detected_reason in grouped_events:
            grouped_events[detected_reason]['count'] += 1
            if SEVERITY_SCORES.get(severity, 0) > SEVERITY_SCORES.get(grouped_events[detected_reason]['severity'], 0):
                grouped_events[detected_reason]['severity'] = severity
        else:
            grouped_events[detected_reason] = {
                'base_score': current_score,
                'count': 1,
                'severity': severity
            }

    
    for reason, data in grouped_events.items():
        count = data['count']
        base_score = data['base_score']
        severity = data['severity']
        
        repeat_penalty = min((count - 1) * (base_score * 0.1), base_score) 
        total_event_risk = base_score + repeat_penalty
        
        score += total_event_risk

        if severity == "INFO":
            continue
        if count <= 5:
            continue
        anomalies.append({
            "level": severity.upper(),
            "title": f"High Volume: {reason.replace('_', ' ').title()}",
            "msg": f"Storm detected: {count} occurrences of {reason}!",
            "time": "Security Aggregation",
            "score_impact": int(total_event_risk)
        })

    final_score = min(int(score), 100)
    
    return final_score, anomalies