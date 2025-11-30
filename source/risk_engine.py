def calculate_risk(failed_logins, open_ports, cpu, ram, disk, security_events):

    score = 0
    anomalies = []

    if failed_logins > 10:
        score += 60
        anomalies.append({
            "level": "critical",
            "title": "Brute Force Attack",
            "msg": f"URGENT: {failed_logins} failed login attempts detected in short time!",
            "time": "Auth Log"
        })
    elif failed_logins > 2:
        score += 20
        anomalies.append({
            "level": "warning",
            "title": "Suspicious Login",
            "msg": f"{failed_logins} failed login attempts detected.",
            "time": "Auth Log"
        })

    if cpu > 90:
        score += 25
        anomalies.append({
            "level": "critical",
            "title": "Critical CPU Usage",
            "msg": f"CPU usage is spiking at {cpu}%! Check for crypto-miners.",
            "time": "System"
        })
    elif cpu > 75:
        score += 10
    
    if ram > 90:
        score += 15
        anomalies.append({
            "level": "warning",
            "title": "High RAM Usage",
            "msg": f"Memory usage is critical: {ram}%",
            "time": "System"
        })

    if disk > 95:
        score += 15
        anomalies.append({
            "level": "critical",
            "title": "Disk Space Critical",
            "msg": "Disk is almost full (>95%). System crash imminent.",
            "time": "System"
        })
    elif disk > 85:
        score += 5
        anomalies.append({
            "level": "info",
            "title": "Disk Usage Warning",
            "msg": f"Disk usage reached {disk}%.",
            "time": "System"
        })

    if open_ports > 15:
        score += 15
        anomalies.append({
            "level": "warning",
            "title": "Abnormal Network Activity",
            "msg": f"Open port count is higher than normal: {open_ports}",
            "time": "Network"
        })

    for event in security_events:
        
        if event['type'] == "FIM_MISSING":
            score += 50
            anomalies.append({
                "level": "critical",
                "title": "Critical File Missing",
                "msg": event['msg'],
                "time": "FIM System"
            })
            
        elif event['type'] == "FIM_CONTENT_CHANGE":
            score += 40
            anomalies.append({
                "level": "critical",
                "title": "File Content Changed",
                "msg": event['msg'],
                "time": "FIM System"
            })
            
        elif event['type'] == "FIM_PERM_CHANGE":
            score += 15
            anomalies.append({
                "level": "warning",
                "title": "File Perms Changed",
                "msg": event['msg'],
                "time": "FIM System"
            })
            
        elif event['type'] == "FIM_ACCESS_DENIED":
            score += 10
            anomalies.append({
                "level": "warning",
                "title": "FIM Access Denied",
                "msg": event['msg'],
                "time": "FIM System"
            })

        elif event['severity'] == "CRITICAL":
            score += 30
            anomalies.append({
                "level": "critical",
                "title": "Security Alert",
                "msg": f"{event['type']}: {event['msg']}",
                "time": event['source']
            })

    final_score = min(score, 100)
    
    return final_score, anomalies