def calculate_risk(failed_logins, open_ports, cpu, ram, disk):
    score = 0
    alerts = []

    if failed_logins > 10:
        score += 60
        alerts.append((
            "CRITICAL",
            "Brute Force Attack",
            f"{failed_logins} failed login attempts detected in the last 30 minutes!"
        ))

    elif failed_logins > 2:
        score += 20
        alerts.append((
            "WARNING",
            "Suspicious Login Activity",
            f"{failed_logins} failed login attempts detected."
        ))

    if open_ports > 15:
        score += 15
        alerts.append((
            "INFO",
            "High Network Activity",
            f"Open port count is higher than normal: {open_ports}"
        ))

    if cpu > 90:
        score += 25
        alerts.append((
            "HIGH",
            "Critical CPU Usage",
            f"CPU usage is at {cpu}%!"
        ))

    elif cpu > 75:
        score += 10

    if ram > 90:
        score += 15
        alerts.append((
            "WARNING",
            "High RAM Usage",
            f"Memory usage is almost full: {ram}%"
        ))

    if disk > 95:
        score += 15
        alerts.append((
            "CRITICAL",
            "Disk Almost Full",
            "Disk space is critically low! System may become unstable."
        ))

    elif disk > 85:
        score += 5
        alerts.append((
            "INFO",
            "Disk Usage Warning",
            f"Disk usage has reached {disk}%."
        ))


    final_score = min(score, 100)
    
    return final_score, alerts