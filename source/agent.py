# agent.py

import shlex
import utils
import risk_engine
import db 
from common_libs import *
from config import Config

from analyzers.ssh import analyze_ssh_logs
from analyzers.sudo import analyze_sudo_logs
from analyzers.firewall import analyze_firewall_logs
from analyzers.audit import analyze_audit_logs
from analyzers.fim import analyze_file_integrity

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

    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.AGENT_MAX_WORKERS) as executor:
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