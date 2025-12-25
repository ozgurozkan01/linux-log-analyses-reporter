import subprocess
import re

def get_ufw_details():
    details = {
        'status': 'UNKNOWN',
        'status_color': 'secondary',
        'version': 'N/A',
        'manager': 'UFW',
        'engine': 'Netfilter',
        'inbound': 'UNKNOWN',
        'outbound': 'UNKNOWN',
        'logging': 'OFF',
        'policy_count': 0
    }

    try:
        ufw_ver_output = subprocess.check_output(["ufw", "--version"], stderr=subprocess.DEVNULL).decode('utf-8')
        if ufw_ver_output:
            details['version'] = ufw_ver_output.splitlines()[0].split(' ')[1]
    except (IndexError, FileNotFoundError, subprocess.CalledProcessError):
        details['version'] = 'Unknown'

    try:
        ipt_output = subprocess.check_output(["iptables", "--version"], stderr=subprocess.DEVNULL).decode('utf-8')
        
        if "nf_tables" in ipt_output:
            details['engine'] = "Netfilter (NFT)"
        elif "legacy" in ipt_output:
            details['engine'] = "Netfilter (Legacy)"
        else:
            details['engine'] = "Netfilter (Std)"
    except Exception:
        details['engine'] = "Netfilter (?)"

    try:
        raw_output = subprocess.check_output("ufw status verbose", shell=True, stderr=subprocess.DEVNULL).decode('utf-8')
        
        status_match = re.search(r'Status:\s+(\w+)', raw_output)
        if status_match:
            status_str = status_match.group(1).upper()
            details['status'] = status_str
            
            if status_str == 'ACTIVE':
                details['status_color'] = 'success'
            elif status_str == 'INACTIVE':
                details['status_color'] = 'danger'
                return details
        else:
            details['status'] = 'STOPPED'
            details['status_color'] = 'danger'
            return details

        log_match = re.search(r'Logging:\s+(.+)', raw_output)
        if log_match:
            details['logging'] = log_match.group(1).upper()

        def_match = re.search(r'Default:\s+(.+)', raw_output)
        if def_match:
            defaults = def_match.group(1)
            
            if 'deny (incoming)' in defaults: details['inbound'] = 'DENY'
            elif 'reject (incoming)' in defaults: details['inbound'] = 'REJECT'
            elif 'allow (incoming)' in defaults: details['inbound'] = 'ALLOW'
            
            if 'allow (outgoing)' in defaults: details['outbound'] = 'ALLOW'
            elif 'deny (outgoing)' in defaults: details['outbound'] = 'DENY'
            elif 'reject (outgoing)' in defaults: details['outbound'] = 'REJECT'

        lines = raw_output.splitlines()
        count = 0
        rules_started = False
        
        for line in lines:
            line = line.strip()
            if line.startswith("To") and "Action" in line and "From" in line:
                rules_started = True
                continue
            
            if rules_started and line.startswith("-"):
                continue
                
            if rules_started and line:
                count += 1
                
        details['policy_count'] = count

    except subprocess.CalledProcessError:
        details['status'] = 'NO PERM'
        details['status_color'] = 'warning'
    except Exception as e:
        print(f"[ERROR] UFW Fetch Error: {e}")

    return details

def get_ufw_rules_list():
    rules = []
    try:
        raw_output = subprocess.check_output("ufw status numbered", shell=True, stderr=subprocess.DEVNULL).decode('utf-8')
        
        pattern = re.compile(r'\[\s*(\d+)\]\s+(.*?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)\s+(.*)')
        
        for line in raw_output.splitlines():
            match = pattern.search(line)
            if match:
                rule = {
                    'id': match.group(1),
                    'to': match.group(2).strip(),
                    'action': match.group(3),
                    'direction': match.group(4),
                    'from': match.group(5).strip()
                }
                
                if rule['action'] == 'ALLOW':
                    rule['color'] = 'success'
                elif rule['action'] == 'DENY':
                    rule['color'] = 'danger'
                else:
                    rule['color'] = 'warning'
                    
                rules.append(rule)
    except Exception as e:
        print(f"Rules fetch error: {e}")
        
    return rules
