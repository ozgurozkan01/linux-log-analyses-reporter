import requests
import psutil
import socket
import json
import ipaddress

def get_live_port_data():
    grouped_ports = {} 

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            port = conn.laddr.port
            ip = conn.laddr.ip
            
            service = get_service_name(port)
            if port == 3306: service = "MYSQL DATABASE"
            if port == 5432: service = "POSTGRESQL"
            if port == 53: service = "DOMAIN (DNS)"
            if port == 80 or port == 443: service = "WEB SERVER"
            if port == 22: service = "SSHD"

            if port not in grouped_ports:
                grouped_ports[port] = {
                    'port': port,
                    'service': service,
                    'status': 'ACTIVE',
                    'ips': [] 
                }
            
            if ip not in grouped_ports[port]['ips']:
                grouped_ports[port]['ips'].append(ip)
    
    result_list = list(grouped_ports.values())
    
    for item in result_list:
        item['ips'].sort(key=get_ip_risk_score, reverse=True)

    result_list.sort(key=lambda x: x['port'])
    
    return result_list

def get_service_name(port, protocol='tcp'):
    try:
        return socket.getservbyport(port, protocol).upper()
    except:
        return "UNKNOWN"

def get_ip_risk_score(ip):
    if ip in ['0.0.0.0', '::']: return 3
    if not ip.startswith('127.') and not ip.startswith('192.168.') and not ip.startswith('10.'): return 3
    if ip.startswith('192.168.') or ip.startswith('10.'): return 2
    return 1

def get_public_ip():
    public_ip = None
    
    try:
        response_ip = requests.get('https://api.ipify.org', timeout=5)
        response_ip.raise_for_status()
        public_ip = response_ip.text
    except requests.exceptions.RequestException:
        return None

    try:
        response_geo = requests.get(f'http://ip-api.com/json/{public_ip}', timeout=5)
        response_geo.raise_for_status()
        geo_data = response_geo.json()

        if geo_data.get('status') == 'success':
            return {
                'ip': public_ip,
                'country_name': geo_data.get('country'),
                'country_code': geo_data.get('countryCode')
            }
        else:
            return {
                'ip': public_ip,
                'country_name': 'N/A',
                'country_code': None
            }
            
    except requests.exceptions.RequestException:
        return {
            'ip': public_ip,
            'country_name': 'N/A',
            'country_code': None
        }

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'

def get_primary_dns():
    dns_servers = []
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    ip = line.split()[1]
                    dns_servers.append(ip)
    except Exception:
        pass
    
    if dns_servers:
        return ", ".join(dns_servers[:2]) 
    return "Local (Stub)"

IP_GEO_CACHE = {}

def get_ip_location(ip):
    if not ip: return None

    try:
        if ipaddress.ip_address(ip).is_private:
            return {'code': 'LAN', 'name': 'Local Network'}
    except ValueError:
        return {'code': 'UNK', 'name': 'Unknown'}

    if ip in IP_GEO_CACHE:
        return IP_GEO_CACHE[ip]

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode,country", timeout=1)
        if response.status_code == 200:
            data = response.json()
            result = {
                'code': data.get('countryCode', 'UNK'), 
                'name': data.get('country', 'Unknown')
            }
            IP_GEO_CACHE[ip] = result 
            return result
    except:
        pass

    return {'code': 'UNK', 'name': 'Unknown'}
