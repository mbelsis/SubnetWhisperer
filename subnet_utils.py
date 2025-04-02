import ipaddress
import pandas as pd
import io
import re
import logging

# Configure logging
logger = logging.getLogger(__name__)

def parse_subnet(subnet_str):
    """Parse a subnet string (CIDR notation) and return a list of IP addresses"""
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        logger.error(f"Invalid subnet format: {subnet_str} - {str(e)}")
        return []

def parse_ip_range(range_str):
    """Parse IP range in format 192.168.1.1-192.168.1.10"""
    try:
        if '-' not in range_str:
            return [range_str]  # Single IP address
        
        start_ip, end_ip = range_str.split('-')
        
        # If end_ip is just the last octet
        if '.' not in end_ip:
            base_ip = start_ip.split('.')
            end_ip = '.'.join(base_ip[:-1]) + '.' + end_ip
        
        start = ipaddress.IPv4Address(start_ip.strip())
        end = ipaddress.IPv4Address(end_ip.strip())
        
        return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]
    except Exception as e:
        logger.error(f"Invalid IP range format: {range_str} - {str(e)}")
        return []

def parse_subnet_input(input_text):
    """Parse various subnet input formats and return a list of IP addresses"""
    ip_addresses = []
    
    # Split input by lines or commas
    lines = re.split(r'[\n,]', input_text)
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Check if the line contains a CIDR subnet
        if '/' in line:
            ip_addresses.extend(parse_subnet(line))
        # Check if the line contains an IP range
        elif '-' in line:
            ip_addresses.extend(parse_ip_range(line))
        # Check if it's a single IP address
        elif re.match(r'^(\d{1,3}\.){3}\d{1,3}$', line):
            ip_addresses.append(line)
    
    # Remove duplicates and sort
    ip_addresses = sorted(list(set(ip_addresses)), 
                         key=lambda ip: [int(octet) for octet in ip.split('.')])
    
    return ip_addresses

def parse_csv_file(csv_content):
    """Parse CSV file containing IP addresses or subnets"""
    try:
        df = pd.read_csv(io.StringIO(csv_content))
        
        # Try to find a column with IP addresses or subnets
        ip_column = None
        for col in df.columns:
            if col.lower() in ['ip', 'ipaddress', 'ip_address', 'subnet', 'address', 'network']:
                ip_column = col
                break
        
        if not ip_column and len(df.columns) > 0:
            # If no obvious column name, use the first column
            ip_column = df.columns[0]
        
        if ip_column:
            return parse_subnet_input('\n'.join(df[ip_column].astype(str).tolist()))
        else:
            return []
    except Exception as e:
        logger.error(f"Error parsing CSV file: {str(e)}")
        return []
