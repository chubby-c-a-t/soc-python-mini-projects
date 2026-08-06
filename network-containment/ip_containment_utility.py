"""
IP Containment Utility
Description: A Level 1 SOC utility designed to ingest raw, noisy IP lists 
from SIEM alerts. It automatically filters out known-safe internal subnets 
and removes duplicates, outputting a sanitised blocklist.
"""

# MOCK DATA: A raw list of IPs scraped from a SIEM alert.
# It contains duplicates and safe internal IPs that need to be filtered out.
raw_siem_ips = [
    "192.168.1.15", # Internal (Safe)
    "45.33.32.156", # Malicious
    "10.0.0.5",     # Internal (Safe)
    "45.33.32.156", # Duplicate Malicious
    "8.8.8.8",      # Safe DNS
    "185.15.59.224" # Malicious
]

def ip_parser(raw_siem_ips):

    known_safe_ips = ["192.168.1.15", "10.0.0.5", "8.8.8.8"]
    clean_blocklist = []

    for raw_siem_ip in raw_siem_ips:
        if raw_siem_ip not in known_safe_ips and raw_siem_ip not in clean_blocklist:
            clean_blocklist.append(raw_siem_ip)
    
    return clean_blocklist

if __name__ == "__main__":
    print("Sanitised Blocklist Generated:")
    print(ip_parser(raw_siem_ips))