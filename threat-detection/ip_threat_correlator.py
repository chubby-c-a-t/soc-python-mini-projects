"""
IP Threat Correlator
Description: A SOC utility that cross-references active network connections 
against a known threat intelligence feed to instantly identify active breaches.
"""

def find_active_threats(active_ips, threat_ips):
    threat_set = set(threat_ips)
    unique_active = set(active_ips)
    
    # List comprehension in place of previous intersection operator
    active_threats = [ip for ip in unique_active if ip in threat_set]
    
    return active_threats

if __name__ == "__main__":
    current_connections = ["192.168.1.50", "10.0.0.5", "198.51.100.4", "10.0.0.5"]
    ioc_feed = ["203.0.113.50", "198.51.100.4", "10.0.0.99"]

    active_threats = find_active_threats(current_connections, ioc_feed)

    print("--- ACTIVE THREAT REPORT ---")
    if not active_threats:
        print("No active threats detected.")
    else:
        for ip in active_threats:
            print(f"CRITICAL: Active connection from known threat IP: {ip}")