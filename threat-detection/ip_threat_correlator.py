"""
IP Threat Correlator
Description: A SOC utility that cross-references active network connections 
against a known threat intelligence feed to instantly identify active breaches.
"""

def find_active_threats(active_ips, threat_ips):
    set_active_ips = set(active_ips)
    set_threat_ips = set(threat_ips)
    
    common_ips = set_active_ips & set_threat_ips

    return common_ips


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