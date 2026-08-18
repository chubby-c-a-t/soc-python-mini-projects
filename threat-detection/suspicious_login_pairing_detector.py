"""
Suspicious Login Pairing Detector
Description: A SOC utility that extracts unique User-to-IP login pairings from a chronological log. 
It uses a set for state-tracking to deduplicate connection pairs and cross-references 
each new connection against a threat feed set to flag known malicious infrastructure.
"""

def analyse_login_pairings(events, threat_feed):
    if not events:
        return []

    seen_pairings = set()
    analysed_events = []

    for event in events:
        username = event[0]
        ip_address = event[1]
        timestamp = event[2]

        # Unique string pairing to track user-IP relationship
        pairing = f"{username}:{ip_address}"

        if pairing not in seen_pairings:
            seen_pairings.add(pairing)
            
            status = "CLEAN"
            if ip_address in threat_feed:
                status = "WARNING (Known Malicious IP)"
            
            analysed_events.append([timestamp, username, ip_address, status])

    return analysed_events


if __name__ == "__main__":
    mock_logs = [
        ["mira", "192.168.1.15", "08:15"],
        ["kai", "10.0.0.99", "08:20"],
        ["mira", "192.168.1.15", "09:05"], # Duplicate pairing, to skipped
        ["mira", "198.51.100.4", "09:30"], # Same user but new malicious IP, to be logged
        ["admin", "198.51.100.4", "10:00"] # Different user, same malicious IP, to be logged
    ]

    known_bad_ips = {"198.51.100.4", "203.0.113.50"}

    results = analyse_login_pairings(mock_logs, known_bad_ips)
    
    print("--- UNIQUE LOGIN PAIRING REPORT ---")
    
    if not results:
        print("No new login events found.")
    else:
        for res in results:
            print(f"[{res[0]}] USER: {res[1]} | IP: {res[2]} | STATUS: {res[3]}")