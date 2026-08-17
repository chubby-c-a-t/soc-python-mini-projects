"""
Sources & Severity Triage Utility
Description: A SOC utility that parses a stream of raw security events. 
It validates the structural integrity of the log, evaluates the data against 
a known blocklist, and routes the event into prioritised queues based on 
severity thresholds.
"""

def classify_soc_events(events, blocked_sources, severity_threshold):
    
    invalid_events = []
    sus_events = []
    clean_events = []
    
    for event in events:
        # Validate structure (requires 3 fields) and severity boundaries (0-10)
        if len(event) != 3 or event[2] < 0 or event[2] > 10:
            invalid_events.append(event)
            
        # Route to suspicious if source is blocked OR severity meets threshold
        elif event[1] in blocked_sources or event[2] >= severity_threshold:
            sus_events.append(event)
            
        # Route to clean if valid and non-threatening
        else:
            clean_events.append(event)

    return clean_events, sus_events, invalid_events

if __name__ == "__main__":
    # MOCK DATA
    # Format: ["Event_ID", "Source_IP", Severity_Score]
    raw_events = [
        ["EVT-01", "192.168.1.15", 2],      # Clean
        ["EVT-02", "10.0.0.99", 8],         # Suspicious (High Severity)
        ["EVT-03", "198.51.100.4", 4],      # Suspicious (Blocked IP)
        ["EVT-04", "10.1.1.5"],             # Invalid (Missing severity score)
        ["EVT-05", "172.16.0.5", 15],       # Invalid (Severity out of bounds)
    ]
    
    known_bad_ips = ["198.51.100.4", "203.0.113.10"]
    alert_threshold = 7

    clean, suspicious, invalid = classify_soc_events(raw_events, known_bad_ips, alert_threshold)

    print("--- LOG TRIAGE RESULTS ---")
    print(f"Clean Events:      {clean}")
    print(f"Suspicious Events: {suspicious}")
    print(f"Invalid Logs:      {invalid}")