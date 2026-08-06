"""
Brute Force Detection Utility
Description: A Level 1 SOC utility that scans a chronological list of 
authentication events for a specific account. It tracks consecutive 
failed login attempts and triggers an alert if the brute-force threshold is met.
"""

# MOCK DATA: Chronological authentication logs for the "admin" account.
login_events = [
    "success",
    "failed",
    "success",
    "failed",
    "failed",
    "failed",
    "failed",
    "failed",
    "success",
    "failed"
]

def detect_brute_force(events, threshold=5):
    consecutive_failures = 0
    
    for i in range(len(events)):
        
        if events[i] == "failed":
            consecutive_failures += 1
            
            if consecutive_failures >= threshold:
                return f"Brute force attack detected. Threshold breached at log index {i}."
            
        elif events[i] == "success":
            consecutive_failures = 0
        
    return "Status Normal: No brute force detected."

if __name__ == "__main__":
    print("Initiating brute force scan...")
    print(detect_brute_force(login_events))