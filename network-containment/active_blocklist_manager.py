"""
Active Blocklist Manager
Description: A SOC utility that dynamically processes a sequence 
of automated firewall commands (block, unblock, rollback). It safely updates 
an active IP blocklist while preventing duplicate entries and utilising 
short-circuit evaluation to avoid indexing errors.
"""

def manage_blocklist(initial_blocklist, actions):
    # Excellent use of .copy() to preserve the original data
    managed_blocklist = initial_blocklist.copy()
    
    # We only need to loop through the instructions!
    for action in actions:
        if action[0] == "block" and action[1] not in managed_blocklist:
            managed_blocklist.append(action[1])
            
        elif action[0] == "unblock" and action[1] in managed_blocklist:
            managed_blocklist.remove(action[1])
            
        elif action[0] == "rollback" and len(managed_blocklist) > 0:
            managed_blocklist.pop()

    return managed_blocklist


if __name__ == "__main__":
    # MOCK DATA
    starting_ips = ["192.168.1.50", "10.0.0.5"]
    soc_commands = [
        ["block", "172.16.0.4"],
        ["unblock", "192.168.1.50"],
        ["rollback"]
    ]
    
    new_list = manage_blocklist(starting_ips, soc_commands)
    
    print("--- FIREWALL BLOCKLIST UPDATE ---")
    print(f"Original List: {starting_ips}")
    print(f"Updated List:  {new_list}")