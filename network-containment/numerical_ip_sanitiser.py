"""
Numerical IP Sanitiser
Description: A SOC utility that deduplicates a raw list of IP addresses 
and sorts them numerically (by network byte order).
"""

import ipaddress


def proper_ip_sort(raw_ips):
    unique_ips = set(raw_ips)
    
    # Sort the list numerically by telling Python to evaluate the strings as IP addresses
    numerically_sorted_ips = sorted(unique_ips, key=ipaddress.ip_address)
    
    return numerically_sorted_ips


if __name__ == "__main__":
    messy_ips = [
        "192.168.1.100", 
        "10.0.0.5", 
        "192.168.1.2",
        "128.162.129.32",
        "178.69.39.229",
        "253.91.146.100",
        "118.59.166.154",
        "63.177.17.88",
        "200.98.240.16",
        "68.169.36.202",
        "70.175.178.181",
        "13.205.199.13",
        "81.99.52.223",
        "10.0.0.5", 
        "200.1.1.0",
        "10.0.0.20"
    ]

    clean_list = proper_ip_sort(messy_ips)

    print("--- NUMERICALLY SORTED IP LIST ---")
    for ip in clean_list:
        print(ip)