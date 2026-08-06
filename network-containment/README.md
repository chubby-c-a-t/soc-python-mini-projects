# IP Containment Utility

## Overview
During an active incident, SOC analysts often need to extract IP addresses from raw logs or SIEM alerts to build firewall blocklists. However, raw data frequently contains duplicate entries and safe internal IP addresses (like DNS servers or local gateways). Accidentally blocking an internal gateway can cause a self-inflicted network outage.

This simple Python utility is designed to solve that problem. It ingests a raw list of IPs, checks them against a hardcoded "safe list" of internal network assets, and removes any duplicates. 

## Technical Highlights
* **Data Sanitisation:** Utilises Python's `in / not in` operators to ensure only malicious, unique IPs are processed.
* **Algorithmic Efficiency:** Uses combined guard clauses to flatten logic and iterate efficiently.
