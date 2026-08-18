# IP Containment Utility

## Overview
During an active incident, SOC analysts often need to extract IP addresses from raw logs or SIEM alerts to build firewall blocklists. However, raw data frequently contains duplicate entries and safe internal IP addresses (like DNS servers or local gateways). Accidentally blocking an internal gateway can cause a self-inflicted network outage.

This simple Python utility is designed to solve that problem. It ingests a raw list of IPs, checks them against a hardcoded "safe list" of internal network assets, and removes any duplicates. 

## Technical Highlights
* **Data Sanitisation:** Utilises Python's `in / not in` operators to ensure only malicious, unique IPs are processed.
* **Algorithmic Efficiency:** Uses combined guard clauses to flatten logic and iterate efficiently.

---

# Active Blocklist Manager

## Overview
SOC analysts frequently receive streams of automated firewall commands whether from a SOAR platform, a ticketing system, or a senior analyst dictating which IPs need to be blocked or cleared. 

This utility simulates processing a chronological queue of these actions. It ingests an initial state, reads a list of operational commands, and dynamically updates the active blocklist. It supports blocking new threats, unblocking, and rolling back the most recent change.

## Technical Highlights
* **List Mutation:** Utilises core Python list methods (`.copy()`, `.remove()`, `.pop()`) to dynamically alter data structures while preserving the integrity of the original dataset.
* **Short-Circuit Evaluation:** Strategically orders conditional statements to naturally prevent `IndexError` crashes when handling single-item commands like `"rollback"`.

# Suspicious Login Pairing Detector

## Overview
This Python utility safely extracts unique user-to-IP relationships from chronological logs, cross-referencing each new pairing against a threat feed to flag malicious infrastructure.

## Technical Highlights
* **State Tracking:** Utilises a Python `set` to monitor seen login pairings, inherently guaranteeing uniqueness to deduplicate data without complex loops.
* **High-Speed Lookups:** Employs a `set` for the active threat feed, allowing for highly efficient membership testing (`in` keyword) during log triage.
* **Relational Mapping:** Uses Python f-strings to concatenate the username and IP address into a single tracking variable for contextual analysis.
