# Phishing Triage Utility

## Overview
This Python utility simulates an automated SOC inbox scanner. It ingests raw email subject lines, scans them for known malicious keywords. If an email triggers multiple distinct alerts (e.g. both "Urgent" and "Financial"), the script enforces a hierarchy rule to route it only to the highest-priority bucket, preventing alert fatigue and duplicate logging.

## Technical Highlights
* **State-Tracking Booleans:** Utilises `True/False` flags to monitor the status of an individual log entry across multiple separate evaluation loops during a single pass.
* **Short-Circuit Evaluation:** Uses the `break` command to immediately halt nested loops once a keyword match is found, conserving CPU cycles on large datasets.
