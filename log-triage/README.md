# Phishing Triage Utility

## Overview
This Python utility simulates an automated SOC inbox scanner. It ingests raw email subject lines, scans them for known malicious keywords. If an email triggers multiple distinct alerts (e.g. both "Urgent" and "Financial"), the script enforces a hierarchy rule to route it only to the highest-priority bucket, preventing alert fatigue and duplicate logging.

## Technical Highlights
* **State-Tracking Booleans:** Utilises `True/False` flags to monitor the status of an individual log entry across multiple separate evaluation loops during a single pass.
* **Short-Circuit Evaluation:** Uses the `break` command to immediately halt nested loops once a keyword match is found, conserving CPU cycles on large datasets.

# Sources & Severity Triage Utility

## Overview
This Python utility simulates a primary log ingestion filter for a SOC environment. It evaluates raw security events against a list of known malicious indicators (blocked IP addresses) and dynamic severity thresholds. The script acts as a routing engine, automatically isolating malformed or corrupted logs while sorting valid events into clean or suspicious queues for further analyst review.

## Technical Highlights
* **Inner Guard Clauses:** Validates the structural length and mathematical boundaries of individual inner data elements `(0-10)` before attempting evaluation, preventing `IndexError` crashes from corrupted or incomplete logs.
* **Compound Conditional Routing:** Utilises `elif` chains combined with the `in` and `or` operators to evaluate multiple threat vectors simultaneously. This efficiently routes events to distinct queues in a single, flat pass without requiring nested loops.
