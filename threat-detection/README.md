# Brute Force Detector

## Overview
This Python utility simulates a rudimentary threat detection engine. It ingests a chronological list of mock authentication events and scans for consecutive failures. If the streak breaches a predefined threshold, the script generates an automated alert pinpointing the location of the anomaly in the log sequence.

## Technical Highlights
* **State Tracking:** Utilises variables outside the main loop to monitor ongoing streaks, resetting the counter when a successful login interrupts the sequence.
* **Early Exit Execution:** Employs a `return` statement when the threshold is breached, halting the loop to save processing power on large log files.
* **Formatted Alerting:** Uses Python f-strings to translate raw integer indices into readable incident alerts for analysts.

# Matched IoC Scanner

## Overview
During log correlation, analysts often receive parallel data streams (like file hashes and filenames) from different sensors. These logs are rarely perfectly matched, leading to orphaned or malformed data points that can crash automated parsing scripts.

This utility safely correlates parallel arrays, isolating unmatched leftovers before scanning the perfectly paired data against a list of known malware signatures (IoCs).

## Technical Highlights
* **Safe Boundaries:** Utilises `min()` to dynamically calculate the safe iteration limit for lists of unequal lengths, completely preventing `IndexError` crashes.
* **List Slicing:** Extracts and preserves orphaned data using slice notation (`[:]`) so no logs are dropped during triage.
