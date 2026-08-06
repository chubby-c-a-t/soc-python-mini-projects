# Brute Force Detection Utility

## Overview
This Python utility simulates a rudimentary threat detection engine. It ingests a chronological list of mock authentication events and scans for consecutive failures. If the streak breaches a predefined threshold, the script generates an automated alert pinpointing the location of the anomaly in the log sequence.

## Technical Highlights
* **State Tracking:** Utilises variables outside the main loop to monitor ongoing streaks, resetting the counter when a successful login interrupts the sequence.
* **Early Exit Execution:** Employs a `return` statement when the threshold is breached, halting the loop to save processing power on large log files.
* **Formatted Alerting:** Uses Python f-strings to translate raw integer indices into readable incident alerts for analysts.
