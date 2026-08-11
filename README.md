# SOC Python Mini-Projects

## Overview: The Primary Goal
This repository documents my progression towards mastering Python fundamentals, applied through the lens of a SOC Analyst.

While the scripts here simulate real-world SOC tasks like parsing security logs and sanitising data the main purpose of this repository's existence is to build and solidify my core programming muscle memory. Rather than building feature-complete applications, I am focusing on small, single-purpose utilities that execute exactly one function efficiently.

## Mock Data
To focus on mastering Python's logic, control flow, and data structures, these projects will generally parse hardcoded mock data to demonstrate core logic without requiring external database dependencies or file I/O.

## AI Transparency
One of my goals with this repository is writing code manually from a blank file but I may utilise AI tools as a tutor to help me grasp concepts, debug logic, and generate the mock data.

## Repository Structure
The utilities are categorised by their primary operational function:

* **`/network-containment`**: Scripts for validating, sorting, and sanitising network indicators (like IP addresses) for firewall blocklists.
* **`/threat-detection`**: Scripts for scanning logs for possible IoC or ongoing attack.
* **`/log-triage`**: Scripts for parsing events based on severity and operational hierarchy.
