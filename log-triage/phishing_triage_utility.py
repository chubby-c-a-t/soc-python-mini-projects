"""
Phishing Triage Utility
Description: A SOC utility that simulates an automated inbox scanner. 
It ingests raw email subject lines and sorts them, so high-severity alerts 
can be prioritised and duplicate logs are prevented.
"""

# MOCK DATA: Raw email subjects from the inbound filter
subject_lines = [
    "Lunch in the breakroom",
    "URGENT: Reset your password",
    "WIRE TRANSFER requested URGENTLY",
    "Weekly metrics report",
    "Action Required: Invoice attached"
]

urgent_keywords = ["URGENT", "Action Required"]
financial_keywords = ["WIRE TRANSFER", "Invoice"]

def triage_phishing_emails(subjects, urgent_words, financial_words):
    financial_alerts = []
    urgent_alerts = []
    safe_emails = []

    for subject in subjects:
        is_urgent = False
        is_financial = False

        # Priority 1: Financial Fraud
        for financial_word in financial_words:
            if financial_word in subject:
                financial_alerts.append(subject)
                is_financial = True
                break

        # Priority 2: Urgent Action (Hierarchy Guard applied)
        for urgent_word in urgent_words:
            if not is_financial and urgent_word in subject:
                urgent_alerts.append(subject)
                is_urgent = True
                break

        # Default: Safe bucket
        if is_financial == False and is_urgent == False:
            safe_emails.append(subject)

    return safe_emails, urgent_alerts, financial_alerts


if __name__ == "__main__":
    safe, urgent, financial = triage_phishing_emails(subject_lines, urgent_keywords, financial_keywords)
    
    print("--- AUTOMATED TRIAGE RESULTS ---")
    print(f"Financial Fraud Alerts (High Priority): {financial}")
    print(f"Urgent Action Alerts (Medium Priority): {urgent}")
    print(f"Cleared Emails (Safe): {safe}")