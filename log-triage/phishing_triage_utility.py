"""
Phishing Triage Utility
Description: A SOC utility that simulates an automated inbox scanner.
It ingests raw email subject lines and sorts them by priority while
preventing duplicate subjects from being processed more than once.
"""

# MOCK DATA: Raw email subjects from the inbound filter
subject_lines = [
    "Lunch in the breakroom",
    "URGENT: Reset your password",
    "WIRE TRANSFER requested URGENTLY",
    "Weekly metrics report",
    "Action Required: Invoice attached",
    "URGENT: Reset your password"  # Duplicate for testing
]

urgent_keywords = ["URGENT", "Action Required"]
financial_keywords = ["WIRE TRANSFER", "Invoice"]


def triage_phishing_emails(subjects, urgent_words, financial_words):
    financial_alerts = []
    urgent_alerts = []
    unflagged_emails = []

    processed_subjects = set()

    for subject in subjects:
        # Uses a set to prevent duplicate subjects from being processed
        if subject in processed_subjects:
            continue

        processed_subjects.add(subject)

        # Convert the subject and keywords to lowercase
        # so matching is not affected by capitalisation
        subject_lower = subject.lower()

        is_financial = False
        is_urgent = False

        # Priority 1: Financial Fraud
        for financial_word in financial_words:
            if financial_word.lower() in subject_lower:
                financial_alerts.append(subject)
                is_financial = True
                break

        # Priority 2: Urgent Action
        if not is_financial:
            for urgent_word in urgent_words:
                if urgent_word.lower() in subject_lower:
                    urgent_alerts.append(subject)
                    is_urgent = True
                    break

        # No matching indicators found
        if not is_financial and not is_urgent:
            unflagged_emails.append(subject)

    return unflagged_emails, urgent_alerts, financial_alerts


if __name__ == "__main__":
    unflagged, urgent, financial = triage_phishing_emails(
        subject_lines,
        urgent_keywords,
        financial_keywords
    )

    print("--- AUTOMATED TRIAGE RESULTS ---")
    print(f"Financial Fraud Alerts (High Priority): {financial}")
    print(f"Urgent Action Alerts (Medium Priority): {urgent}")
    print(f"Unflagged Emails: {unflagged}")
