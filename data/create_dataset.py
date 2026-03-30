import pandas as pd
import numpy as np
import json
from datetime import datetime
import random

def create_phishing_emails(n=100):
    """Create synthetic phishing emails"""
    phishing_templates = [
        {
            "subject": "URGENT: Your account will be suspended",
            "content": """Dear valued customer,

We detected suspicious activity on your account. Please verify your account immediately to avoid suspension.

Click here to verify: http://fake-bank-verify.com/secure/login

Failure to verify within 24 hours will result in permanent account closure.

Best regards,
Security Team""",
            "sender": "security@fake-bank.com",
            "urgency_words": ["URGENT", "immediately", "suspension", "24 hours"],
            "suspicious": ["urgent", "fake domain", "suspicious link", "threat of closure"]
        },
        {
            "subject": "Your payment has been declined",
            "content": """Hello,

Your recent payment of $499.99 was declined due to security concerns.

Please update your payment information:
http://secure-payment-verify.net/update

If not updated within 48 hours, your service will be interrupted.

Thank you,
Billing Department""",
            "sender": "billing@secure-update.com",
            "urgency_words": ["declined", "48 hours", "interrupted"],
            "suspicious": ["payment declined", "suspicious link", "pressure tactic"]
        }
    ]
    
    emails = []
    for i in range(n):
        template = random.choice(phishing_templates)
        emails.append({
            "id": f"phishing_{i}",
            "label": "phishing",
            "sender": template["sender"],
            "subject": template["subject"],
            "content": template["content"],
            "urgency_words": template["urgency_words"],
            "suspicious_elements": template["suspicious"]
        })
    return emails

def create_legitimate_emails(n=100):
    """Create synthetic legitimate emails"""
    legit_templates = [
        {
            "subject": "Your monthly statement",
            "content": """Hello,

Your account statement for March is now available.

Please log in to your account to view the statement.

Thank you for banking with us.

Best regards,
Customer Service""",
            "sender": "statements@realbank.com",
            "urgency_words": [],
            "suspicious": []
        },
        {
            "subject": "Team meeting tomorrow",
            "content": """Hi team,

Just a reminder about our team meeting tomorrow at 10 AM in Conference Room A.

Please come prepared with your weekly updates.

Thanks,
Manager""",
            "sender": "manager@company.com",
            "urgency_words": [],
            "suspicious": []
        }
    ]
    
    emails = []
    for i in range(n):
        template = random.choice(legit_templates)
        emails.append({
            "id": f"legit_{i}",
            "label": "legitimate",
            "sender": template["sender"],
            "subject": template["subject"],
            "content": template["content"],
            "urgency_words": template["urgency_words"],
            "suspicious_elements": template["suspicious"]
        })
    return emails

# Create datasets
phishing_emails = create_phishing_emails(200)
legit_emails = create_legitimate_emails(200)
all_emails = phishing_emails + legit_emails

# Save to CSV
df = pd.DataFrame(all_emails)
df.to_csv('data/phishing_dataset.csv', index=False)

print(f"Created dataset with {len(all_emails)} emails")
print(f"  - Phishing: {len(phishing_emails)}")
print(f"  - Legitimate: {len(legit_emails)}")