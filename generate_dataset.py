import pandas as pd
import numpy as np
import random
import os

def generate_seetd(num_records=10000):
    np.random.seed(42)
    random.seed(42)

    # Class counts
    safe_count = int(num_records * 0.50)
    spam_count = int(num_records * 0.30)
    phish_count = int(num_records * 0.15)
    malware_count = int(num_records * 0.05)

    data = []

    def generate_safe():
        subjects = ["Meeting notes", "Lunch today?", "Project update", "Weekly report", "Invoice attached"]
        bodies = [
            "Hi team, please find the meeting notes attached.",
            "Are we still on for lunch at 12?",
            "The project is on track for Q3 delivery.",
            "Here is the weekly report. Let me know if you have questions.",
            "Please review the attached invoice for last month's services."
        ]
        domains = ["company.com", "gmail.com", "partner.org", "university.edu"]
        
        has_att = np.random.choice([0, 1], p=[0.7, 0.3])
        att_ext = np.random.choice(['.pdf', '.docx', '.xlsx', '']) if has_att else ''
        att_size = np.random.uniform(50, 5000) if has_att else 0
        
        url_count = np.random.randint(0, 3)
        susp_url_count = 0
        
        return {
            'subject': random.choice(subjects),
            'body': random.choice(bodies),
            'sender_domain': random.choice(domains),
            'has_attachment': has_att,
            'attachment_ext': att_ext,
            'attachment_size_kb': att_size,
            'url_count': url_count,
            'suspicious_url_count': susp_url_count,
            'label': 0
        }

    def generate_spam():
        subjects = ["BUY NOW! 50% OFF", "Enlarge your business", "Cheap medications", "You have won a gift card!"]
        bodies = [
            "Click here to buy our amazing new product! 50% off for a limited time.",
            "Want to grow your business? We offer cheap SEO services. Contact us today.",
            "Get cheap pills without a prescription. Fast shipping.",
            "Congratulations! You have been selected to win a $500 gift card. Claim it now."
        ]
        domains = ["discount.xyz", "marketing.net", "promos.biz", "freesales.info"]
        
        has_att = np.random.choice([0, 1], p=[0.9, 0.1])
        att_ext = np.random.choice(['.jpg', '.pdf', '']) if has_att else ''
        att_size = np.random.uniform(10, 200) if has_att else 0
        
        url_count = np.random.randint(1, 5)
        susp_url_count = np.random.randint(0, url_count + 1)
        
        return {
            'subject': random.choice(subjects),
            'body': random.choice(bodies),
            'sender_domain': random.choice(domains),
            'has_attachment': has_att,
            'attachment_ext': att_ext,
            'attachment_size_kb': att_size,
            'url_count': url_count,
            'suspicious_url_count': susp_url_count,
            'label': 1
        }

    def generate_phishing():
        subjects = ["URGENT: Account Suspension", "Verify Your Identity", "Security Alert: New Login", "Action Required: Update Payment"]
        bodies = [
            "Dear User, your account will be suspended in 24 hours. Click the link to verify.",
            "We noticed suspicious activity on your account. Please log in immediately to secure it.",
            "Your password has expired. Update it here or lose access.",
            "Your recent payment failed. Please update your billing details."
        ]
        domains = ["paypal-security.com", "apple-support-alert.net", "bank-verify.info", "login-update.org"]
        
        has_att = np.random.choice([0, 1], p=[0.8, 0.2])
        att_ext = np.random.choice(['.html', '.pdf', '']) if has_att else ''
        att_size = np.random.uniform(5, 50) if has_att else 0
        
        url_count = np.random.randint(1, 4)
        susp_url_count = url_count # All URLs in phishing are usually suspicious
        
        return {
            'subject': random.choice(subjects),
            'body': random.choice(bodies),
            'sender_domain': random.choice(domains),
            'has_attachment': has_att,
            'attachment_ext': att_ext,
            'attachment_size_kb': att_size,
            'url_count': url_count,
            'suspicious_url_count': susp_url_count,
            'label': 2
        }

    def generate_malware():
        subjects = ["Invoice #49281", "Remittance Advice", "Scanned Document", "Important Court Notice"]
        bodies = [
            "Please find the attached invoice for your recent purchase. Open to view details.",
            "Attached is the remittance advice for the payment processed today.",
            "You have received a scanned document from the HR printer.",
            "You have been subpoenaed. Read the attached document for court details."
        ]
        domains = ["unknown-sender.com", "freemail.org", "compromised-site.com"]
        
        has_att = 1
        att_ext = np.random.choice(['.exe', '.vbs', '.scr', '.zip', '.js'])
        att_size = np.random.uniform(10, 1500)
        
        url_count = np.random.randint(0, 2)
        susp_url_count = np.random.randint(0, url_count + 1) if url_count > 0 else 0
        
        return {
            'subject': random.choice(subjects),
            'body': random.choice(bodies),
            'sender_domain': random.choice(domains),
            'has_attachment': has_att,
            'attachment_ext': att_ext,
            'attachment_size_kb': att_size,
            'url_count': url_count,
            'suspicious_url_count': susp_url_count,
            'label': 3
        }

    for _ in range(safe_count): data.append(generate_safe())
    for _ in range(spam_count): data.append(generate_spam())
    for _ in range(phish_count): data.append(generate_phishing())
    for _ in range(malware_count): data.append(generate_malware())

    # Shuffle dataset
    random.shuffle(data)
    
    df = pd.DataFrame(data)
    
    # Save to CSV
    output_path = 'email_dataset.csv'
    df.to_csv(output_path, index=False)
    print(f"Generated {len(df)} records. Saved to {output_path}")
    print("Class distribution:")
    print(df['label'].value_counts(normalize=True) * 100)

if __name__ == "__main__":
    generate_seetd()
