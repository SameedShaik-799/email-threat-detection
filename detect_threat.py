import pandas as pd
import numpy as np
import pickle
import json
import os

class EmailThreatDetector:
    def __init__(self, model_path='xgboost_threat_model.pkl', extractor_path='feature_extractor.pkl'):
        if not os.path.exists(model_path) or not os.path.exists(extractor_path):
            raise FileNotFoundError("Model or extractor not found. Please train the model first.")
            
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
            
        with open(extractor_path, 'rb') as f:
            self.extractor = pickle.load(f)
            
        self.class_names = {0: 'Safe', 1: 'Spam', 2: 'Phishing', 3: 'Malware'}
        
    def predict(self, email_data: dict):
        """
        email_data should be a dictionary containing:
        - subject
        - body
        - sender_domain
        - has_attachment (0 or 1)
        - attachment_ext (e.g. '.exe', '.pdf', '')
        - attachment_size_kb (float)
        - url_count (int)
        - suspicious_url_count (int)
        """
        df = pd.DataFrame([email_data])
        
        # Transform using feature engineering
        X = self.extractor.transform(df)
        
        # Predict probability
        probs = self.model.predict_proba(X)[0]
        pred_class = int(np.argmax(probs))
        
        # Exact output generation
        output = {
            "email_subject": email_data.get('subject', ''),
            "predicted_threat_level": self.class_names[pred_class],
            "confidence_scores": {
                "Safe": round(float(probs[0]), 4),
                "Spam": round(float(probs[1]), 4),
                "Phishing": round(float(probs[2]), 4),
                "Malware": round(float(probs[3]), 4)
            },
            "key_indicators_found": {
                "has_malicious_extension": bool(df['is_malicious_ext'].iloc[0]),
                "urgent_language_detected": bool(df['has_urgent_kw'].iloc[0]),
                "financial_keywords_detected": bool(df['has_financial_kw'].iloc[0]),
                "suspicious_url_count": int(email_data.get('suspicious_url_count', 0)),
                "attachment_risk": bool(email_data.get('has_attachment', 0) and df['is_malicious_ext'].iloc[0])
            }
        }
        
        return output

if __name__ == "__main__":
    detector = EmailThreatDetector()
    
    # Test with a mock Phishing email
    test_phishing_email = {
        'subject': 'URGENT: Verify Your Bank Account Immediately',
        'body': 'Dear user, your bank account will be suspended. Please verify by clicking the link.',
        'sender_domain': 'secure-bank-verify.com',
        'has_attachment': 0,
        'attachment_ext': '',
        'attachment_size_kb': 0,
        'url_count': 1,
        'suspicious_url_count': 1
    }
    
    # Test with a mock Malware email
    test_malware_email = {
        'subject': 'Invoice #99482 Payment Receipt',
        'body': 'Please find attached the receipt for your recent transaction.',
        'sender_domain': 'unknown-sender.biz',
        'has_attachment': 1,
        'attachment_ext': '.exe',
        'attachment_size_kb': 1024,
        'url_count': 0,
        'suspicious_url_count': 0
    }
    
    print("--- Testing Phishing Email Detection ---")
    result_phishing = detector.predict(test_phishing_email)
    print(json.dumps(result_phishing, indent=4))
    
    print("\n--- Testing Malware Email Detection ---")
    result_malware = detector.predict(test_malware_email)
    print(json.dumps(result_malware, indent=4))
