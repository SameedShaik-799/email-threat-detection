import urllib.request, json

tests = [
    ('Safe',     {'subject':'Meeting Notes Q4','body':'Hi team, please find meeting notes attached.','sender_domain':'company.com','has_attachment':1,'attachment_ext':'.pdf','attachment_size_kb':420,'url_count':0,'suspicious_url_count':0}),
    ('Spam',     {'subject':'BUY NOW 70% OFF','body':'Click here to buy our amazing product at 70% discount!','sender_domain':'deals.promo-xyz.biz','has_attachment':0,'attachment_ext':'','attachment_size_kb':0,'url_count':3,'suspicious_url_count':2}),
    ('Phishing', {'subject':'URGENT: Account Suspended','body':'Dear user, your account will be suspended. Verify immediately.','sender_domain':'secure-bank-verify.info','has_attachment':0,'attachment_ext':'','attachment_size_kb':0,'url_count':2,'suspicious_url_count':2}),
    ('Malware',  {'subject':'Invoice #99482 Attached','body':'Please open the attached file for payment details.','sender_domain':'unknown-billing.com','has_attachment':1,'attachment_ext':'.exe','attachment_size_kb':1024,'url_count':0,'suspicious_url_count':0}),
]

print("\n=== ThreatScan AI — End-to-End API Test ===\n")
all_pass = True
for expected, payload in tests:
    req = urllib.request.Request(
        'http://127.0.0.1:5000/api/detect',
        data=json.dumps(payload).encode(),
        headers={'Content-Type': 'application/json'}
    )
    res = json.loads(urllib.request.urlopen(req).read())
    predicted = res['predicted_threat_level']
    conf = res['confidence_scores'][predicted]
    status = 'PASS' if predicted == expected else 'FAIL'
    if status == 'FAIL':
        all_pass = False
    icon = '[PASS]' if status == 'PASS' else '[FAIL]'
    print(f"{icon} | Expected: {expected:<10} | Got: {predicted:<10} | Confidence: {conf:.2f}%")

print()
print("=== Result:", "ALL TESTS PASSED" if all_pass else "SOME TESTS FAILED", "===")
