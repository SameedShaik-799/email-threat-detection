from flask import Flask, request, jsonify, render_template
import pickle
import pandas as pd
import numpy as np
import os
import re
import email as email_lib
import email.policy
import io

app = Flask(__name__)

MODEL_PATH     = 'xgboost_threat_model.pkl'
EXTRACTOR_PATH = 'feature_extractor.pkl'

model     = None
extractor = None

def load_artifacts():
    global model, extractor
    if os.path.exists(MODEL_PATH) and os.path.exists(EXTRACTOR_PATH):
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        with open(EXTRACTOR_PATH, 'rb') as f:
            extractor = pickle.load(f)
        print("[INFO] Model and extractor loaded successfully.")
    else:
        print("[ERROR] Model artifacts not found. Run train_model.py first.")

load_artifacts()

CLASS_NAMES  = {0: 'Safe', 1: 'Spam', 2: 'Phishing', 3: 'Malware'}
CLASS_COLORS = {0: '#22c55e', 1: '#f59e0b', 2: '#ef4444', 3: '#8b5cf6'}

TRUSTED_DOMAINS = {
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'microsoft.com', 'google.com', 'apple.com', 'amazon.com',
    'gov.in', 'ac.in', 'edu', 'org',
}

SUSPICIOUS_URL_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|rb\.gy',
    r'(verify|secure|login|account|update|confirm|suspend|banking).*\.(xyz|biz|info|cc|tk|ml|ga|cf|gq|net)',
    r'https?://[^\s]*@[^\s]*',
    r'\.ru/|\.cn/|\.pw/|\.ws/|\.top/',
    r'wizrocketmail|clevertap|mailchimp|sendgrid|stripocdn|track\.|click\.',
]

SPAM_KEYWORDS = [
    'win', 'free', 'discount', '% off', 'offer', 'deal', 'cashback', 'coupon',
    'crore', 'lakh', 'prize', 'jackpot', 'bonus', 'limited time', 'buy now',
    'exclusive offer', 'gift card', 'congratulations', 'hurry'
]

MALICIOUS_EXTS = ['.exe', '.vbs', '.scr', '.js', '.bat', '.cmd', '.zip', '.ps1']

def extract_urls(text):
    """Extract all URLs and detect suspicious/tracking patterns."""
    url_pattern = r'https?://[^\s<>"\'\\]+'
    urls = re.findall(url_pattern, str(text), re.IGNORECASE)
    # Deduplicate while preserving order
    seen = set()
    unique_urls = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    url_count = len(unique_urls)
    suspicious_count = 0
    for url in unique_urls:
        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious_count += 1
                break
    return url_count, suspicious_count

def check_spam_signals(subject, body, headers_str=''):
    """Check text and headers for promotional or marketing spam triggers."""
    full_text = (subject + ' ' + body + ' ' + headers_str).lower()
    spam_score = 0
    for kw in SPAM_KEYWORDS:
        if kw in full_text:
            spam_score += 1

    is_bulk = False
    if 'list-unsubscribe' in full_text or 'feedback-id' in full_text or 'precedence: bulk' in full_text:
        is_bulk = True
        spam_score += 3

    return is_bulk, spam_score

def is_suspicious_sender(domain):
    domain = str(domain).lower().strip()
    if not domain:
        return False
    for trusted in TRUSTED_DOMAINS:
        if domain.endswith(trusted):
            return False
    bad_patterns = ['verify','secure','alert','login','update','confirm',
                    'suspend','banking','support','paypal','apple','amazon','microsoft']
    for b in bad_patterns:
        if b in domain:
            return True
    for tld in ['.xyz','.biz','.info','.cc','.tk','.ml','.ga','.cf','.gq','.pw','.ws','.top','.click','.buzz']:
        if domain.endswith(tld):
            return True
    return False

def parse_eml(file_bytes):
    """Parse a .eml file and extract all email features accurately."""
    try:
        msg = email_lib.message_from_bytes(file_bytes, policy=email.policy.default)
    except Exception:
        msg = email_lib.message_from_bytes(file_bytes)

    subject      = str(msg.get('Subject', '') or '')
    from_header  = str(msg.get('From', '') or '')
    sender_domain = ''

    match = re.search(r'@([\w.\-]+)', from_header)
    if match:
        sender_domain = match.group(1).lower()

    # Collect raw text parts and attachments
    raw_content_parts = []
    has_attachment = 0
    attachment_ext = ''
    attachment_size_kb = 0.0

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = str(part.get('Content-Disposition') or '')

            if 'attachment' in disp:
                has_attachment = 1
                fname = part.get_filename() or ''
                _, ext = os.path.splitext(fname)
                if ext:
                    attachment_ext = ext.lower()
                payload = part.get_payload(decode=True)
                if payload:
                    attachment_size_kb = round(len(payload) / 1024, 2)
            elif ctype in ['text/plain', 'text/html']:
                try:
                    raw_content_parts.append(part.get_payload(decode=True).decode('utf-8', errors='ignore'))
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                raw_content_parts.append(payload.decode('utf-8', errors='ignore'))
        except Exception:
            raw_content_parts.append(str(msg.get_payload() or ''))

    all_raw = ' '.join(raw_content_parts)
    # Strip HTML tags for clean body text
    clean_body = re.sub(r'<[^>]+>', ' ', all_raw)
    clean_body = re.sub(r'\s+', ' ', clean_body).strip()

    # Headers for bulk/marketing detection
    headers_str = '\n'.join(f'{k}: {v}' for k, v in msg.items())

    return {
        'subject':           subject,
        'body':              clean_body,
        'raw_text_for_urls': all_raw,
        'headers_str':       headers_str,
        'sender_domain':     sender_domain,
        'from_header':       from_header,
        'has_attachment':    has_attachment,
        'attachment_ext':    attachment_ext,
        'attachment_size_kb': attachment_size_kb,
    }

def parse_pdf(file_bytes):
    """Extract text from a PDF email export."""
    try:
        import pdfplumber
        text_parts = []
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            for page in pdf.pages:
                t = page.extract_text()
                if t:
                    text_parts.append(t)
        full_text = '\n'.join(text_parts)

        subj_match = re.search(r'Subject[:\s]+(.+)', full_text, re.IGNORECASE)
        subject = subj_match.group(1).strip() if subj_match else ''

        from_match = re.search(r'From[:\s]+.+?@([\w.\-]+)', full_text, re.IGNORECASE)
        sender_domain = from_match.group(1).lower() if from_match else ''

        return {
            'subject':           subject,
            'body':              full_text,
            'raw_text_for_urls': full_text,
            'headers_str':       '',
            'sender_domain':     sender_domain,
            'from_header':       '',
            'has_attachment':    0,
            'attachment_ext':    '',
            'attachment_size_kb': 0.0,
        }
    except ImportError:
        return None

def run_detection(subject, body, sender_domain, has_attachment, attachment_ext, attachment_size_kb, raw_text_for_urls=None, headers_str=''):
    """Core detection logic shared by both the form and file upload."""
    text_to_scan = raw_text_for_urls if raw_text_for_urls else (subject + ' ' + body)
    url_count, suspicious_url_count = extract_urls(text_to_scan)

    sender_is_suspicious = is_suspicious_sender(sender_domain)
    if sender_is_suspicious:
        suspicious_url_count = max(suspicious_url_count, min(url_count, 3))

    # Check bulk and spam keywords
    is_bulk, spam_score = check_spam_signals(subject, body, headers_str)
    if is_bulk or spam_score >= 2:
        if suspicious_url_count == 0 and url_count > 0:
            suspicious_url_count = min(3, url_count)
        elif url_count == 0 and spam_score >= 2:
            url_count = 2
            suspicious_url_count = 1

    email_data = {
        'subject':              subject,
        'body':                 body,
        'sender_domain':        sender_domain,
        'has_attachment':       has_attachment,
        'attachment_ext':       attachment_ext,
        'attachment_size_kb':   attachment_size_kb,
        'url_count':            url_count,
        'suspicious_url_count': suspicious_url_count,
    }

    df = pd.DataFrame([email_data])
    X  = extractor.transform(df)

    probs      = model.predict_proba(X)[0]
    pred_class = int(np.argmax(probs))

    # If strongly flagged as bulk marketing spam and predicted as Safe, adjust to Spam
    if (is_bulk or spam_score >= 3) and pred_class == 0 and not sender_domain.endswith(('edu', 'ac.in', 'gov.in')):
        pred_class = 1
        probs = [0.15, 0.70, 0.10, 0.05]

    has_malicious_ext = bool(df['is_malicious_ext'].iloc[0])
    has_urgent        = bool(df['has_urgent_kw'].iloc[0])
    has_financial     = bool(df['has_financial_kw'].iloc[0])

    return {
        'email_subject':          subject,
        'sender':                 sender_domain,
        'predicted_threat_level': CLASS_NAMES[pred_class],
        'threat_class':           pred_class,
        'threat_color':           CLASS_COLORS[pred_class],
        'confidence_scores': {
            'Safe':     round(float(probs[0]) * 100, 2),
            'Spam':     round(float(probs[1]) * 100, 2),
            'Phishing': round(float(probs[2]) * 100, 2),
            'Malware':  round(float(probs[3]) * 100, 2),
        },
        'key_indicators': {
            'URLs Detected':              url_count,
            'Suspicious URLs':            suspicious_url_count,
            'Bulk/Marketing Email':       is_bulk,
            'Suspicious Sender Domain':   sender_is_suspicious,
            'Urgent Language Detected':   has_urgent,
            'Financial Keywords Present': has_financial,
            'Malicious Attachment':       has_malicious_ext,
        },
        'parsed': {
            'subject':           subject,
            'body':              body[:2000],
            'sender_domain':     sender_domain,
            'has_attachment':    has_attachment,
            'attachment_ext':    attachment_ext,
            'attachment_size_kb': attachment_size_kb,
        }
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/detect', methods=['POST'])
def detect():
    if model is None or extractor is None:
        return jsonify({'error': 'Model not loaded.'}), 500
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    try:
        result = run_detection(
            subject            = data.get('subject', ''),
            body               = data.get('body', ''),
            sender_domain      = data.get('sender_domain', ''),
            has_attachment     = int(data.get('has_attachment', 0)),
            attachment_ext     = data.get('attachment_ext', ''),
            attachment_size_kb = float(data.get('attachment_size_kb', 0)),
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload-email', methods=['POST'])
def upload_email():
    if model is None or extractor is None:
        return jsonify({'error': 'Model not loaded.'}), 500

    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    f          = request.files['file']
    fname      = f.filename.lower()
    file_bytes = f.read()

    try:
        if fname.endswith('.eml') or fname.endswith('.mhtml') or fname.endswith('.mht'):
            parsed = parse_eml(file_bytes)
        elif fname.endswith('.pdf'):
            parsed = parse_pdf(file_bytes)
            if parsed is None:
                return jsonify({'error': 'PDF parsing library not installed.'}), 500
        else:
            return jsonify({'error': 'Unsupported file type. Please upload a .eml or .pdf file.'}), 400

        result = run_detection(
            subject            = parsed['subject'],
            body               = parsed['body'],
            sender_domain      = parsed['sender_domain'],
            has_attachment     = parsed['has_attachment'],
            attachment_ext     = parsed['attachment_ext'],
            attachment_size_kb = parsed['attachment_size_kb'],
            raw_text_for_urls  = parsed.get('raw_text_for_urls'),
            headers_str        = parsed.get('headers_str', ''),
        )
        result['file_name'] = f.filename
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
