import pickle
import numpy as np
import re
import os
from flask import Flask, render_template, request
from urllib.parse import urlparse
from report_logger import init_db, log_report, get_all_reports, get_report_count
from email_alert import send_user_warning, send_admin_report

app = Flask(__name__)

# Load ML model and feature columns
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, 'model', 'phishing_model.pkl')
features_path = os.path.join(BASE_DIR, 'model', 'feature_columns.pkl')

with open(model_path, 'rb') as f:
    model = pickle.load(f)

with open(features_path, 'rb') as f:
    feature_columns = pickle.load(f)

# Initialize database
init_db()


def extract_features_from_url(url):
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full = url.lower()

    # UsingIP
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    features['UsingIP'] = 1 if ip_pattern.search(domain) else -1

    # LongURL
    if len(url) < 54:
        features['LongURL'] = -1
    elif len(url) <= 75:
        features['LongURL'] = 0
    else:
        features['LongURL'] = 1

    # ShortURL
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co',
                  'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
    features['ShortURL'] = 1 if any(s in full for s in shorteners) else -1

    # Symbol@
    features['Symbol@'] = 1 if '@' in url else -1

    # Redirecting//
    features['Redirecting//'] = 1 if '//' in parsed.path else -1

    # PrefixSuffix-
    features['PrefixSuffix-'] = 1 if '-' in domain else -1

    # SubDomains
    dot_count = domain.count('.')
    if dot_count == 1:
        features['SubDomains'] = -1
    elif dot_count == 2:
        features['SubDomains'] = 0
    else:
        features['SubDomains'] = 1

    # HTTPS
    features['HTTPS'] = -1 if url.startswith('https') else 1

    # DomainRegLen
    features['DomainRegLen'] = -1 if len(domain) > 0 else 1

    # Favicon
    features['Favicon'] = -1

    # NonStdPort
    features['NonStdPort'] = 1 if parsed.port and parsed.port not in [80, 443] else -1

    # HTTPSDomainURL
    features['HTTPSDomainURL'] = 1 if 'https' in domain else -1

    # RequestURL
    features['RequestURL'] = -1

    # AnchorURL
    features['AnchorURL'] = 0

    # LinksInScriptTags
    features['LinksInScriptTags'] = -1

    # ServerFormHandler
    features['ServerFormHandler'] = -1

    # InfoEmail
    features['InfoEmail'] = 1 if 'mailto:' in full else -1

    # AbnormalURL
    features['AbnormalURL'] = -1 if domain in full else 1

    # WebsiteForwarding
    features['WebsiteForwarding'] = -1

    # StatusBarCust
    features['StatusBarCust'] = -1

    # DisableRightClick
    features['DisableRightClick'] = -1

    # UsingPopupWindow
    features['UsingPopupWindow'] = -1

    # IframeRedirection
    features['IframeRedirection'] = -1

    # AgeofDomain
    features['AgeofDomain'] = -1

    # DNSRecording
    features['DNSRecording'] = -1

    # WebsiteTraffic
    features['WebsiteTraffic'] = 0

    # PageRank
    features['PageRank'] = -1

    # GoogleIndex
    features['GoogleIndex'] = -1

    # LinksPointingToPage
    features['LinksPointingToPage'] = 0

    # StatsReport
    suspicious = ['login', 'verify', 'secure', 'account', 'update',
                  'banking', 'confirm', 'paypal', 'signin', 'password']
    features['StatsReport'] = 1 if any(w in full for w in suspicious) else -1

    return [features[col] for col in feature_columns]


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check_url():
    url = request.form.get('url', '').strip()
    user_email = request.form.get('email', '').strip()

    if not url:
        return render_template('index.html', error="Please enter a URL")

    # Add http if missing
    if not url.startswith('http'):
        url = 'http://' + url

    # Extract features and predict
    feature_list = np.array([extract_features_from_url(url)])
    prediction = model.predict(feature_list)[0]
    confidence = model.predict_proba(feature_list)[0][1] * 100

    is_phishing = prediction == 1

    # Build feature display
    feature_display = dict(zip(feature_columns, feature_list[0]))

    if is_phishing:
        log_report(url, confidence, user_email if user_email else None)
        if user_email:
            send_user_warning(user_email, url, confidence)
            send_admin_report(url, confidence, user_email)

    return render_template(
        'result.html',
        url=url,
        is_phishing=is_phishing,
        confidence=round(confidence, 2),
        features=feature_display
    )


@app.route('/admin')
def admin():
    reports = get_all_reports()
    total = get_report_count()
    return render_template('admin.html', reports=reports, total=total)


@app.route('/blocklist')
def blocklist():
    reports = get_all_reports()
    urls = [r[1] for r in reports]
    return '\n'.join(urls), 200, {'Content-Type': 'text/plain'}


if __name__ == '__main__':
    app.run(debug=True)