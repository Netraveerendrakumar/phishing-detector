import pickle
import numpy as np
import re
import requests
from flask import Flask, render_template, request
from urllib.parse import urlparse
from report_logger import init_db, log_report, get_all_reports, get_report_count
from email_alert import send_user_warning, send_admin_report

app = Flask(__name__)

# Load ML model and feature columns
with open('model/phishing_model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('model/feature_columns.pkl', 'rb') as f:
    feature_columns = pickle.load(f)

# Initialize database
init_db()


def extract_features_from_url(url):
    """
    Extract the 30 features matching our dataset columns from a raw URL.
    Returns a list of 1, 0, or -1 values matching the trained model.
    """
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full = url.lower()

    # UsingIP — is an IP address used instead of domain name
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    features['UsingIP'] = 1 if ip_pattern.search(domain) else -1

    # LongURL — URL length
    if len(url) < 54:
        features['LongURL'] = -1
    elif len(url) <= 75:
        features['LongURL'] = 0
    else:
        features['LongURL'] = 1

    # ShortURL — uses URL shortening service
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co',
                  'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
    features['ShortURL'] = 1 if any(s in full for s in shorteners) else -1

    # Symbol@ — has @ symbol in URL
    features['Symbol@'] = 1 if '@' in url else -1

    # Redirecting// — has // redirection in path
    features['Redirecting//'] = 1 if '//' in parsed.path else -1

    # PrefixSuffix- — hyphen in domain
    features['PrefixSuffix-'] = 1 if '-' in domain else -1

    # SubDomains — number of dots in domain
    dot_count = domain.count('.')
    if dot_count == 1:
        features['SubDomains'] = -1
    elif dot_count == 2:
        features['SubDomains'] = 0
    else:
        features['SubDomains'] = 1

    # HTTPS — uses HTTPS
    features['HTTPS'] = -1 if url.startswith('https') else 1

    # DomainRegLen — domain length as proxy for registration length
    features['DomainRegLen'] = -1 if len(domain) > 0 else 1

    # Favicon — assume legitimate (hard to check without loading page)
    features['Favicon'] = -1

    # NonStdPort — uses non-standard port
    features['NonStdPort'] = 1 if parsed.port and parsed.port not in [80, 443] else -1

    # HTTPSDomainURL — HTTPS in domain name (phishing trick)
    features['HTTPSDomainURL'] = 1 if 'https' in domain else -1

    # RequestURL — assume mostly legitimate
    features['RequestURL'] = -1

    # AnchorURL — assume moderate
    features['AnchorURL'] = 0

    # LinksInScriptTags — assume legitimate
    features['LinksInScriptTags'] = -1

    # ServerFormHandler — assume legitimate
    features['ServerFormHandler'] = -1

    # InfoEmail — email address in URL
    features['InfoEmail'] = 1 if 'mailto:' in full else -1

    # AbnormalURL — domain not in URL (basic check)
    features['AbnormalURL'] = -1 if domain in full else 1

    # WebsiteForwarding — assume low redirects
    features['WebsiteForwarding'] = -1

    # StatusBarCust — assume legitimate
    features['StatusBarCust'] = -1

    # DisableRightClick — assume legitimate
    features['DisableRightClick'] = -1

    # UsingPopupWindow — assume legitimate
    features['UsingPopupWindow'] = -1

    # IframeRedirection — assume legitimate
    features['IframeRedirection'] = -1

    # AgeofDomain — assume older domain
    features['AgeofDomain'] = -1

    # DNSRecording — assume has DNS record
    features['DNSRecording'] = -1

    # WebsiteTraffic — assume moderate
    features['WebsiteTraffic'] = 0

    # PageRank — assume has rank
    features['PageRank'] = -1

    # GoogleIndex — assume indexed
    features['GoogleIndex'] = -1

    # LinksPointingToPage — assume some links
    features['LinksPointingToPage'] = 0

    # StatsReport — check suspicious keywords
    suspicious = ['login', 'verify', 'secure', 'account', 'update',
                  'banking', 'confirm', 'paypal', 'signin', 'password']
    features['StatsReport'] = 1 if any(w in full for w in suspicious) else -1

    # Return in exact column order the model was trained on
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

    # Build readable feature breakdown for UI
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