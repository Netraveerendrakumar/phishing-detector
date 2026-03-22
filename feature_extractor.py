import re
import requests
from urllib.parse import urlparse

def extract_features(url):
    features = {}

    # Basic URL properties
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_at'] = url.count('@')
    features['num_question'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_underscores'] = url.count('_')
    features['num_percent'] = url.count('%')
    features['num_ampersand'] = url.count('&')

    # Has HTTPS or not
    features['has_https'] = 1 if url.startswith('https') else 0

    # Domain features
    parsed = urlparse(url)
    domain = parsed.netloc
    features['domain_length'] = len(domain)

    # Suspicious keywords in URL
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account',
                           'banking', 'confirm', 'paypal', 'signin', 'free',
                           'lucky', 'bonus', 'click', 'password', 'credential']
    features['has_suspicious_keyword'] = 1 if any(
        word in url.lower() for word in suspicious_keywords
    ) else 0

    # IP address used instead of domain
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    features['has_ip'] = 1 if ip_pattern.search(domain) else 0

    # Subdomain count
    features['subdomain_count'] = len(domain.split('.')) - 2 if domain else 0

    # Path length
    features['path_length'] = len(parsed.path)

    # Has port number
    features['has_port'] = 1 if parsed.port else 0

    return features


def features_to_list(features_dict):
    """Convert features dict to ordered list for model input"""
    keys = [
        'url_length', 'num_dots', 'num_hyphens', 'num_slashes',
        'num_at', 'num_question', 'num_equals', 'num_underscores',
        'num_percent', 'num_ampersand', 'has_https', 'domain_length',
        'has_suspicious_keyword', 'has_ip', 'subdomain_count',
        'path_length', 'has_port'
    ]
    return [features_dict[k] for k in keys]