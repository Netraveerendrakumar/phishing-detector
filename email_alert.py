import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- YOUR CREDENTIALS ---
SENDER_EMAIL = "netraveerendrakumar@gmail.com"
SENDER_PASSWORD = "pjve wyrp gyro ffxa"  # replace this
ADMIN_EMAIL = "netraveerendrakumar@gmail.com"


def send_user_warning(user_email, url, confidence):
    """Send phishing warning to the user"""
    subject = "⚠️ Phishing Alert - Suspicious URL Detected"
    body = f"""
Hello,

Our Phishing Detector has flagged a dangerous URL:

  URL      : {url}
  Risk     : {confidence:.1f}% phishing probability

Please do NOT visit this link. It may be designed
to steal your passwords or personal information.

Stay safe,
Phishing Detector System
    """
    result = _send_email(user_email, subject, body)
    return result


def send_admin_report(url, confidence, user_email=None):
    """Send phishing report to admin"""
    subject = "🚨 Admin Report - Phishing URL Detected"
    body = f"""
Admin Alert,

A new phishing URL has been flagged and logged.

  URL         : {url}
  Confidence  : {confidence:.1f}%
  Reported by : {user_email if user_email else 'Anonymous'}

Login to your admin dashboard to view all reports:
  http://127.0.0.1:5000/admin

Phishing Detector System
    """
    result = _send_email(ADMIN_EMAIL, subject, body)
    return result


def _send_email(recipient, subject, body):
    """Internal function to send email via Gmail SMTP"""
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient, msg.as_string())
        server.quit()
        print(f"✅ Email sent to {recipient}")
        return True

    except Exception as e:
        print(f"❌ Email failed: {e}")
        return False