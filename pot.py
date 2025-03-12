from flask import Flask, request, render_template, redirect
import logging
import re
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Set up logging
logging.basicConfig(filename='report1.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')

# Predefined valid credentials (use environment variables)
VALID_CREDENTIALS = {
    "admin": os.getenv("admin123"),
    "228t1a4246": os.getenv("123456789"),
    "228t1a4218": os.getenv("00000000"),
    "228t1a4264": os.getenv("00000000")
}

# Patterns to detect malicious activity
MALICIOUS_PATTERNS = {
    r"<script>": "XSS Attempt",
    r"union.*select": "SQL Injection Attempt",
    r"http[s]?://": "External URL Injection Attempt",
    r"eval\\(": "Eval Function Usage Attempt",
    r"alert\\(": "Alert Function Usage Attempt",
    r"drop\\s+table": "SQL Drop Table Attempt",
    r";--": "SQL Comment Attempt",
}

# Email Configuration (use environment variables for security)
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USER = ("vigneshguthi3212@gmail.com")  # Set this in your environment variables
EMAIL_PASSWORD = ("jobk ywlh qoto pgmk")
EMAIL_RECEIVER = ("vigneshguthi3212@gmail.com")

def send_email(subject, body):
    """Send an email alert."""
    if not EMAIL_USER or not EMAIL_PASSWORD:
        logging.error("Email credentials are not set. Skipping email alert.")
        return

    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_USER, EMAIL_RECEIVER, msg.as_string())
        server.quit()
        logging.info("Email alert sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def detect_attack_type(input_string):
    """Detects potential malicious activity based on patterns."""
    for pattern, attack_type in MALICIOUS_PATTERNS.items():
        if re.search(pattern, input_string, re.IGNORECASE):
            return attack_type
    return None

@app.before_request
def log_malicious_activity():
    """Log and alert on malicious activity."""
    attack_type = detect_attack_type(request.url)
    if attack_type:
        logging.warning(f"Malicious activity detected: {attack_type}, URL: {request.url}, IP: {request.remote_addr}")
        send_email("Malicious Activity Detected", f"Attack Type: {attack_type}\nURL: {request.url}\nIP: {request.remote_addr}")

    for key, value in request.args.items():
        attack_type = detect_attack_type(value)
        if attack_type:
            logging.warning(f"Malicious input detected: {attack_type}, Parameter: {key}={value}, IP: {request.remote_addr}")
            send_email("Malicious Input Detected", f"Attack Type: {attack_type}\nParameter: {key}={value}\nIP: {request.remote_addr}")

@app.route('/')
def index():
    logging.info(f"Connection from {request.remote_addr} - {request.headers.get('User-Agent')}")
    return render_template('fake_login.html')  # Render the HTML template

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    logging.info(f"Login attempt from {request.remote_addr} - Username: {username}")
    
    if username in VALID_CREDENTIALS and VALID_CREDENTIALS[username] == password:
        return redirect("https://dietportal.in:8443/ExamClick/")
    else:
        return "Login failed. Please try again."

@app.route('/admin')
def admin():
    logging.info(f"Unauthorized admin access attempt from {request.remote_addr}")
    return "Access Denied."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)