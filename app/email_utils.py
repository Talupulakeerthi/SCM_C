import re
import dns.resolver
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from .config import EMAIL_USER, EMAIL_PASS, logger

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

def is_real_domain_email(email: str) -> bool:
    if not bool(EMAIL_RE.match(email)): return False
    domain = email.split("@", 1)[1].lower()
    try:
        return len(dns.resolver.resolve(domain, "MX", lifetime=5)) > 0
    except: return False

def send_email(to_email: str, subject: str, body: str):
    if not EMAIL_USER or not EMAIL_PASS:
        with open("sent_emails.log", "a") as f:
            f.write(f"TO: {to_email} SUBJ: {subject}\n{body}\n\n")
        return

    msg = MIMEMultipart()
    msg["From"], msg["To"], msg["Subject"] = EMAIL_USER, to_email, subject
    msg.attach(MIMEText(body, "plain"))
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=20)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, [to_email], msg.as_string())
        server.quit()
    except Exception:
        logger.exception(f"Failed to email {to_email}")