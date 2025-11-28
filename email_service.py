import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

def send_role_change_email(to_email: str, new_role: str):
    """
    Sends an email to user when admin changes their role.
    """

    subject = "Your SCM Lite Account Role Has Been Updated"

    body = f"""
Hello,

Your account role has been updated by the administrator.

New Role Assigned: {new_role.upper()}

If this was not done by you, please contact the support team immediately.

Regards,
SCMLite Team
"""

    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_USER
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        # send email
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, to_email, msg.as_string())
        server.quit()

        print(f"[EMAIL SENT] Role change email sent to {to_email}")
        return True

    except Exception as e:
        print("[EMAIL ERROR]", e)
        return False
