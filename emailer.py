# controller/emailer.py
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

logger = logging.getLogger(__name__)

SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
SMTP_FROM = os.getenv("SMTP_FROM", "orchestration@example.com")
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "true").lower() in ("1", "true", "yes")

def send_email(to_addresses, subject, html_body, text_body=None):
    if isinstance(to_addresses, str):
        to_addresses = [to_addresses]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to_addresses)

    if text_body is None:
        text_body = "Please view this message in an HTML-capable client."

    part1 = MIMEText(text_body, "plain")
    part2 = MIMEText(html_body, "html")

    msg.attach(part1)
    msg.attach(part2)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            if SMTP_STARTTLS and SMTP_USERNAME:
                smtp.starttls()
            if SMTP_USERNAME:
                smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.sendmail(SMTP_FROM, to_addresses, msg.as_string())
        logger.info("Email sent to %s: %s", to_addresses, subject)
        return True
    except Exception as e:
        logger.exception("Failed to send email: %s", e)
        return False
