import logging
import smtplib
from email.message import EmailMessage

from flask import current_app

log = logging.getLogger(__name__)


def email_configured():
    return bool(current_app.config.get("SMTP_HOST"))


def send_email(to, subject, body):
    """Send a plain-text email. Without SMTP settings, logs it instead. Returns True if sent."""
    cfg = current_app.config
    if not email_configured():
        log.warning("SMTP not configured; email to %s not sent.\nSubject: %s\n\n%s", to, subject, body)
        print(f"\n--- email to {to} (SMTP not configured) ---\nSubject: {subject}\n\n{body}\n---\n", flush=True)
        return False
    msg = EmailMessage()
    msg["From"] = cfg.get("SMTP_FROM") or cfg.get("SMTP_USER")
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=15) as smtp:
        smtp.starttls()
        if cfg.get("SMTP_USER"):
            smtp.login(cfg["SMTP_USER"], cfg.get("SMTP_PASSWORD") or "")
        smtp.send_message(msg)
    return True
