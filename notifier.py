import smtplib
import requests
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def send_notifications(findings, config):
    notify_config = config.get("notifications", {})
    if not notify_config.get("enabled", False) or not findings:
        return

    methods = notify_config.get("methods", [])
    for method in methods:
        if method == "slack":
            send_slack_alert(findings, notify_config)
        elif method == "email":
            send_email_alert(findings, notify_config)

def send_slack_alert(findings, notify_config):
    webhook_url = notify_config.get("slack_webhook")
    if not webhook_url:
        print("⚠️ Slack webhook URL missing.")
        return

    message = "*Leak Hound Alert: Potential Secrets Detected*\n"
    for f in findings:
        message += f"- `{f['file']}:{f['line']}` | *{f['rule']}* | `{f['severity']}`\n"

    payload = {"text": message}

    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code != 200:
            print(f"⚠️ Slack notification failed: {response.text}")
    except Exception as e:
        print(f"⚠️ Slack error: {e}")

def send_email_alert(findings, notify_config):
    email_cfg = notify_config.get("email", {})
    smtp_server = email_cfg.get("smtp_server")
    port = email_cfg.get("port", 587)
    use_tls = email_cfg.get("use_tls", True)
    sender = email_cfg.get("from")
    receiver = email_cfg.get("to")
    username = email_cfg.get("username")
    password = email_cfg.get("password")

    # Support environment variable substitution
    if password and password.startswith("env:"):
        env_var = password.split("env:")[1]
        password = os.environ.get(env_var, "")

    if not (sender and receiver and smtp_server and password):
        print("⚠️ Email config incomplete.")
        return

    subject = "🚨 Leak Hound Alert"
    body = "Leak Hound detected potential secrets:\n\n"
    for f in findings:
        body += f"- {f['file']}:{f['line']} | {f['rule']} | {f['severity']}\n"

    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = receiver
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, port) as server:
            if use_tls:
                server.starttls(context=context)
            server.login(username, password)
            server.send_message(msg)
        print("📧 Email alert sent.")
    except Exception as e:
        print(f"⚠️ Email error: {e}")
