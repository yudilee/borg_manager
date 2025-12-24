"""
Borg Manager - Webhook Notifications

Send notifications to external services via webhooks and email.
"""

import logging
import json
from typing import Optional, Dict, Any
import urllib.request
import urllib.error
import ssl

logger = logging.getLogger('BorgManager')


def send_webhook(url: str, payload: Dict[str, Any], 
                 headers: Optional[Dict[str, str]] = None) -> bool:
    """Send a webhook notification.
    
    Args:
        url: Webhook URL endpoint
        payload: JSON payload to send
        headers: Optional additional headers
        
    Returns:
        True if successful, False otherwise
    """
    try:
        data = json.dumps(payload).encode('utf-8')
        request_headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'BorgBackupManager/1.0'
        }
        if headers:
            request_headers.update(headers)
        
        req = urllib.request.Request(url, data=data, headers=request_headers, method='POST')
        
        # Allow self-signed certs in dev environments
        ctx = ssl.create_default_context()
        
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            return response.status == 200
            
    except urllib.error.HTTPError as e:
        logger.error(f"Webhook HTTP error: {e.code} - {e.reason}")
        return False
    except urllib.error.URLError as e:
        logger.error(f"Webhook URL error: {e.reason}")
        return False
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return False


def send_slack_notification(webhook_url: str, message: str, 
                            title: str = "Borg Backup", 
                            status: str = "info") -> bool:
    """Send a Slack notification.
    
    Args:
        webhook_url: Slack incoming webhook URL
        message: Message text
        title: Message title/header
        status: 'success', 'error', or 'info' for color coding
        
    Returns:
        True if successful
    """
    color_map = {
        "success": "#36a64f",
        "error": "#ff0000",
        "info": "#439FE0"
    }
    
    payload = {
        "attachments": [{
            "color": color_map.get(status, color_map["info"]),
            "title": title,
            "text": message,
            "footer": "Borg Backup Manager"
        }]
    }
    
    return send_webhook(webhook_url, payload)


def send_discord_notification(webhook_url: str, message: str,
                              title: str = "Borg Backup",
                              status: str = "info") -> bool:
    """Send a Discord notification.
    
    Args:
        webhook_url: Discord webhook URL
        message: Message text
        title: Embed title
        status: 'success', 'error', or 'info' for color coding
        
    Returns:
        True if successful
    """
    color_map = {
        "success": 0x36a64f,
        "error": 0xff0000,
        "info": 0x439FE0
    }
    
    payload = {
        "embeds": [{
            "title": title,
            "description": message,
            "color": color_map.get(status, color_map["info"]),
            "footer": {"text": "Borg Backup Manager"}
        }]
    }
    
    return send_webhook(webhook_url, payload)


def send_generic_webhook(webhook_url: str, job_name: str, 
                         status: str, duration: str,
                         stats: Optional[Dict] = None) -> bool:
    """Send a generic webhook notification with backup details.
    
    Args:
        webhook_url: Webhook URL
        job_name: Name of the backup job
        status: 'Success' or 'Failed'
        duration: Duration string
        stats: Optional backup statistics
        
    Returns:
        True if successful
    """
    payload = {
        "event": "backup_complete",
        "job_name": job_name,
        "status": status,
        "duration": duration,
        "timestamp": __import__("datetime").datetime.now().isoformat(),
        "stats": stats or {}
    }
    
    return send_webhook(webhook_url, payload)


# Email support (requires smtplib, included in Python stdlib)
def send_email_notification(smtp_host: str, smtp_port: int,
                            from_addr: str, to_addr: str,
                            subject: str, body: str,
                            username: Optional[str] = None,
                            password: Optional[str] = None,
                            use_tls: bool = True) -> bool:
    """Send an email notification.
    
    Args:
        smtp_host: SMTP server hostname
        smtp_port: SMTP server port
        from_addr: Sender email address
        to_addr: Recipient email address
        subject: Email subject
        body: Email body text
        username: Optional SMTP username
        password: Optional SMTP password
        use_tls: Whether to use TLS encryption
        
    Returns:
        True if successful
    """
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        if use_tls:
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
        else:
            server = smtplib.SMTP(smtp_host, smtp_port)
        
        if username and password:
            server.login(username, password)
        
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email sent to {to_addr}")
        return True
        
    except Exception as e:
        logger.error(f"Email error: {e}")
        return False
