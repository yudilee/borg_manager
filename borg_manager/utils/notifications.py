"""
Borg Manager - Desktop Notifications

Cross-platform desktop notification support.
"""

import subprocess
import platform
import logging

logger = logging.getLogger('BorgManager')


def send_notification(title: str, message: str, urgency: str = "normal") -> None:
    """Send a desktop notification cross-platform.
    
    Args:
        title: Notification title
        message: Notification body text
        urgency: Priority level (low, normal, critical)
    """
    try:
        system = platform.system()
        
        if system == "Linux":
            # Use notify-send on Linux
            subprocess.run([
                "notify-send", 
                "-u", urgency,
                "-a", "Borg Backup Manager",
                title, 
                message
            ], capture_output=True, timeout=5)
            
        elif system == "Darwin":
            # Use osascript on macOS
            script = f'display notification "{message}" with title "{title}"'
            subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
            
        elif system == "Windows":
            # Use PowerShell toast notification on Windows
            ps_script = f'''
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
            $textNodes = $template.GetElementsByTagName("text")
            $textNodes.Item(0).AppendChild($template.CreateTextNode("{title}")) | Out-Null
            $textNodes.Item(1).AppendChild($template.CreateTextNode("{message}")) | Out-Null
            $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Borg Backup Manager").Show($toast)
            '''
            subprocess.run(["powershell", "-Command", ps_script], capture_output=True, timeout=10)
            
    except Exception as e:
        logger.debug(f"Notification failed: {e}")
