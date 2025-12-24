"""
Borg Manager - Formatting Utilities

Helper functions for formatting bytes, dates, and other display values.
"""

import datetime
from typing import Union


def format_bytes(size: Union[int, float]) -> str:
    """Converts raw bytes to human readable string.
    
    Args:
        size: Size in bytes
        
    Returns:
        Human-readable string like "1.50 GB"
    """
    if not isinstance(size, (int, float)):
        return "0 B"
    
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T', 5: 'P'}
    
    while size > power:
        size /= power
        n += 1
    
    return f"{size:.2f} {power_labels.get(n, '?')}B"


def time_since(dt_str: str) -> str:
    """Calculate human-readable time since given datetime string.
    
    Args:
        dt_str: ISO format datetime string
        
    Returns:
        Human-readable time like "5 hours ago"
    """
    try:
        dt_str = dt_str.replace('T', ' ')
        if '.' in dt_str:
            dt_str = dt_str.split('.')[0]
        
        past = datetime.datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.datetime.now()
        diff = now - past
        
        days = diff.days
        seconds = diff.seconds
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        
        if days > 0:
            return f"{days} days ago"
        elif hours > 0:
            return f"{hours} hours ago"
        elif minutes > 0:
            return f"{minutes} mins ago"
        else:
            return "Just now"
    except Exception:
        return "Unknown"


def format_duration(seconds: int) -> str:
    """Format seconds into human-readable duration.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        String like "2h 15m 30s"
    """
    if seconds < 60:
        return f"{seconds}s"
    
    minutes, secs = divmod(seconds, 60)
    hours, mins = divmod(minutes, 60)
    
    if hours > 0:
        return f"{hours}h {mins}m {secs}s"
    else:
        return f"{mins}m {secs}s"
