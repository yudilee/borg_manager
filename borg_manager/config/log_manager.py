"""
Borg Manager - Log Manager

Manages file logging, rotation, archiving, and pruning.
"""

import os
import time
import gzip
import glob
import shutil
import datetime
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config_manager import ConfigManager

from ..utils.constants import LOGS_DIR, LOGS_ARCHIVE_DIR

logger = logging.getLogger('BorgManager')


class LogManager:
    """Manages file logging, rotation, archiving, and pruning."""
    
    def __init__(self, config_manager: 'ConfigManager'):
        """Initialize log manager.
        
        Args:
            config_manager: ConfigManager instance for reading settings
        """
        self.config_manager = config_manager
        self._ensure_folders()
        self._run_maintenance()

    def _ensure_folders(self) -> None:
        """Ensure log directories exist."""
        os.makedirs(LOGS_DIR, exist_ok=True)
        os.makedirs(LOGS_ARCHIVE_DIR, exist_ok=True)

    def get_today_filename(self) -> str:
        """Get the path to today's log file."""
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        return os.path.join(LOGS_DIR, f"{today}.log")

    def write(self, message: str, level: str = "INFO") -> None:
        """Writes to the daily log file.
        
        Args:
            message: Log message
            level: Log level (INFO, WARNING, ERROR, SYSTEM, etc.)
        """
        try:
            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
            entry = f"[{timestamp}] [{level}] {message}\n"
            with open(self.get_today_filename(), "a", encoding="utf-8") as f:
                f.write(entry)
        except Exception as e:
            logger.error(f"Logging to file failed: {e}")

    def _run_maintenance(self) -> None:
        """Rotates, archives, and prunes logs based on policy."""
        settings = self.config_manager.config.get("log_settings", {})
        active_days = int(settings.get("active_days", 7))
        archive_days = int(settings.get("archive_days", 30))

        now = time.time()
        
        # 1. Archive old active logs
        for log_file in glob.glob(os.path.join(LOGS_DIR, "*.log")):
            # Skip today's log
            if log_file == self.get_today_filename():
                continue

            try:
                mtime = os.path.getmtime(log_file)
                if (now - mtime) > (active_days * 86400):
                    # Move and compress
                    base_name = os.path.basename(log_file)
                    archive_path = os.path.join(LOGS_ARCHIVE_DIR, f"{base_name}.gz")
                    
                    with open(log_file, 'rb') as f_in:
                        with gzip.open(archive_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    
                    os.remove(log_file)
                    self.write(f"Archived old log: {base_name}", "SYSTEM")
            except Exception as e:
                logger.error(f"Error archiving log {log_file}: {e}")

        # 2. Prune old archives
        for archive_file in glob.glob(os.path.join(LOGS_ARCHIVE_DIR, "*.gz")):
            try:
                mtime = os.path.getmtime(archive_file)
                if (now - mtime) > (archive_days * 86400):
                    os.remove(archive_file)
                    self.write(f"Pruned archived log: {os.path.basename(archive_file)}", "SYSTEM")
            except Exception as e:
                logger.error(f"Error pruning archive {archive_file}: {e}")
