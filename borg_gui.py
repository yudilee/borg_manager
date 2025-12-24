"""
Borg Backup Manager - GUI Application

A full-featured graphical interface for managing BorgBackup repositories.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import subprocess
import threading
import json
import os
import shutil
import datetime
import shlex
import re
import time
import sys
import platform
import uuid
import stat
import gzip
import glob
import math
import logging
from typing import Optional, Tuple, List, Dict, Any, Callable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('BorgManager')

# ===========================================
# Import from modular package
# ===========================================
from borg_manager.utils.constants import (
    THEME_COLORS, ICONS, icon, USE_EMOJI,
    PLATFORM_FONTS, DEFAULT_FONT, MONO_FONT, get_platform_fonts,
    KEYRING_SERVICE
)
from borg_manager.utils.formatting import format_bytes, time_since
from borg_manager.utils.notifications import send_notification
from borg_manager.utils.security import (
    store_passphrase, retrieve_passphrase, delete_passphrase, HAS_KEYRING
)

# ===========================================
# Try to import optional dependencies
# ===========================================
HAS_TRAY = False
try:
    import pystray
    from PIL import Image, ImageDraw, ImageTk
    HAS_TRAY = True
except (ImportError, ValueError, Exception) as e:
    logger.warning(f"System Tray not available: {e}")

HAS_MATPLOTLIB = False
try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    logger.info("Matplotlib not found. Charts will be disabled.")

HAS_PARAMIKO = False
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    logger.info("Paramiko not found. Will use system SSH command.")

# ===========================================
# Application Paths (local to main app)
# ===========================================
if getattr(sys, 'frozen', False):
    APP_EXEC_DIR = os.path.dirname(sys.executable)
    USE_USER_HOME = True
else:
    APP_EXEC_DIR = os.path.dirname(os.path.abspath(__file__))
    USE_USER_HOME = False

DATA_ROOT = APP_EXEC_DIR
if USE_USER_HOME:
    DATA_ROOT = os.path.join(os.path.expanduser("~"), ".config", "borg_manager")
    os.makedirs(DATA_ROOT, exist_ok=True)

CONFIG_SUBDIR = os.path.join(DATA_ROOT, "config")
SCRIPTS_DIR = os.path.join(DATA_ROOT, "scripts")
LOGS_DIR = os.path.join(DATA_ROOT, "logs")
LOGS_ARCHIVE_DIR = os.path.join(LOGS_DIR, "archive")

ROOT_CONFIG = os.path.join(DATA_ROOT, "config.json")
SUB_CONFIG = os.path.join(CONFIG_SUBDIR, "config.json")

if os.path.exists(ROOT_CONFIG):
    CONFIG_FILE = ROOT_CONFIG
else:
    CONFIG_FILE = SUB_CONFIG

if CONFIG_FILE == SUB_CONFIG:
    os.makedirs(CONFIG_SUBDIR, exist_ok=True)

for d in [SCRIPTS_DIR, LOGS_DIR, LOGS_ARCHIVE_DIR]:
    os.makedirs(d, exist_ok=True)

# ==========================================
# SSH HELPER (Cross-platform remote execution)
# ==========================================

class SSHHelper:
    """Handles SSH connections for remote command execution.
    Uses Paramiko if available (Windows), otherwise system ssh.
    
    Attributes:
        host: Full host string in user@hostname format
        ssh_key: Path to SSH private key file
        password: SSH password for authentication
        username: Parsed username from host
        hostname: Parsed hostname from host
    """
    
    def __init__(self, host: str, ssh_key: Optional[str] = None, password: Optional[str] = None) -> None:
        """Initialize SSH helper.
        
        Args:
            host: user@hostname format
            ssh_key: Path to private key file (optional)
            password: SSH password (optional, used if key not provided)
        """
        self.host = host
        self.ssh_key = ssh_key
        self.password = password
        self._parse_host()
    
    def _parse_host(self):
        """Parse user@hostname into components."""
        if "@" in self.host:
            self.username, self.hostname = self.host.split("@", 1)
        else:
            self.username = None
            self.hostname = self.host
    
    def execute(self, command, timeout=300):
        """Execute command on remote host.
        
        Returns:
            tuple: (success: bool, output: str, error: str)
        """
        if HAS_PARAMIKO:
            return self._execute_paramiko(command, timeout)
        else:
            return self._execute_subprocess(command, timeout)
    
    def _execute_paramiko(self, command, timeout):
        """Execute using Paramiko library."""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_args = {
                "hostname": self.hostname,
                "timeout": 30
            }
            if self.username:
                connect_args["username"] = self.username
            if self.ssh_key:
                connect_args["key_filename"] = self.ssh_key
            elif self.password:
                connect_args["password"] = self.password
            
            client.connect(**connect_args)
            
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            output = stdout.read().decode("utf-8", errors="replace")
            error = stderr.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()
            
            client.close()
            
            return (exit_code == 0, output, error)
        except Exception as e:
            return (False, "", str(e))
    
    def _execute_subprocess(self, command, timeout):
        """Execute using system ssh command."""
        ssh_cmd = ["ssh"]
        if self.ssh_key:
            ssh_cmd.extend(["-i", self.ssh_key])
        ssh_cmd.extend(["-o", "StrictHostKeyChecking=accept-new"])
        ssh_cmd.append(self.host)
        ssh_cmd.append(command)
        
        try:
            result = subprocess.run(
                ssh_cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return (result.returncode == 0, result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            return (False, "", "Command timed out")
        except Exception as e:
            return (False, "", str(e))
    
    def execute_stream(self, command, callback, timeout=600):
        """Execute command and stream output line by line.
        
        Args:
            command: Command to run
            callback: Function to call with each line of output
            timeout: Max execution time
        
        Returns:
            tuple: (success: bool, error: str)
        """
        if HAS_PARAMIKO:
            return self._stream_paramiko(command, callback, timeout)
        else:
            return self._stream_subprocess(command, callback, timeout)
    
    def _stream_paramiko(self, command, callback, timeout):
        """Stream output using Paramiko with proper progress handling.
        
        Uses chunk-based reading to handle borg's carriage return progress updates.
        """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_args = {"hostname": self.hostname, "timeout": 30}
            if self.username:
                connect_args["username"] = self.username
            if self.ssh_key:
                connect_args["key_filename"] = self.ssh_key
            elif self.password:
                connect_args["password"] = self.password
            
            client.connect(**connect_args)
            
            # Use get_pty=True to merge stdout/stderr and get real-time output
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=True)
            
            # Read in chunks instead of lines to handle \r progress updates
            channel = stdout.channel
            buffer = ""
            
            import time
            while not channel.exit_status_ready() or channel.recv_ready():
                if channel.recv_ready():
                    try:
                        chunk = channel.recv(4096).decode("utf-8", errors="replace")
                        buffer += chunk
                        
                        # Process complete lines (split on \r or \n)
                        while '\r' in buffer or '\n' in buffer:
                            # Find the earliest line separator
                            r_pos = buffer.find('\r')
                            n_pos = buffer.find('\n')
                            
                            if r_pos == -1:
                                split_pos = n_pos
                            elif n_pos == -1:
                                split_pos = r_pos
                            else:
                                split_pos = min(r_pos, n_pos)
                            
                            line = buffer[:split_pos]
                            # Skip \r\n as single separator
                            if split_pos + 1 < len(buffer) and buffer[split_pos:split_pos+2] == '\r\n':
                                buffer = buffer[split_pos + 2:]
                            else:
                                buffer = buffer[split_pos + 1:]
                            
                            if line.strip():
                                callback(line.strip())
                    except Exception:
                        pass
                else:
                    time.sleep(0.05)  # Small delay to prevent busy-waiting
            
            # Process any remaining buffer content
            if buffer.strip():
                callback(buffer.strip())
            
            exit_code = channel.recv_exit_status()
            client.close()
            
            return (exit_code == 0, "")
        except Exception as e:
            return (False, str(e))
    
    def _stream_subprocess(self, command, callback, timeout):
        """Stream output using subprocess with proper progress handling.
        
        Uses character-by-character reading to handle borg's carriage return progress updates.
        """
        ssh_cmd = ["ssh", "-tt"]  # Force PTY allocation for real-time output
        if self.ssh_key:
            ssh_cmd.extend(["-i", self.ssh_key])
        ssh_cmd.extend(["-o", "StrictHostKeyChecking=accept-new"])
        ssh_cmd.append(self.host)
        ssh_cmd.append(command)
        
        try:
            process = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr into stdout
                bufsize=0  # Unbuffered for real-time output
            )
            
            buffer = ""
            while True:
                # Read one byte at a time for immediate output
                byte = process.stdout.read(1)
                if not byte:
                    break
                    
                char = byte.decode("utf-8", errors="replace")
                
                if char in ('\r', '\n'):
                    if buffer.strip():
                        callback(buffer.strip())
                    buffer = ""
                else:
                    buffer += char
            
            # Process any remaining buffer
            if buffer.strip():
                callback(buffer.strip())
            
            process.wait(timeout=timeout)
            
            return (process.returncode == 0, "")
        except subprocess.TimeoutExpired:
            process.kill()
            return (False, "Command timed out")
        except Exception as e:
            return (False, str(e))
    
    def list_dir(self, path):
        """List directory contents on remote host.
        
        Returns:
            list: List of tuples (name, is_dir) or empty list on error
        """
        # Use ls -la to get file info
        cmd = f"ls -la '{path}' 2>/dev/null | tail -n +2"
        success, output, error = self.execute(cmd, timeout=30)
        
        if not success:
            return []
        
        items = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 9:
                continue
            
            permissions = parts[0]
            name = " ".join(parts[8:])  # Name may contain spaces
            
            if name in (".", ".."):
                continue
            
            is_dir = permissions.startswith("d")
            items.append((name, is_dir))
        
        return sorted(items, key=lambda x: (not x[1], x[0].lower()))
    
    def get_home(self):
        """Get home directory on remote host."""
        success, output, error = self.execute("echo $HOME", timeout=10)
        if success:
            return output.strip()
        return "/"
    
    def download_file(self, remote_path, local_path, progress_callback=None):
        """Download a file from remote host via SFTP.
        
        Args:
            remote_path: Path on remote server
            local_path: Local destination path
            progress_callback: Optional callback(transferred, total) for progress
        
        Returns:
            tuple: (success: bool, error: str)
        """
        if not HAS_PARAMIKO:
            return (False, "Paramiko not available")
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_args = {"hostname": self.hostname, "timeout": 30}
            if self.username:
                connect_args["username"] = self.username
            if self.ssh_key:
                connect_args["key_filename"] = self.ssh_key
            elif self.password:
                connect_args["password"] = self.password
            
            client.connect(**connect_args)
            sftp = client.open_sftp()
            
            # Get file size for progress
            stat = sftp.stat(remote_path)
            total_size = stat.st_size
            
            def progress(transferred, total):
                if progress_callback:
                    progress_callback(transferred, total)
            
            sftp.get(remote_path, local_path, callback=progress)
            
            sftp.close()
            client.close()
            return (True, "")
        except Exception as e:
            return (False, str(e))

class LogManager:
    """Manages file logging, rotation, archiving, and pruning."""
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self._ensure_folders()
        self._run_maintenance()

    def _ensure_folders(self):
        os.makedirs(LOGS_DIR, exist_ok=True)
        os.makedirs(LOGS_ARCHIVE_DIR, exist_ok=True)

    def get_today_filename(self):
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        return os.path.join(LOGS_DIR, f"{today}.log")

    def write(self, message, level="INFO"):
        """Writes to the daily log file."""
        try:
            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
            entry = f"[{timestamp}] [{level}] {message}\n"
            with open(self.get_today_filename(), "a", encoding="utf-8") as f:
                f.write(entry)
        except Exception as e:
            logger.error(f"Logging to file failed: {e}")

    def _run_maintenance(self):
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

class ConfigManager:
    def __init__(self):
        self.active_source_id = None  # Track which source we're working with
        self.config = {
            "current_repo": None,
            "borg_binary": None,
            "jobs": {},
            "source_servers": {
                "__local__": {
                    "name": "Local Machine",
                    "host": None,
                    "ssh_key": None,
                    "repos": {}  # Now a dict of repo configs, not a list of names
                }
            },
            "log_settings": {
                "active_days": 7,
                "archive_days": 90
            }
        }
        self.load_config()

    def load_config(self):
        # Legacy config support
        old_config = os.path.expanduser("~/.config/borg-gui-config.json")
        if os.path.exists(old_config) and not os.path.exists(CONFIG_FILE):
             try:
                 shutil.move(old_config, CONFIG_FILE)
             except: pass

        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    self.config.update(data)
                    
                    if "log_settings" not in self.config:
                        self.config["log_settings"] = {"active_days": 7, "archive_days": 90}
                    
                    # Migration: Add source_servers if not present
                    if "source_servers" not in self.config:
                        self.config["source_servers"] = {
                            "__local__": {
                                "name": "Local Machine",
                                "host": None,
                                "ssh_key": None,
                                "repos": list(self.config.get("repos", {}).keys())
                            }
                        }

            except Exception as e:
                logger.error(f"Error loading config: {e}")

    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving config: {e}")

    def add_history_entry(self, job_name, repo_name, status, duration, start_time, stats=None, source=None):
        """Add a job execution record to history."""
        if "history" not in self.config:
            self.config["history"] = []
        
        entry = {
            "id": str(uuid.uuid4())[:8],
            "job": job_name,
            "repo": repo_name,
            "source": source or "__local__",
            "status": status,
            "duration": duration,
            "start": start_time,
            "stats": stats or {}
        }
        
        # Add to beginning
        self.config["history"].insert(0, entry)
        
        # Keep only last 50
        if len(self.config["history"]) > 50:
            self.config["history"] = self.config["history"][:50]
            
        self.save_config()
        
    def get_history(self):
        return self.config.get("history", [])

    def set_active_source(self, source_id):
        """Set the active source server for repo operations."""
        self.active_source_id = source_id
    
    def get_active_source_repos(self):
        """Get repos dict for active source server."""
        if not self.active_source_id:
            return {}
        srv = self.config.get("source_servers", {}).get(self.active_source_id)
        if srv:
            return srv.get("repos", {})
        return {}

    def add_repo(self, name, path, pass_cmd="", ssh_password="", repo_passphrase="", source_id=None):
        """Add a repo to the specified (or active) source server.
        
        If keyring is available, passphrases are stored securely in the system keyring.
        Otherwise, they are stored in the config file (less secure).
        """
        sid = source_id or self.active_source_id
        if not sid:
            logger.error("No active source server set")
            return
        
        if sid not in self.config.get("source_servers", {}):
            logger.error(f"Source server {sid} not found")
            return
        
        # Ensure repos is a dict
        if not isinstance(self.config["source_servers"][sid].get("repos"), dict):
            self.config["source_servers"][sid]["repos"] = {}
        
        # Try to store passphrase in keyring
        stored_in_keyring = False
        keyring_key = f"{sid}:{name}"
        if repo_passphrase:
            stored_in_keyring = store_passphrase(keyring_key, repo_passphrase)
        
        self.config["source_servers"][sid]["repos"][name] = {
            "path": path, 
            "pass_command": pass_cmd,
            "ssh_password": ssh_password,
            # Only store in config if keyring storage failed
            "repo_passphrase": "" if stored_in_keyring else repo_passphrase,
            "passphrase_in_keyring": stored_in_keyring
        }
        if not self.config["current_repo"]:
            self.config["current_repo"] = name
        self.save_config()
    
    def get_repo_passphrase(self, name: str, source_id: str = None) -> str:
        """Get passphrase for a repo, checking keyring first then config.
        
        Args:
            name: Repository name
            source_id: Source server ID (uses active if not specified)
            
        Returns:
            The passphrase or empty string if not found
        """
        sid = source_id or self.active_source_id
        if not sid:
            return ""
        
        repo = self.config.get("source_servers", {}).get(sid, {}).get("repos", {}).get(name, {})
        
        # Check keyring first
        if repo.get("passphrase_in_keyring"):
            keyring_key = f"{sid}:{name}"
            passphrase = retrieve_passphrase(keyring_key)
            if passphrase:
                return passphrase
        
        # Fallback to config
        return repo.get("repo_passphrase", "")

    def delete_repo(self, name, source_id=None):
        """Delete a repo from the specified (or active) source server."""
        sid = source_id or self.active_source_id
        if not sid:
            return
        
        repos = self.config.get("source_servers", {}).get(sid, {}).get("repos", {})
        if name in repos:
            del self.config["source_servers"][sid]["repos"][name]
            if self.config["current_repo"] == name:
                self.config["current_repo"] = None
            self.save_config()

    def get_current_repo_details(self):
        """Get current repo details from active source server."""
        name = self.config.get("current_repo")
        repos = self.get_active_source_repos()
        if name and name in repos:
            return name, repos[name]
        return None, None

    def get_repo_details(self, name, source_id=None):
        """Get repo details from specified (or active) source server."""
        sid = source_id or self.active_source_id
        if not sid:
            return None
        repos = self.config.get("source_servers", {}).get(sid, {}).get("repos", {})
        return repos.get(name)

    def set_borg_binary(self, path):
        self.config["borg_binary"] = path
        self.save_config()
    
    # --- JOB MANAGEMENT ---
    def save_job(self, job_data):
        if "id" not in job_data or not job_data["id"]:
            job_data["id"] = str(uuid.uuid4())
        self.config["jobs"][job_data["id"]] = job_data
        self.save_config()
        return job_data["id"]

    def delete_job(self, job_id):
        if job_id in self.config["jobs"]:
            del self.config["jobs"][job_id]
            self.save_config()

    # --- SOURCE SERVER MANAGEMENT ---
    def get_source_servers(self):
        """Returns dict of all source servers."""
        return self.config.get("source_servers", {})
    
    def add_source_server(self, server_id, name, host, ssh_key=None, repos=None):
        """Add or update a source server."""
        if "source_servers" not in self.config:
            self.config["source_servers"] = {}
        
        self.config["source_servers"][server_id] = {
            "name": name,
            "host": host,
            "ssh_key": ssh_key,
            "repos": repos if isinstance(repos, dict) else {}  # Now a dict, not list
        }
        self.save_config()
    
    def delete_source_server(self, server_id):
        """Delete a source server (cannot delete __local__)."""
        if server_id == "__local__":
            return False
        if server_id in self.config.get("source_servers", {}):
            del self.config["source_servers"][server_id]
            self.save_config()
            return True
        return False
    
    def get_source_server(self, server_id):
        """Get details of a specific source server."""
        return self.config.get("source_servers", {}).get(server_id)

# ==========================================
# CRON & SCRIPT GENERATION
# ==========================================

class CronManager:
    @staticmethod
    def generate_job_script(job, repo_config, borg_bin, ssh_helper=None):
        """Generates a standalone .sh script for the backup job"""
        job_id = job["id"]
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', job["name"])
        
        # Decide paths based on local/remote
        if ssh_helper:
            # Remote paths - mirror structure in .config
            remote_home = ssh_helper.get_home().rstrip('/')
            base_dir = f"{remote_home}/.config/borg_manager"
            scripts_dir = f"{base_dir}/scripts"
            logs_dir = f"{base_dir}/logs"
            
            # Ensure directories exist
            ssh_helper.execute(f"mkdir -p {scripts_dir} {logs_dir}")
            
            script_path = f"{scripts_dir}/job_{job_id}_{safe_name}.sh"
            log_file = f"{logs_dir}/job_{job_id}_cron.log"
            history_file = f"{logs_dir}/cron_history.jsonl"
            
            # Use just 'borg' commands since we assume it's in path or handled by ssh session
            # but we passed borg_bin which might be a full path on local.
            # For remote, typically just "borg" is safe, or we use what's passed if it looks like a path?
            # Let's default to "borg" if we are remote, unless specific path known.
            # But the caller might pass a local path.
            borg_inv = "borg" 
        else:
            # Local paths
            if not os.path.exists(SCRIPTS_DIR): os.makedirs(SCRIPTS_DIR)
            script_path = os.path.join(SCRIPTS_DIR, f"job_{job_id}_{safe_name}.sh")
            log_file = os.path.join(LOGS_DIR, f"job_{job_id}_cron.log")
            history_file = "$HOME/.config/borg_manager/logs/cron_history.jsonl" # Shell variable fine here
            borg_inv = borg_bin
        
        repo_path = repo_config["path"]
        
        # Build Includes/Excludes
        args = []
        for exc in job.get("excludes", []):
            args.append(f"--exclude '{exc}'")
        
        # Archive Name Format
        archive_name = f"{safe_name}-$(date +%Y-%m-%d-%H%M)"
        
        # Environment Setup
        env_vars = []
        env_vars.append(f"export BORG_REPO='{repo_path}'")
        
        # Handle Passwords
        if repo_config.get("repo_passphrase"):
            env_vars.append(f"export BORG_PASSPHRASE='{repo_config['repo_passphrase']}'")
        elif repo_config.get("pass_command"):
             env_vars.append(f"export BORG_PASSCOMMAND='{repo_config['pass_command']}'")
             
        rsh_cmd = "ssh -o StrictHostKeyChecking=accept-new"
        if repo_config.get("ssh_password") and shutil.which("sshpass"):
             # Note: check shutil.which on remote is hard, we assume if password provided we try to use it?
             # Or we just export it. SSHPASS env var is used by sshpass tool.
             # If running on remote server, that server needs sshpass if using password auth to repo.
             env_vars.append(f"export SSHPASS='{repo_config['ssh_password']}'")
             # We assume sshpass is available on the runner (remote or local)
             rsh_cmd = f"sshpass -e {rsh_cmd}"
        
        env_vars.append(f"export BORG_RSH='{rsh_cmd}'")
        env_vars.append("export BORG_RELOCATED_REPO_ACCESS_IS_OK=no")

        # Script Content
        content = [
            "#!/bin/bash",
            f"# Borg Backup Job: {job['name']}",
            f"# ID: {job_id}",
            "",
            "echo \"Starting Backup: $(date)\" >> " + log_file,
            "",
            "# Environment Variables"
        ]
        content.extend(env_vars)
        
        # Borg Create Command
        includes_str = "' '" .join(job.get("includes", []))
        if includes_str: includes_str = f"'{includes_str}'"
        
        borg_cmd = f"{borg_inv} create --stats --compression zstd,6 {' '.join(args)} ::{archive_name} {includes_str}"
        
        content.append("")
        content.append("# Run Backup")
        content.append(f"{borg_cmd} >> {log_file} 2>&1")
        
        # Capture status
        content.append("if [ $? -eq 0 ]; then")
        content.append(f"    echo \"Backup Success: $(date)\" >> {log_file}")
        content.append("    JOB_STATUS=\"Success\"")
        
        # Pruning Logic in Script
        if job.get("prune_enabled", False):
            d = job.get("keep_daily", 7)
            w = job.get("keep_weekly", 4)
            m = job.get("keep_monthly", 6)
            content.append("    # Run Prune")
            content.append(f"    echo \"Starting Prune...\" >> {log_file}")
            content.append(f"    {borg_inv} prune --list --stats --keep-daily {d} --keep-weekly {w} --keep-monthly {m} >> {log_file} 2>&1")
        
        content.append("else")
        content.append(f"    echo \"Backup Failed: $(date)\" >> {log_file}")
        content.append("    JOB_STATUS=\"Failed\"")
        content.append("fi")
        
        # Write File
        content.append("")
        content.append("# --- JSON HISTORY LOGGING ---")
        if ssh_helper:
             content.append(f"HISTORY_FILE=\"{history_file}\"")
        else:
             content.append(f"HISTORY_FILE=\"{history_file}\"")
             
        content.append("mkdir -p \"$(dirname \"$HISTORY_FILE\")\"")
        content.append("END_TIME=$(date +%Y-%m-%d\ %H:%M)")
        content.append("DURATION=\"Unknown\"")
        
        content.append(f"JOB_NAME=\"{job['name']}\"")
        content.append(f"REPO_NAME=\"{repo_config.get('path', 'Unknown')}\"")
        content.append("JSON_ENTRY=\"{\\\"job\\\": \\\"$JOB_NAME\\\", \\\"repo\\\": \\\"$REPO_NAME\\\", \\\"status\\\": \\\"$JOB_STATUS\\\", \\\"duration\\\": \\\"$DURATION\\\", \\\"start\\\": \\\"$END_TIME\\\", \\\"source\\\": \\\"cron\\\"}\"")
        content.append("echo \"$JSON_ENTRY\" >> \"$HISTORY_FILE\"")

        script_content_str = "\n".join(content)

        if ssh_helper:
            # Remote Write
            # Escape for echo... this can be tricky.
            # Better to use base64 to avoid quoting hell.
            # Assuming remote has base64.
            import base64
            b64_content = base64.b64encode(script_content_str.encode('utf-8')).decode('utf-8')
            
            # Command: echo {b64} | base64 -d > {path}
            cmd = f"echo '{b64_content}' | base64 -d > {script_path}"
            success, _, err = ssh_helper.execute(cmd)
            if not success:
                raise Exception(f"Failed to write remote script: {err}")
            
            # Chmod +x
            ssh_helper.execute(f"chmod +x {script_path}")
            
        else:
            # Local Write
            with open(script_path, 'w') as f:
                f.write(script_content_str)
            
            # Make Executable
            st = os.stat(script_path)
            os.chmod(script_path, st.st_mode | stat.S_IEXEC)
        
        return script_path

    @staticmethod
    def get_installed_cron_lines(ssh_helper=None):
        """Returns list of cron lines managed by this app.
        
        Args:
            ssh_helper: Optional SSHHelper for remote crontab
        """
        try:
            if ssh_helper:
                # Remote crontab via SSH
                success, output, _ = ssh_helper.execute("crontab -l 2>/dev/null || true")
                if not success:
                    return []
                lines = output.strip().splitlines()
            else:
                # Local crontab
                res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                if res.returncode != 0: return []
                lines = res.stdout.strip().splitlines()
            return [line for line in lines if "# BORG_GUI_JOB_" in line]
        except:
            return []

    @staticmethod
    def update_crontab(job_id, script_path, time_str, frequency="Daily", day="", enable=True, ssh_helper=None):
        """Reads crontab, removes old entry for this job, adds new one if enable=True.
        
        Args:
            ssh_helper: Optional SSHHelper for remote crontab
        """
        try:
            if ssh_helper:
                # Remote crontab
                success, output, _ = ssh_helper.execute("crontab -l 2>/dev/null || true")
                current_cron = output.strip().splitlines() if success else []
            else:
                # Local crontab
                res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                current_cron = res.stdout.strip().splitlines() if res.returncode == 0 else []
        except:
            current_cron = []
        
        # Marker to identify this job
        marker = f"# BORG_GUI_JOB_{job_id}"
        
        # Filter out existing lines for this job
        new_cron = [line for line in current_cron if marker not in line and line.strip() != ""]
        
        # Add new line if enabling
        if enable:
            try:
                h, m = time_str.split(":")
                
                cron_dow = "*"
                cron_dom = "*"
                
                if frequency == "Weekly":
                    days_map = {"Sunday": 0, "Monday": 1, "Tuesday": 2, "Wednesday": 3, "Thursday": 4, "Friday": 5, "Saturday": 6}
                    cron_dow = days_map.get(day, "*")
                elif frequency == "Monthly":
                    cron_dom = day if day else "1"

                cron_line = f"{int(m)} {int(h)} {cron_dom} * {cron_dow} {script_path} {marker}"
                new_cron.append(cron_line)
            except ValueError:
                logger.warning("Invalid time format for cron")
                return False

        # Write back
        cron_text = "\n".join(new_cron) + "\n"
        
        if ssh_helper:
            # Remote: echo crontab and pipe to crontab -
            escaped = cron_text.replace("'", "'\"'\"'")
            cmd = f"echo '{escaped}' | crontab -"
            success, _, error = ssh_helper.execute(cmd)
            return success
        else:
            # Local
            proc = subprocess.run(["crontab", "-"], input=cron_text, text=True)
            return proc.returncode == 0

# ==========================================
# HELPER CLASS: INTERACTIVE FILE BROWSER
# ==========================================

class FileSelectorDialog(tk.Toplevel):
    def __init__(self, parent, on_confirm_callback, root_path=None, on_cancel_callback=None, ssh_helper=None):
        super().__init__(parent)
        self.title("Interactive File Selector")
        self.geometry("900x600")
        self.on_confirm = on_confirm_callback
        self.on_cancel = on_cancel_callback
        self.root_path = root_path
        self.ssh_helper = ssh_helper  # NEW: SSH helper for remote browsing
        
        self.includes = set()
        self.excludes = set()

        self._init_ui()
        self._load_root()
        
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _init_ui(self):
        # Instructions
        info_frame = ttk.Frame(self, padding=10)
        info_frame.pack(fill=tk.X)
        msg = "Browse and select folders."
        if self.root_path:
            msg += f" (Browsing: {self.root_path})"
        ttk.Label(info_frame, text=msg).pack(anchor=tk.W)
        ttk.Label(info_frame, text="Green = Included, Red = Excluded").pack(anchor=tk.W)

        # Treeview
        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.tree = ttk.Treeview(tree_frame, columns=("status", "path"), selectmode="browse")
        self.tree.heading("#0", text="File System")
        self.tree.heading("status", text="Status")
        self.tree.heading("path", text="Full Path")
        
        self.tree.column("#0", width=400)
        self.tree.column("status", width=100, anchor="center")
        self.tree.column("path", width=300)
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Bindings
        self.tree.bind("<<TreeviewOpen>>", self._on_open_event)
        # Right click menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Include This", command=self._mark_include)
        self.context_menu.add_command(label="⛔ Exclude This", command=self._mark_exclude)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Clear Selection", command=self._mark_clear)
        
        if platform.system() == "Darwin": # Mac
             self.tree.bind("<Button-2>", self._popup_menu)
        else:
             self.tree.bind("<Button-3>", self._popup_menu)

        # Buttons
        btn_frame = ttk.Frame(self, padding=10)
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(btn_frame, text=f"{icon('confirm')} Include", command=self._mark_include).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=f"{icon('error')} Exclude", command=self._mark_exclude).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=f"{icon('close')} Clear", command=self._mark_clear).pack(side=tk.LEFT, padx=5)

        # Refresh Button
        ttk.Button(btn_frame, text=f"{icon('refresh')} Refresh", command=self._refresh_tree).pack(side=tk.LEFT, padx=20)
        
        ttk.Button(btn_frame, text=f"{icon('confirm')} Confirm", command=self._finish).pack(side=tk.RIGHT, padx=5)

        # Styles for tags
        self.tree.tag_configure("include", foreground="green", background="#e6ffe6")
        self.tree.tag_configure("exclude", foreground="red", background="#ffe6e6")
        self.tree.tag_configure("error", foreground="red")

    def _refresh_tree(self):
        # Clear and reload
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._load_root()

    def _load_root(self):
        if self.root_path:
            # Mode: Inspecting a specific folder
            display_text = os.path.basename(self.root_path)
            if not display_text: display_text = self.root_path
            
            node = self.tree.insert("", "end", text=display_text, values=("", self.root_path), open=True)
            self.tree.insert(node, "end", text="dummy") 
            self._populate_node(node)
        elif self.ssh_helper:
            # Mode: Remote filesystem via SSH
            home = self.ssh_helper.get_home()
            node = self.tree.insert("", "end", text="/", values=("", "/"), open=False)
            self.tree.insert(node, "end", text="dummy")
            
            node_home = self.tree.insert("", "end", text=f"Home ({os.path.basename(home)})", values=("", home), open=False)
            self.tree.insert(node_home, "end", text="dummy")
        else:
            # Mode: Local Filesystem Browsing
            system = platform.system()
            if system == "Windows":
                import string
                from ctypes import windll
                drives = []
                bitmask = windll.kernel32.GetLogicalDrives()
                for letter in string.ascii_uppercase:
                    if bitmask & 1:
                        drives.append(f"{letter}:\\")
                    bitmask >>= 1
                for d in drives:
                    node = self.tree.insert("", "end", text=d, values=("", d), open=False)
                    self.tree.insert(node, "end", text="dummy") 
            else:
                node = self.tree.insert("", "end", text="/", values=("", "/"), open=False)
                self.tree.insert(node, "end", text="dummy")
                
                home = os.path.expanduser("~")
                node_home = self.tree.insert("", "end", text=f"Home ({os.path.basename(home)})", values=("", home), open=False)
                self.tree.insert(node_home, "end", text="dummy")

    def _on_open_event(self, event):
        item_id = self.tree.focus()
        self._populate_node(item_id)

    def _populate_node(self, item_id):
        if not item_id: return
        
        children = self.tree.get_children(item_id)
        is_unloaded = False
        if len(children) == 1 and self.tree.item(children[0], option="text") == "dummy":
            is_unloaded = True
        
        if not is_unloaded and len(children) > 0:
            return 
            
        parent_path = self.tree.item(item_id, option="values")[1]
        
        if is_unloaded:
            self.tree.delete(children[0])

        try:
            if self.ssh_helper:
                # Remote listing via SSH
                items = self.ssh_helper.list_dir(parent_path)
                for name, is_dir in items:
                    if name.startswith("."): 
                        continue
                    full_path = parent_path.rstrip("/") + "/" + name
                    
                    tags = ()
                    status_text = ""
                    if full_path in self.includes:
                        tags = ("include",)
                        status_text = "INCLUDED"
                    elif full_path in self.excludes:
                        tags = ("exclude",)
                        status_text = "EXCLUDED"
                    
                    oid = self.tree.insert(item_id, "end", text=name, values=(status_text, full_path), tags=tags)
                    if is_dir:
                        self.tree.insert(oid, "end", text="dummy")
            else:
                # Local listing
                items = sorted(os.listdir(parent_path))
                for p in items:
                    if p.startswith("."): continue 
                    full_path = os.path.join(parent_path, p)
                    is_dir = os.path.isdir(full_path)
                    
                    tags = ()
                    status_text = ""
                    if full_path in self.includes:
                        tags = ("include",)
                        status_text = "INCLUDED"
                    elif full_path in self.excludes:
                        tags = ("exclude",)
                        status_text = "EXCLUDED"

                    oid = self.tree.insert(item_id, "end", text=p, values=(status_text, full_path), tags=tags)
                    if is_dir:
                        self.tree.insert(oid, "end", text="dummy")
        except Exception as e:
            self.tree.insert(item_id, "end", text=f"Error: {e}", values=("ERROR", ""), tags=("error",)) 

    def _popup_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _get_selected_path(self):
        sel = self.tree.selection()
        if not sel: return None, None
        item = sel[0]
        return item, self.tree.item(item, option="values")[1]

    def _mark_include(self):
        item, path = self._get_selected_path()
        if not path: return
        if path in self.excludes: self.excludes.remove(path)
        self.includes.add(path)
        self.tree.item(item, tags=("include",), values=("INCLUDED", path))

    def _mark_exclude(self):
        item, path = self._get_selected_path()
        if not path: return
        if path in self.includes: self.includes.remove(path)
        self.excludes.add(path)
        self.tree.item(item, tags=("exclude",), values=("EXCLUDED", path))

    def _mark_clear(self):
        item, path = self._get_selected_path()
        if not path: return
        if path in self.includes: self.includes.remove(path)
        if path in self.excludes: self.excludes.remove(path)
        self.tree.item(item, tags=(), values=("", path))

    def _finish(self):
        self.on_confirm(list(self.includes), list(self.excludes))
        self.destroy()

    def _on_close(self):
        if self.on_cancel:
            self.on_cancel()
        self.destroy()


# ==========================================
# MAIN APPLICATION
# ==========================================

class BorgApp(tk.Tk):
    def __init__(self):
        # Set AppUserModelID on Windows BEFORE creating the window
        if platform.system() == "Windows":
            try:
                import ctypes
                myappid = 'borgmanager.gui.v1'
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
            except Exception as e:
                logger.warning(f"Failed to set AppUserModelID: {e}")

        super().__init__()
        self.title("Borg Backup GUI Manager")
        self.geometry("1100x768")
        
        # Set App Icon
        try:
            # Handle PyInstaller path
            if getattr(sys, 'frozen', False):
                script_dir = sys._MEIPASS
            else:
                script_dir = os.path.dirname(os.path.abspath(__file__))

            if platform.system() == "Windows":
                icon_path = os.path.join(script_dir, "borg_manager_icon.ico")
                if os.path.exists(icon_path):
                    self.iconbitmap(default=icon_path)
            else:
                # Linux/Mac - use PIL to load PNG (tk.PhotoImage doesn't handle all PNG formats)
                icon_path = os.path.join(script_dir, "borg_manager_icon.png")
                if os.path.exists(icon_path) and HAS_TRAY:  # HAS_TRAY means PIL is available
                    pil_img = Image.open(icon_path)
                    # Resize for icon (64x64 is common)
                    pil_img = pil_img.resize((64, 64), Image.Resampling.LANCZOS if hasattr(Image, 'Resampling') else Image.LANCZOS)
                    self._app_icon = ImageTk.PhotoImage(pil_img)
                    self.iconphoto(True, self._app_icon)
        except Exception as e:
            logger.warning(f"Failed to set icon: {e}")

            
        self.config_manager = ConfigManager()
        self.log_manager = LogManager(self.config_manager)
        
        # Style with Fira fonts
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Define custom styles with platform-appropriate fonts
        self.style.configure(".", font=(DEFAULT_FONT, 10))
        self.style.configure("TLabel", font=(DEFAULT_FONT, 10))
        self.style.configure("TButton", font=(DEFAULT_FONT, 10))
        self.style.configure("Card.TFrame", relief="ridge", borderwidth=1)
        self.style.configure("CardHeader.TLabel", font=(DEFAULT_FONT, 11, "bold"))
        self.style.configure("BigNumber.TLabel", font=(DEFAULT_FONT, 18, "bold"))
        self.style.configure("SubText.TLabel", font=(DEFAULT_FONT, 9), foreground="#555")
        
        # Variables
        self.current_process = None
        self.is_running = False
        self.icon = None

        # Find binary before UI init
        self.borg_bin = self._find_borg_binary()

        self.job_queue = [] # List of queued jobs
        self.current_theme = self.config_manager.config.get("theme", "light")
        
        # Active source server (tracks which server we're managing)
        self.active_source_id = None
        self.active_ssh_helper = None
        
        # Apply theme to main window BEFORE showing startup dialogs
        self._apply_early_theme()
        
        # First-time welcome check (show before server selection)
        self._check_first_time_user()
        
        # Show startup server selection (must be before main UI)
        if not self._show_startup_server_selection():
            self.destroy()
            return
        
        self._init_ui()
        self.refresh_repo_display()
        
        self.protocol("WM_DELETE_WINDOW", self.on_close_request)

        # Tray and Scheduler Setup
        if HAS_TRAY:
            self._setup_tray_icon()
        else:
            self.after(1000, lambda: self.log("WARNING: System Tray dependencies missing. Use 'Tools > Check Dependencies' to fix.", "ERROR"))
        
        self._start_scheduler()
        self._start_queue_processor()
        self.log("Application Started. Logs initialized at " + self.log_manager.get_today_filename(), "SYSTEM")

        # Startup Dependency Check (delayed to not block UI)
        self.after(500, self._startup_dependency_check)

    def _find_borg_binary(self):
        # On Windows, borg runs on the remote Linux server, not locally
        if platform.system() == "Windows":
            return "borg"  # Placeholder - actual borg runs remotely
        
        cached = self.config_manager.config.get("borg_binary")
        if cached and os.path.exists(cached):
            return cached

        path = shutil.which("borg")
        if path: return path

        common_paths = ["/usr/bin/borg", "/usr/local/bin/borg", "/opt/homebrew/bin/borg"]
        for p in common_paths:
            if os.path.exists(p): return p
        
        messagebox.showwarning("Borg Not Found", "Could not automatically find the 'borg' executable.\nPlease select it manually.")
        selected = filedialog.askopenfilename(title="Locate Borg Executable")
        if selected:
            self.config_manager.set_borg_binary(selected)
            return selected
            
        return "borg"

    def _show_startup_server_selection(self):
        """Show server selection dialog on startup.
        
        Returns:
            bool: True if server selected, False if cancelled
        """
        servers = self.config_manager.get_source_servers()
        is_windows = platform.system() == "Windows"
        
        # Filter out Local on Windows (borg doesn't run on Windows)
        if is_windows:
            servers = {k: v for k, v in servers.items() if k != "__local__"}
        
        # If no servers and on Windows, must add one
        if not servers and is_windows:
            messagebox.showinfo(
                "Welcome",
                "Borg Backup Manager runs on Windows but manages Linux servers remotely.\n\n"
                "Please add a Linux server to manage."
            )
            # Open server manager
            self._startup_add_server()
            servers = self.config_manager.get_source_servers()
            servers = {k: v for k, v in servers.items() if k != "__local__"}
            if not servers:
                return False
        
        # If only one server (or Local on Linux), auto-select
        if len(servers) == 1:
            sid = list(servers.keys())[0]
            self._set_active_source(sid)
            return True
        
        # Show selection dialog
        dialog = tk.Toplevel(self)
        dialog.title("Select Server to Manage")
        dialog.geometry("450x400")
        dialog.transient(self)
        dialog.grab_set()
        
        # Apply theme colors
        bg_color = self.get_theme_color("bg_window")
        bg_card = self.get_theme_color("bg_card")
        fg_color = self.get_theme_color("text_main")
        dialog.configure(bg=bg_color)
        
        result = {"selected": None}
        
        # Use tk.Frame for explicit bg control (ttk doesn't respect bg on all platforms)
        main_frame = tk.Frame(dialog, bg=bg_color, padx=15, pady=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text="Select a server to manage:", font=("", 11, "bold"),
                bg=bg_color, fg=fg_color).pack(pady=(0, 15))
        
        # Server list
        list_frame = tk.Frame(main_frame, bg=bg_color)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        listbox = tk.Listbox(list_frame, height=10, font=("", 10), bg=bg_card, fg=fg_color,
                            selectbackground="#27ae60", selectforeground="white",
                            highlightthickness=1, highlightbackground=bg_card)
        listbox.pack(fill=tk.BOTH, expand=True)
        
        server_map = {}
        for sid, srv in servers.items():
            name = srv.get("name", sid)
            host = srv.get("host") or "(Local)"
            display = f"{name} - {host}"
            listbox.insert(tk.END, display)
            server_map[listbox.size() - 1] = sid
        
        if listbox.size() > 0:
            listbox.selection_set(0)
        
        def on_select():
            sel = listbox.curselection()
            if sel:
                result["selected"] = server_map[sel[0]]
                dialog.destroy()
        
        def on_add_new():
            dialog.destroy()
            self._startup_add_server()
            # Recurse to show selection again
            result["selected"] = "__retry__"
        
        btn_frame = tk.Frame(dialog, bg=bg_color)
        btn_frame.pack(fill=tk.X, pady=20, padx=20)
        
        ttk.Button(btn_frame, text="[>] Connect", command=on_select).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="[+] Add New Server", command=on_add_new).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="[x] Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        dialog.wait_window()
        
        if result["selected"] == "__retry__":
            return self._show_startup_server_selection()
        elif result["selected"]:
            self._set_active_source(result["selected"])
            return True
        else:
            return False
    
    def _startup_add_server(self):
        """Quick add server dialog for startup."""
        dialog = tk.Toplevel(self)
        dialog.title("Add Server")
        dialog.geometry("450x380")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg=self.get_theme_color("bg_window"))

        main = ttk.Frame(dialog, padding=20)
        main.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main, text="Server Name:").pack(anchor=tk.W)
        name_var = tk.StringVar()
        ttk.Entry(main, textvariable=name_var, width=40).pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(main, text="SSH Host (user@hostname):").pack(anchor=tk.W)
        host_var = tk.StringVar()
        ttk.Entry(main, textvariable=host_var, width=40).pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(main, text="SSH Key Path (optional):").pack(anchor=tk.W)
        key_var = tk.StringVar()
        key_frame = ttk.Frame(main)
        key_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Entry(key_frame, textvariable=key_var, width=30).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(key_frame, text=f"{icon('open')} Browse", command=lambda: key_var.set(filedialog.askopenfilename())).pack(side=tk.RIGHT)
        
        # Status label for SSH key setup
        status_var = tk.StringVar()
        status_lbl = ttk.Label(main, textvariable=status_var, foreground="blue")
        status_lbl.pack(anchor=tk.W, pady=5)
        
        def setup_ssh_key():
            host = host_var.get().strip()
            if not host:
                messagebox.showerror("Error", "Enter SSH Host first.")
                return
            
            # Find local public key
            pubkey_paths = [
                os.path.expanduser("~/.ssh/id_rsa.pub"),
                os.path.expanduser("~/.ssh/id_ed25519.pub"),
                os.path.expanduser("~/.ssh/id_ecdsa.pub")
            ]
            pubkey = None
            for p in pubkey_paths:
                if os.path.exists(p):
                    with open(p, 'r') as f:
                        pubkey = f.read().strip()
                    break
            
            if not pubkey:
                # Generate new key
                if messagebox.askyesno("No SSH Key", "No SSH key found. Generate one?"):
                    try:
                        key_path = os.path.expanduser("~/.ssh/id_rsa")
                        subprocess.run(["ssh-keygen", "-t", "rsa", "-N", "", "-f", key_path], check=True)
                        with open(key_path + ".pub", 'r') as f:
                            pubkey = f.read().strip()
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to generate key: {e}")
                        return
                else:
                    return
            
            # Copy to server - use paramiko with dialog password (no terminal)
            status_var.set("Copying SSH key to server...")
            dialog.update()
            
            try:
                # Parse user@host format
                if "@" in host:
                    ssh_user, ssh_host = host.split("@", 1)
                else:
                    ssh_user = os.getenv("USER", "root")
                    ssh_host = host
                
                # Handle port if specified (user@host:port)
                ssh_port = 22
                if ":" in ssh_host:
                    ssh_host, port_str = ssh_host.rsplit(":", 1)
                    try:
                        ssh_port = int(port_str)
                    except ValueError:
                        pass
                
                # Ask for password via dialog
                password = simpledialog.askstring(
                    "SSH Password",
                    f"Enter password for {ssh_user}@{ssh_host}:",
                    show='*',
                    parent=dialog
                )
                
                if not password:
                    status_var.set("❌ Password not provided")
                    return
                
                if HAS_PARAMIKO:
                    # Use paramiko for cross-platform SSH
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    try:
                        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=password, timeout=30)
                        
                        # Create .ssh dir and add key
                        cmd = f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '{pubkey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
                        stdin, stdout, stderr = ssh.exec_command(cmd)
                        exit_status = stdout.channel.recv_exit_status()
                        
                        if exit_status == 0:
                            status_var.set("✅ SSH key copied successfully!")
                            messagebox.showinfo("Success", "SSH key has been copied to the server.\nYou can now connect without a password.")
                        else:
                            error_msg = stderr.read().decode()
                            status_var.set("❌ Failed to copy key")
                            messagebox.showerror("Error", f"Failed: {error_msg}")
                        
                        ssh.close()
                    except paramiko.AuthenticationException:
                        status_var.set("❌ Authentication failed")
                        messagebox.showerror("Error", "Authentication failed. Check username and password.")
                    except Exception as e:
                        status_var.set(f"❌ Connection error")
                        messagebox.showerror("Error", f"Connection error: {e}")
                else:
                    # Fallback: try sshpass if available (Linux)
                    if shutil.which("sshpass"):
                        cmd = f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '{pubkey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
                        result = subprocess.run(
                            ["sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=accept-new", 
                             "-p", str(ssh_port), f"{ssh_user}@{ssh_host}", cmd],
                            capture_output=True, text=True, timeout=60
                        )
                        if result.returncode == 0:
                            status_var.set("✅ SSH key copied successfully!")
                            messagebox.showinfo("Success", "SSH key has been copied to the server.")
                        else:
                            status_var.set("❌ Failed")
                            messagebox.showerror("Error", f"Failed: {result.stderr}")
                    else:
                        status_var.set("❌ Paramiko not available")
                        messagebox.showerror("Error", "SSH key copy requires paramiko library.\nInstall with: pip install paramiko")
            except Exception as e:
                status_var.set(f"❌ Error: {e}")
                messagebox.showerror("Error", str(e))
        
        ttk.Button(main, text=f"{icon('key')} Setup SSH Key (Workstation -> Server)", command=setup_ssh_key).pack(pady=10)
        
        def save():
            name = name_var.get().strip()
            host = host_var.get().strip()
            if not name or not host:
                messagebox.showerror("Error", "Name and Host are required.")
                return
            
            sid = re.sub(r'[^a-zA-Z0-9]', '_', name.lower())
            ssh_key = key_var.get().strip() or None
            self.config_manager.add_source_server(sid, name, host, ssh_key, [])
            dialog.destroy()
        
        ttk.Button(main, text="💾 Save Server", command=save).pack(pady=10)
        
        dialog.wait_window()
    
    def _set_active_source(self, source_id):
        """Set the active source server and create SSH helper."""
        self.active_source_id = source_id
        self.config_manager.set_active_source(source_id)  # Sync with ConfigManager
        srv = self.config_manager.get_source_server(source_id)
        
        if srv and srv.get("host"):
            self.active_ssh_helper = SSHHelper(
                host=srv["host"],
                ssh_key=srv.get("ssh_key"),
                password=None
            )
            self.title(f"Borg Manager - {srv.get('name', source_id)}")
        else:
            self.active_ssh_helper = None
            self.title("Borg Manager - Local")
        
        # Show repo selection dialog
        self._show_repo_selection()
    
    def _show_repo_selection(self):
        """Show dialog to select active repository for current source."""
        srv = self.config_manager.get_source_server(self.active_source_id)
        if not srv:
            return
        
        # Repos are now stored directly as dict under source server
        available_repos = srv.get("repos", {})
        
        if not available_repos:
            # No repos configured - show custom themed dialog
            source_name = srv.get('name', self.active_source_id)
            
            dialog = tk.Toplevel(self)
            dialog.title("No Repositories")
            dialog.geometry("420x220")
            dialog.transient(self)
            dialog.grab_set()
            
            bg = self.get_theme_color("bg_window")
            fg = self.get_theme_color("text_main")
            dialog.configure(bg=bg)
            
            main = tk.Frame(dialog, bg=bg, padx=25, pady=20)
            main.pack(fill=tk.BOTH, expand=True)
            
            tk.Label(main, text="📦 No Repositories", font=(DEFAULT_FONT, 14, "bold"),
                    bg=bg, fg=fg).pack(pady=(0, 15))
            
            msg = f"No repositories configured for {source_name}.\n\nWould you like to add a repository now?"
            tk.Label(main, text=msg, font=(DEFAULT_FONT, 10), justify=tk.CENTER,
                    bg=bg, fg=fg).pack(pady=10)
            
            def on_yes():
                dialog.destroy()
                self.open_repo_manager()
            
            def on_no():
                dialog.destroy()
            
            btn_frame = tk.Frame(main, bg=bg)
            btn_frame.pack(pady=15)
            
            btn_yes = tk.Button(btn_frame, text="Yes, Add Repository", command=on_yes,
                               bg="#3498db", fg="white", font=(DEFAULT_FONT, 10),
                               padx=15, pady=5, relief=tk.FLAT, cursor="hand2")
            btn_yes.pack(side=tk.LEFT, padx=10)
            
            btn_no = tk.Button(btn_frame, text="No, Later", command=on_no,
                              bg="#95a5a6", fg="white", font=(DEFAULT_FONT, 10),
                              padx=15, pady=5, relief=tk.FLAT, cursor="hand2")
            btn_no.pack(side=tk.LEFT, padx=10)
            
            dialog.wait_window()
            return
        
        if len(available_repos) == 1:
            # Auto-select if only one repo
            repo_name = list(available_repos.keys())[0]
            self.config_manager.config["current_repo"] = repo_name
            self.config_manager.save_config()
            return
        
        # Show selection dialog
        dialog = tk.Toplevel(self)
        dialog.title("Select Repository")
        dialog.geometry("400x300")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg=self.get_theme_color("bg_window"))
        
        main = ttk.Frame(dialog, padding=20)
        main.pack(fill=tk.BOTH, expand=True)
        
        source_name = srv.get("name", self.active_source_id)
        ttk.Label(main, text=f"Active Source: {source_name}", 
                 font=("", 11, "bold"), foreground="blue").pack(pady=(0, 10))
        
        ttk.Label(main, text="Select repository to manage:").pack(anchor=tk.W, pady=(0, 5))
        
        listbox = tk.Listbox(main, font=("", 10), height=8,
                            bg=self.get_theme_color("bg_card"),
                            fg=self.get_theme_color("text_main"))
        listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        for name in available_repos.keys():
            listbox.insert(tk.END, name)
        
        if listbox.size() > 0:
            listbox.selection_set(0)
        
        def select():
            sel = listbox.curselection()
            if sel:
                repo_name = listbox.get(sel[0])
                self.config_manager.config["current_repo"] = repo_name
                self.config_manager.save_config()
                dialog.destroy()
        
        def on_double_click(event):
            select()
        
        listbox.bind("<Double-1>", on_double_click)
        
        ttk.Button(main, text=f"{icon('confirm')} Select", command=select).pack(pady=10)
        
        dialog.wait_window()

    def _apply_early_theme(self):
        """Apply minimal theme to main window before startup dialogs."""
        bg = self.get_theme_color("bg_window")
        fg = self.get_theme_color("text_main")
        bg_card = self.get_theme_color("bg_card")
        
        # Set main window background
        self.configure(bg=bg)
        
        # Apply TTK styles needed for startup dialogs
        style = ttk.Style()
        style.configure(".", background=bg, foreground=fg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TFrame", background=bg)
        
        # Dark themed buttons
        if self.current_theme == "dark":
            style.configure("TButton", background="#424242", foreground="#ffffff")
            style.map("TButton",
                background=[('active', '#616161'), ('pressed', '#303030')],
                foreground=[('active', '#ffffff')]
            )
        else:
            style.configure("TButton", background="#e0e0e0", foreground="#212121")
            style.map("TButton",
                background=[('active', '#bdbdbd'), ('pressed', '#9e9e9e')],
                foreground=[('active', '#212121')]
            )

    def _apply_theme_style(self):
        """Apply global styles based on current theme."""
        bg = self.get_theme_color("bg_window")
        fg = self.get_theme_color("text_main")
        bg_card = self.get_theme_color("bg_card")
        
        # Tk Root
        self.configure(bg=bg)
        
        # TTK Styles
        style = ttk.Style()
        style.configure(".", background=bg, foreground=fg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TButton", background=bg, foreground=fg)
        style.map("TButton",
            foreground=[('active', fg), ('disabled', 'gray')],
            background=[('active', bg_card), ('pressed', bg)]
        )
        style.configure("TFrame", background=bg)
        # Entry & Combobox Style
        entry_bg = bg_card if self.current_theme == "dark" else "#ffffff"
        style.configure("TEntry", fieldbackground=entry_bg, foreground=fg)
        style.configure("TCombobox", fieldbackground=entry_bg, foreground=fg, background=bg)
        style.map("TCombobox", fieldbackground=[("readonly", entry_bg)], selectbackground=[("readonly", entry_bg)])
        style.configure("TLabelframe", background=bg, foreground=fg)
        style.configure("TLabelframe.Label", background=bg, foreground=fg)
        style.configure("TNotebook", background=bg)
        style.configure("TNotebook.Tab", background=bg, foreground=fg, padding=[10, 2])
        style.map("TNotebook.Tab", background=[("selected", bg_card)], foreground=[("selected", fg)])
        
        # Treeview
        tree_bg = "#ffffff" if self.current_theme == "light" else "#424242"
        style.configure("Treeview", background=tree_bg, fieldbackground=tree_bg, foreground=fg)
        style.configure("Treeview.Heading", background=bg_card, foreground=fg)
        style.map("Treeview", background=[("selected", self.get_theme_color("stat_orig"))])

    def _init_ui(self):
        self._apply_theme_style()  # Apply colors first
        
        # --- Menu Bar ---
        # Get theme colors for menu
        menu_bg = self.get_theme_color("bg_card")
        menu_fg = self.get_theme_color("text_main")
        menu_font = (DEFAULT_FONT, 10)
        
        self.menubar = tk.Menu(self, bg=menu_bg, fg=menu_fg, font=menu_font,
                              activebackground="#27ae60", activeforeground="white")
        self.config(menu=self.menubar)
        
        file_menu = tk.Menu(self.menubar, tearoff=0, bg=menu_bg, fg=menu_fg, font=menu_font, activebackground="#27ae60", activeforeground="white")
        file_menu.add_command(label="Exit", command=self.on_close_request)
        self.menubar.add_cascade(label="File", menu=file_menu)
        
        tools_menu = tk.Menu(self.menubar, tearoff=0, bg=menu_bg, fg=menu_fg, font=menu_font, activebackground="#27ae60", activeforeground="white")
        tools_menu.add_command(label="Check Dependencies / Install", command=self.open_dependency_manager)
        tools_menu.add_command(label="Manage System Cron", command=self.open_cron_manager)
        tools_menu.add_command(label="Toggle Dark/Light Mode", command=self.toggle_theme)
        tools_menu.add_separator()
        tools_menu.add_command(label="Manage Source Servers", command=self.open_source_server_manager)
        tools_menu.add_command(label="Manage Repos", command=self.open_repo_manager)
        self.menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help Menu
        help_menu = tk.Menu(self.menubar, tearoff=0, bg=menu_bg, fg=menu_fg, font=menu_font, activebackground="#27ae60", activeforeground="white")
        help_menu.add_command(label="Quick Start Guide", command=self._show_quick_start)
        help_menu.add_command(label="Keyboard Shortcuts", command=self._show_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self._show_about)
        self.menubar.add_cascade(label="Help", menu=help_menu)

        # --- Top Bar (Active Source & Repo) ---
        top_frame = ttk.Frame(self, padding=10)
        top_frame.pack(fill=tk.X)

        ttk.Label(top_frame, text="Source:").pack(side=tk.LEFT)
        self.source_label = ttk.Label(top_frame, text="None", foreground="#27ae60", font=("", 10, "bold"))
        self.source_label.pack(side=tk.LEFT, padx=(5, 15))
        
        ttk.Label(top_frame, text="Repo:").pack(side=tk.LEFT)
        self.repo_label = ttk.Label(top_frame, text="None", foreground="#8e44ad")
        self.repo_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(top_frame, text="[>] Manage Repos", command=self.open_repo_manager).pack(side=tk.RIGHT)

        # --- Main Layout: Side Panel + Content ---
        main_container = ttk.Frame(self)
        main_container.pack(fill=tk.BOTH, expand=True, padx=0, pady=0) # Removed padding for continuous look
        
        # Determine theme colors
        is_dark = self.current_theme == "dark"
        bg_sidebar = "#202020" if is_dark else "#f0f0f0"
        bg_content = self.get_theme_color("bg_window")
        fg_text = "#e0e0e0" if is_dark else "#333333"
        sep_color = "#333333" if is_dark else "#d0d0d0"
        
        # Left: Sidebar with tab buttons
        self.sidebar = tk.Frame(main_container, bg=bg_sidebar, width=160) # Slightly wider
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)
        
        # Vertical Separator Line
        separator = tk.Frame(main_container, bg=sep_color, width=1)
        separator.pack(side=tk.LEFT, fill=tk.Y)
        
        # Right: Content area
        # Use a container frame first to manage background
        content_wrapper = tk.Frame(main_container, bg=bg_content)
        content_wrapper.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Content area frame (ttk handles theme bg mostly, but we want control)
        self.content_area = ttk.Frame(content_wrapper, style="Card.TFrame") # Match card bg for seamlessness
        self.content_area.pack(fill=tk.BOTH, expand=True, padx=15, pady=15) # Inner padding for content
        
        # Create content frames (replaces notebook tabs)
        self.tab_dashboard = ttk.Frame(self.content_area)
        self.tab_archives = ttk.Frame(self.content_area)
        self.tab_mounts = ttk.Frame(self.content_area)
        self.tab_backup = ttk.Frame(self.content_area)
        self.tab_schedule = ttk.Frame(self.content_area)
        self.tab_maintenance = ttk.Frame(self.content_area)
        self.tab_logs = ttk.Frame(self.content_area)
        self.tab_queue = ttk.Frame(self.content_area)
        self.tab_charts = ttk.Frame(self.content_area)
        
        # Store all tabs for switching
        self.all_tabs = {
            "dashboard": self.tab_dashboard,
            "archives": self.tab_archives,
            "mounts": self.tab_mounts,
            "backup": self.tab_backup,
            "schedule": self.tab_schedule,
            "queue": self.tab_queue,
            "charts": self.tab_charts,
            "maintenance": self.tab_maintenance,
            "logs": self.tab_logs,
        }
        
        # Tab button definitions (icon, label, tab_key) - Removed individual colors
        tab_defs = [
            ("status", "Dashboard", "dashboard"),
            ("archive", "Archives", "archives"),
            ("mount", "Mounts", "mounts"),
            ("add", "New Backup", "backup"),
            ("schedule", "Scheduler", "schedule"),
            ("queue", "Queue", "queue"),
            ("chart", "Charts", "charts"),
            ("prune", "Maintenance", "maintenance"),
            ("log", "Logs", "logs"),
        ]
        
        # Add chart/queue icon checks (kept from previous)
        if "chart" not in ICONS: ICONS["chart"] = ("📊", "[C]")
        if "queue" not in ICONS: ICONS["queue"] = ("📋", "[Q]")
        
        # Create sidebar buttons with custom styling
        self.sidebar_buttons = {}
        
        # Header/spacer in sidebar
        tk.Label(self.sidebar, text=" ", bg=bg_sidebar, font=("", 4)).pack()
        
        for icon_name, label, tab_key in tab_defs:
            # Button Container (for accent bar)
            btn_frame = tk.Frame(self.sidebar, bg=bg_sidebar, height=40)
            btn_frame.pack(fill=tk.X, pady=0)
            btn_frame.pack_propagate(False)
            
            # Accent bar (left indicator)
            accent = tk.Label(btn_frame, bg=bg_sidebar, width=1) # Hidden by default (same color as bg)
            accent.pack(side=tk.LEFT, fill=tk.Y)
            
            # Main Button
            btn = tk.Button(
                btn_frame,
                text=f"  {icon(icon_name)}  {label}",
                anchor="w",
                padx=10,
                bd=0,
                bg=bg_sidebar,
                fg=fg_text,
                activebackground=bg_sidebar, # No flash, we handle state
                activeforeground=fg_text,
                relief=tk.FLAT,
                font=("Segoe UI", 10), # Professional font
                cursor="hand2",
                command=lambda tk=tab_key: self._switch_tab(tk)
            )
            btn.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            # Store references to widgets we need to update
            self.sidebar_buttons[tab_key] = {
                "frame": btn_frame,
                "accent": accent,
                "btn": btn
            }
        
        # Notebook compatibility
        self.notebook = self 
        self.current_tab = "dashboard"
        
        # Show dashboard by default
        self._switch_tab("dashboard")
        
        # Build all tabs
        self._build_dashboard_tab()
        self._build_archives_tab()
        self._build_mounts_tab()
        self._build_backup_tab()
        self._build_schedule_tab()
        self._build_queue_tab()
        self._build_charts_tab()
        self._build_maintenance_tab()
        self._build_logs_tab()

    def _switch_tab(self, tab_key):
        """Switch to the specified tab by key."""
        # Hide all tabs
        for key, frame in self.all_tabs.items():
            frame.pack_forget()
        
        # Show selected tab
        if tab_key in self.all_tabs:
            self.all_tabs[tab_key].pack(fill=tk.BOTH, expand=True)
            self.current_tab = tab_key
            
            # Theme colors
            is_dark = self.current_theme == "dark"
            bg_sidebar = "#202020" if is_dark else "#f0f0f0"
            bg_active = self.get_theme_color("bg_window") # Match content area
            fg_text = "#e0e0e0" if is_dark else "#333333"
            accent_color = "#0078d7" # Professional Blue
            
            # Update button highlighting
            for key, widgets in self.sidebar_buttons.items():
                frame = widgets["frame"]
                accent = widgets["accent"]
                btn = widgets["btn"]
                
                if key == tab_key:
                    # Active State
                    frame.config(bg=bg_active)
                    btn.config(bg=bg_active, font=("Segoe UI", 10, "bold"))
                    accent.config(bg=accent_color, width=4) # Show accent bar
                else:
                    # Inactive State
                    frame.config(bg=bg_sidebar)
                    btn.config(bg=bg_sidebar, font=("Segoe UI", 10))
                    accent.config(bg=bg_sidebar, width=1) # Hide accent bar
            
            # Trigger refresh for specific tabs
            if tab_key == "dashboard":
                self.run_info()
            elif tab_key == "archives":
                self.refresh_archives()
            elif tab_key == "mounts":
                self.refresh_mounts()
            elif tab_key == "queue":
                self._refresh_queue_ui()
            elif tab_key == "charts":
                self._refresh_charts()

    def select(self, tab_frame=None):
        """Compatibility method for notebook.select() - finds and switches to the tab."""
        if tab_frame is None:
            # Getter mode: return current tab widget name (str)
            if self.current_tab in self.all_tabs:
                return str(self.all_tabs[self.current_tab])
            return ""
            
        # Setter mode: switch to tab
        for key, frame in self.all_tabs.items():
            if frame == tab_frame or str(frame) == str(tab_frame):
                self._switch_tab(key)
                return
        # If passed a string key directly
        if isinstance(tab_frame, str) and tab_frame in self.all_tabs:
            self._switch_tab(tab_frame)

    # --- STARTUP CHECKS ---

    def _startup_dependency_check(self):
        """Checks if critical dependencies are missing and opens the manager if so."""
        missing = []
        is_windows = platform.system() == "Windows"
        
        # 1. Check Binaries (skip borg/sshpass on Windows - they run on remote Linux server)
        if not is_windows:
            if not shutil.which("borg"): missing.append("borg")
            if not shutil.which("sshpass"): missing.append("sshpass")
        
        # SSH is needed on all platforms
        if not shutil.which("ssh"): missing.append("ssh") 

        # 2. Check Python Libs
        if not importlib.util.find_spec("pystray"): missing.append("pystray")
        if not importlib.util.find_spec("PIL"): missing.append("Pillow")

        # 3. Check System Libs (Linux)
        if platform.system() == "Linux":
            try:
                import gi
                try:
                    gi.require_version('AppIndicator3', '0.1')
                except (ValueError, ImportError):
                    try:
                        gi.require_version('AyatanaAppIndicator3', '0.1')
                    except (ValueError, ImportError):
                        missing.append("AppIndicator3")
            except ImportError:
                 missing.append("python3-gi")

        if missing:
            self.log(f"Missing dependencies detected on startup: {', '.join(missing)}", "ERROR")
            messagebox.showwarning("Missing Dependencies", f"The following components are missing:\n{', '.join(missing)}\n\nPlease install them in the next window.")
            self.open_dependency_manager()
    
    def _check_first_time_user(self):
        """Show welcome dialog if no source servers are configured (beyond __local__)."""
        source_servers = self.config_manager.get_source_servers()
        real_servers = [k for k in source_servers.keys() if k != "__local__"]
        
        if not real_servers:
            # Use custom dialog for consistent theming
            dialog = tk.Toplevel(self)
            dialog.title("Welcome to Borg Backup Manager")
            dialog.geometry("450x300")
            dialog.transient(self)
            dialog.grab_set()
            
            bg = self.get_theme_color("bg_window")
            fg = self.get_theme_color("text_main")
            dialog.configure(bg=bg)
            
            main = tk.Frame(dialog, bg=bg, padx=25, pady=20)
            main.pack(fill=tk.BOTH, expand=True)
            
            tk.Label(main, text="🗄️ Welcome!", font=(DEFAULT_FONT, 16, "bold"),
                    bg=bg, fg=fg).pack(pady=(0, 15))
            
            msg = ("It looks like this is your first time using the app.\n\n"
                   "To get started, you'll need to add a SOURCE SERVER.\n"
                   "This is the Linux machine whose files you want to backup.\n\n"
                   "After adding a source server, you can configure\n"
                   "repositories and schedule backups from that server.")
            
            tk.Label(main, text=msg, font=(DEFAULT_FONT, 10), justify=tk.LEFT,
                    bg=bg, fg=fg).pack(pady=10)
            
            def on_yes():
                dialog.destroy()
                self._startup_add_server()
            
            def on_no():
                dialog.destroy()
            
            btn_frame = tk.Frame(main, bg=bg)
            btn_frame.pack(pady=15)
            
            # Use tk.Button (not ttk) to avoid underscore mnemonic display issue
            btn_yes = tk.Button(btn_frame, text="Yes, Add Server", command=on_yes,
                               bg="#3498db", fg="white", font=(DEFAULT_FONT, 10),
                               padx=15, pady=5, relief=tk.FLAT, cursor="hand2")
            btn_yes.pack(side=tk.LEFT, padx=10)
            
            btn_no = tk.Button(btn_frame, text="No, Later", command=on_no,
                              bg="#95a5a6", fg="white", font=(DEFAULT_FONT, 10),
                              padx=15, pady=5, relief=tk.FLAT, cursor="hand2")
            btn_no.pack(side=tk.LEFT, padx=10)
            
            dialog.wait_window()
    
    def _show_quick_start(self):
        """Show quick start guide dialog."""
        guide = """QUICK START GUIDE
================

1. ADD A REPOSITORY
   Go to Tools > Manage Repos or click [>] Manage Repos
   - For local: /path/to/backup/folder
   - For remote: ssh://user@hostname/path

2. CREATE YOUR FIRST BACKUP
   - Go to "New Backup" tab
   - Add folders to include using [+] Add
   - Click [*] START BACKUP

3. SCHEDULE AUTOMATIC BACKUPS
   - Go to "Scheduler" tab
   - Click [+] New Job
   - Set time and frequency
   - Enable "Internal Timer" or "System Cron"

4. RESTORE FILES
   - Go to "Archives" tab
   - Select an archive
   - Click [>] Mount
   - Browse files in the mounted folder

TIPS:
- Use Prune to clean old backups
- Check Logs for any errors
- System Cron runs even when app is closed"""
        
        win = tk.Toplevel(self)
        win.title("Quick Start Guide")
        win.configure(bg=self.get_theme_color("bg_window"))
        win.geometry("500x500")
        
        bg_card = self.get_theme_color("bg_card")
        fg_text = self.get_theme_color("text_main")
        
        text = tk.Text(win, wrap=tk.WORD, padx=10, pady=10, bg=bg_card, fg=fg_text, relief="flat")
        text.insert("1.0", guide)
        text.config(state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Button(win, text=f"{icon('close')} Close", command=win.destroy).pack(pady=10)
    
    def _show_shortcuts(self):
        """Show keyboard shortcuts dialog with professional styling."""
        dialog = tk.Toplevel(self)
        dialog.title("⌨️ Keyboard Shortcuts")
        dialog.geometry("450x400")
        dialog.transient(self)
        dialog.grab_set()
        
        bg = self.get_theme_color("bg_window")
        fg = self.get_theme_color("text_main")
        card_bg = self.get_theme_color("bg_card")
        dialog.configure(bg=bg)
        
        main = tk.Frame(dialog, bg=bg, padx=20, pady=15)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Header
        tk.Label(main, text="⌨️ Keyboard Shortcuts", font=(DEFAULT_FONT, 14, "bold"),
                bg=bg, fg=fg).pack(pady=(0, 15))
        
        # Create shortcut sections
        shortcuts = [
            ("🔄 General", [
                ("Ctrl+R", "Refresh current view"),
                ("Ctrl+Q", "Quit application"),
                ("Ctrl+N", "New backup"),
                ("Ctrl+S", "Save (in scheduler)"),
            ]),
            ("📁 Navigation", [
                ("Ctrl+M", "Manage repositories"),
                ("1-7", "Switch to tab by number"),
            ]),
        ]
        
        for section, items in shortcuts:
            section_frame = tk.LabelFrame(main, text=section, font=(DEFAULT_FONT, 10, "bold"),
                                         bg=card_bg, fg=fg, padx=10, pady=8)
            section_frame.pack(fill=tk.X, pady=5)
            
            for key, desc in items:
                row = tk.Frame(section_frame, bg=card_bg)
                row.pack(fill=tk.X, pady=2)
                tk.Label(row, text=key, font=(DEFAULT_FONT, 10, "bold"), width=10, anchor="w",
                        bg=card_bg, fg="#27ae60").pack(side=tk.LEFT)
                tk.Label(row, text=desc, font=(DEFAULT_FONT, 10), anchor="w",
                        bg=card_bg, fg=fg).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(main, text=f"{icon('ok')} OK", command=dialog.destroy).pack(pady=15)
    
    def _show_about(self):
        """Show about dialog with professional styling."""
        dialog = tk.Toplevel(self)
        dialog.title("ℹ️ About Borg Manager")
        dialog.geometry("400x350")
        dialog.transient(self)
        dialog.grab_set()
        
        bg = self.get_theme_color("bg_window")
        fg = self.get_theme_color("text_main")
        dialog.configure(bg=bg)
        
        main = tk.Frame(dialog, bg=bg, padx=25, pady=20)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Logo/Title
        tk.Label(main, text="🗄️", font=("", 48), bg=bg).pack()
        tk.Label(main, text="Borg Backup Manager", font=(DEFAULT_FONT, 16, "bold"),
                bg=bg, fg=fg).pack(pady=5)
        tk.Label(main, text="Version 2.0 - Remote-First Edition", font=(DEFAULT_FONT, 10),
                bg=bg, fg="#888").pack()
        
        tk.Label(main, text="─" * 30, bg=bg, fg="#555").pack(pady=10)
        
        features = [
            "🔐 SSH Remote Management",
            "📅 Scheduled Backups (Cron + Internal)",  
            "📂 Archive Browsing & Mounting",
            "🔧 Maintenance & Pruning",
            "📊 Charts & Analytics",
        ]
        
        for f in features:
            tk.Label(main, text=f, font=(DEFAULT_FONT, 10), bg=bg, fg=fg, anchor="w").pack(anchor="w", pady=1)
        
        tk.Label(main, text="─" * 30, bg=bg, fg="#555").pack(pady=10)
        
        link = tk.Label(main, text="🌐 borgbackup.readthedocs.io", font=(DEFAULT_FONT, 10, "underline"),
                       bg=bg, fg="#3498db", cursor="hand2")
        link.pack()
        
        ttk.Button(main, text=f"{icon('ok')} Close", command=dialog.destroy).pack(pady=15)

    # --- CLOSE & TRAY LOGIC ---

    def on_close_request(self):
        if not HAS_TRAY:
            if messagebox.askyesno("Quit", "Quit Application?\n\nWarning: Internal scheduled backups will STOP.\nCron backups will continue running."):
                self.quit_app()
            return

        dialog = tk.Toplevel(self)
        dialog.title("Close Application")
        dialog.configure(bg=self.get_theme_color("bg_window"))
        dialog.geometry("460x220")
        dialog.resizable(False, False)
        dialog.grab_set()
        
        x = self.winfo_x() + (self.winfo_width() // 2) - 240
        y = self.winfo_y() + (self.winfo_height() // 2) - 100
        dialog.geometry(f"+{x}+{y}")

        # Wrapper to ensure theme consistency
        wrapper = ttk.Frame(dialog, padding=25)
        wrapper.pack(fill=tk.BOTH, expand=True)

        ttk.Label(wrapper, text="How would you like to close?", font=("", 12, "bold")).pack(pady=(0, 12))
        ttk.Label(wrapper, text="Internal scheduler needs App/Tray to run.\nCron jobs run independently.", justify="center").pack(pady=8)

        btn_frame = ttk.Frame(wrapper)
        btn_frame.pack(pady=20)

        def on_tray():
            dialog.destroy()
            self.hide_to_tray()

        def on_quit():
            dialog.destroy()
            self.quit_app()

        ttk.Button(btn_frame, text=f"{icon('confirm')} Minimize to Tray", command=on_tray).pack(side=tk.LEFT, padx=10, ipady=8)
        ttk.Button(btn_frame, text=f"{icon('close')} Quit Completely", command=on_quit).pack(side=tk.LEFT, padx=10, ipady=8)

    # --- TRAY IMPLEMENTATION (RESTORED) ---
    
    def _setup_tray_icon(self):
        # Create a backup-themed icon programmatically
        w, h = 64, 64
        image = Image.new('RGB', (w, h), color=(41, 128, 185))  # Blue background
        draw = ImageDraw.Draw(image)
        
        # Cloud shape (white)
        draw.ellipse([12, 24, 32, 44], fill=(255, 255, 255))  # Left bump
        draw.ellipse([24, 20, 48, 44], fill=(255, 255, 255))  # Center bump
        draw.ellipse([36, 26, 52, 42], fill=(255, 255, 255))  # Right bump
        draw.rectangle([15, 34, 50, 44], fill=(255, 255, 255))  # Base
        
        # Arrow pointing up (green for backup)
        draw.polygon([
            (32, 12),   # Arrow tip (top)
            (24, 24),   # Left wing
            (28, 24),   # Left inner
            (28, 32),   # Left bottom
            (36, 32),   # Right bottom
            (36, 24),   # Right inner
            (40, 24),   # Right wing
        ], fill=(46, 204, 113))  # Green
        
        # Create menu (will be updated periodically)
        menu = pystray.Menu(
            pystray.MenuItem("Show Manager", self.show_window_from_tray),
            pystray.MenuItem("Run All Jobs Now", self.force_run_schedule),
            pystray.MenuItem("Quit", self.quit_app)
        )
        
        self.icon = pystray.Icon("BorgBackup", image, "Borg Backup Manager", menu)
        threading.Thread(target=self.icon.run, daemon=True).start()
        
        # Start a timer to update systray tooltip with next run
        self._update_tray_status()

    def hide_to_tray(self):
        self.withdraw()
        if not HAS_TRAY:
            messagebox.showinfo("Background", "App is running in background. No System Tray support.\nGo to 'Tools > Check Dependencies' to fix.")
    
    def _get_next_run_text(self):
        """Get text showing next scheduled job for systray menu."""
        jobs = self.config_manager.config.get("jobs", {})
        now = datetime.datetime.now()
        next_job = None
        min_minutes = float('inf')
        
        for job_id, job in jobs.items():
            if not job.get("internal_enabled", False):
                continue
            try:
                # Parse multiple times
                raw_time = str(job.get("time", "00:00"))
                time_slots = [t.strip() for t in raw_time.split(',') if t.strip()]
                
                for t_str in time_slots:
                    try:
                        h, m = map(int, t_str.split(":"))
                        # Calculate minutes until this job runs today
                        job_time = now.replace(hour=h, minute=m, second=0)
                        if job_time < now:
                            job_time += datetime.timedelta(days=1)
                        diff = (job_time - now).total_seconds() / 60
                        if diff < min_minutes:
                            min_minutes = diff
                            next_job = job
                    except:
                        continue
            except:
                continue
        
        if next_job:
            if min_minutes < 60:
                return f"Next: {next_job['name']} in {int(min_minutes)}m"
            else:
                hours = int(min_minutes / 60)
                return f"Next: {next_job['name']} in {hours}h"
        return "No jobs scheduled"
    
    def _update_tray_status(self):
        """Update systray tooltip with status."""
        if not HAS_TRAY or not self.icon:
            return
        
        if self.is_running:
            self.icon.title = "Borg Backup - Running..."
            status_text = "Backup Running..."
        else:
            next_text = self._get_next_run_text()
            self.icon.title = f"Borg Backup - {next_text}"
            status_text = next_text
            
        # Update Menu with dynamic status
        self.icon.menu = pystray.Menu(
            pystray.MenuItem("Show Manager", self.show_window_from_tray),
            pystray.MenuItem(status_text, None, enabled=False),
            pystray.MenuItem("Run All Jobs Now", self.force_run_schedule),
            pystray.MenuItem("Quit", self.quit_app)
        )
    
        # Update again in 60 seconds
        self.after(60000, self._update_tray_status)

    def show_window_from_tray(self, icon=None, item=None):
        self.after(0, self.deiconify)

    def quit_app(self, icon=None, item=None):
        if self.icon:
            self.icon.stop()
        self.quit()
        sys.exit()

    def force_run_schedule(self, icon=None, item=None):
        self.log("Forced internal job check requested from Tray.", "AUDIT")
        threading.Thread(target=self._force_run_internal_jobs, daemon=True).start()

    def _force_run_internal_jobs(self):
        jobs = self.config_manager.config.get("jobs", {})
        count = 0
        for job_id, job in jobs.items():
            if job.get("internal_enabled", False):
                 self.after(0, lambda j=job_id: self._run_job_now(j))
                 count += 1
        if count == 0:
            self.log("No internal jobs are enabled.", "INFO")

    # --- SCHEDULER LOGIC ---

    # --- QUEUE LOGIC ---
    # --- QUEUE LOGIC ---
    def _start_queue_processor(self):
        self.log("Queue Processor started", "SYSTEM")
        def loop():
            while True:
                time.sleep(2)
                try:
                    self.after(0, self._process_queue)
                except Exception as e:
                    logger.error(f"Queue Processor Error: {e}")
        threading.Thread(target=loop, daemon=True).start()

    def _process_queue(self):
        """Check queue and run next job if idle."""
        if self.is_running: return
        if not self.job_queue: return
        
        # Pop next job
        try:
            job_item = self.job_queue.pop(0)
            
            if "cmd_list" in job_item:
                # AD-HOC COMMAND
                self.log(f"Queue Processor: Starting Command: {job_item['name']}", "INFO")
                # Need to use after() to ensure we launch in main thread context if not already
                # run_borg_thread handles threading internally
                cmd = job_item["cmd_list"]
                on_complete = job_item.get("on_complete")
                
                self.run_borg_thread(cmd, on_complete=on_complete, task_name=job_item.get('name', 'Task'))
                
            else:
                # STANDARD BACKUP JOB
                self.log(f"Queue Processor: Starting Job: {job_item['name']}", "INFO")
                self._run_job_now(job_item['id'])
            
            # Refresh UI
            if hasattr(self, '_refresh_queue_ui'):
                self._refresh_queue_ui()
        except Exception as e:
            self.log(f"Error processing queue item: {e}", "ERROR")

    def _queue_command(self, name, cmd_list, on_complete=None):
        """Queue an ad-hoc command."""
        self.job_queue.append({
            "id": "cmd_" + str(uuid.uuid4())[:8],
            "name": name,
            "cmd_list": cmd_list,
            "on_complete": on_complete,
            "trigger_time": "Queued",
            "added_at": datetime.datetime.now().strftime("%H:%M:%S"),
            "status": "Pending"
        })
        self.log(f"Command Queued: {name}", "INFO")
        if hasattr(self, '_refresh_queue_ui'):
            self._refresh_queue_ui()
            
    def _queue_job(self, job_id, trigger_time):
        """Add a job to the execution queue."""
        job = self.config_manager.config["jobs"].get(job_id)
        if not job: return
        
        # Check if already in queue to avoid duplicates
        for q in self.job_queue:
            if q.get('id') == job_id and q.get('trigger_time') == trigger_time:
                self.log(f"Job {job['name']} already in queue for {trigger_time}, skipping.", "WARNING")
                return

        self.job_queue.append({
            "id": job_id,
            "name": job.get("name", "Unknown"),
            "repo": job.get("repo", "Unknown"),
            "trigger_time": trigger_time,
            "added_at": datetime.datetime.now().strftime("%H:%M:%S"),
            "status": "Pending"
        })
        self.log(f"Job Queued: {job['name']} for {trigger_time}", "INFO")
        
        if hasattr(self, '_refresh_queue_ui'):
            self._refresh_queue_ui()

    # --- SCHEDULER LOGIC ---

    def _start_scheduler(self):
        self.log("Internal scheduler started (checks every 15s)", "SYSTEM")
        def loop():
            while True:
                try:
                    self._check_jobs()
                except Exception as e:
                    logger.error(f"Scheduler Thread Error: {e}")
                time.sleep(15)  # Check every 15 seconds for reliability
        threading.Thread(target=loop, daemon=True).start()

    def _check_jobs(self):
        try:
            # Reload config to get latest changes
            self.config_manager.load_config()
            
            # Note: We do NOT block on self.is_running here anymore.
            # We simply queue jobs. The queue processor handles concurrency.

            # Iterate over all defined jobs
            jobs = self.config_manager.config.get("jobs", {})
            now = datetime.datetime.now()
            current_hour = now.hour
            current_minute = now.minute
            today_str = now.strftime("%Y-%m-%d")
            
            # Determine current state for frequency checks
            current_dow = now.strftime("%A") # e.g. "Monday"
            current_dom = str(now.day)       # e.g. "5"

            for job_id, job in jobs.items():
                if not job.get("internal_enabled", False):
                    continue
                
                # --- Check Frequency ---
                freq = job.get("frequency", "Daily")
                target_day = job.get("day", "")
                
                should_run_day = True
                if freq == "Weekly":
                    if current_dow != target_day: should_run_day = False
                elif freq == "Monthly":
                    if current_dom != target_day: should_run_day = False
                
                if not should_run_day:
                    continue
                    
                # --- Check Time(s) ---
                # Parse multiple times separated by comma
                raw_time = job.get("time", "03:00")
                if not isinstance(raw_time, str): raw_time = str(raw_time) # Safety check
                time_slots = [t.strip() for t in raw_time.split(',') if t.strip()]
                
                # Execution tracking: executed_slots = {"09:00": "2023-10-27", "17:00": "2023-10-26"}
                executed_slots = job.get("executed_slots", {})
                
                # Simple migration for legacy last_run
                if "last_run" in job and not executed_slots:
                    pass

                for t_str in time_slots:
                    try:
                        target_h, target_m = map(int, t_str.split(":"))
                    except:
                        continue
                    
                    # Check if this specific slot ran today
                    last_run_for_slot = executed_slots.get(t_str)
                    if last_run_for_slot == today_str:
                        continue # Already ran this slot today

                    # Match if we're in the target minute (more reliable than exact string match)
                    if current_hour == target_h and current_minute == target_m:
                        self.log(f"Triggering Internal Job: {job['name']} ({freq}) at {t_str}", "INFO")
                        
                        # Update systray if available
                        if HAS_TRAY and self.icon:
                            self.icon.title = f"Queued: {job['name']}"
                        
                        # QUEUE THE JOB (Do not run immediately)
                        self._queue_job(job_id, t_str)
                        
                        # Update Execution Record
                        executed_slots[t_str] = today_str
                        job["executed_slots"] = executed_slots
                        # Also update legacy last_run for display purposes
                        job["last_run"] = today_str
                        
                        self.config_manager.save_config()
                        
                        # Break after triggering one slot to avoid double-triggering logic issues 
                        # (though unlikely in same minute unless user put "09:00, 09:00")
                        break
        except Exception as outer_e:
            self.log(f"Critical Scheduler Error: {outer_e}", "ERROR")

    def _run_job_now(self, job_id):
        job = self.config_manager.config["jobs"].get(job_id)
        if not job: return

        repo_name = job.get("repo")
        repo_config = self.config_manager.get_repo_details(repo_name)
        if not repo_config:
            self.log(f"Cannot run job {job['name']}: Repo '{repo_name}' not found.", "ERROR")
            return

        # Check if remote source
        source_id = job.get("source", "__local__")
        is_remote = source_id != "__local__"
        source_server = self.config_manager.get_source_server(source_id) if is_remote else None
        
        if is_remote and not source_server:
            self.log(f"Source server '{source_id}' not found for job {job['name']}", "ERROR")
            return

        # Prepare Archive Name
        archive_name = f"{job['name'].replace(' ', '_')}-{datetime.datetime.now().strftime('%Y-%m-%d-%H%M')}"
        
        # Prepare Archive Name
        archive_name = f"{job['name'].replace(' ', '_')}-{datetime.datetime.now().strftime('%Y-%m-%d-%H%M')}"
        
        # --- Build Common Arguments ---
        borg_bin = self.borg_bin if not is_remote else "borg"
        repo_path = repo_config["path"]
        
        cmd_list = [borg_bin, "create", "--stats", "--compression", "zstd,6"]
        for exc in job.get("excludes", []):
            cmd_list.extend(["--exclude", exc])
        
        cmd_list.append(f"{repo_path}::{archive_name}")
        cmd_list.extend(job.get("includes", []))
        
        # Build Environment (Common)
        env = self._build_env_for_repo(repo_config)
        
        self.log(f"🚀 Starting Job: {job['name']} -> {archive_name}", "INFO")
        
        def on_complete_refresh():
            self.refresh_archives()

        if is_remote:
            self.log(f"Remote source: {source_server.get('host')}", "INFO")
            
            # Check if we can use the active SSH helper (same source)
            # We compare source IDs. active_source_id is set when selecting a server in Dashboard/Archives.
            use_existing_helper = (self.active_source_id == source_id) and (self.active_ssh_helper is not None)
            
            if use_existing_helper:
                # Use the existing secure connection
                job_name = job['name']
                self.after(0, lambda jn=job_name: self.run_borg_thread(cmd_list, env_override=env, on_complete=on_complete_refresh, task_name=f"Job: {jn}"))
            else:
                # Ad-Hoc Connection (Source is not the currently active managed server)
                # We interpret this as a "Local" command that runs 'ssh ...'
                
                # Build SSH Command
                ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
                if source_server.get("ssh_key"):
                    ssh_cmd.extend(["-i", source_server["ssh_key"]])
                ssh_cmd.append(source_server["host"])
                
                # Construct Remote Shell Command
                # We need to manually inject environment variables as exports
                exports = []
                if env.get("BORG_PASSPHRASE"): exports.append(f"export BORG_PASSPHRASE='{env['BORG_PASSPHRASE']}'")
                if env.get("SSHPASS"): exports.append(f"export SSHPASS='{env['SSHPASS']}'")
                if env.get("BORG_RSH"): exports.append(f"export BORG_RSH='{env['BORG_RSH']}'")
                # BORG_REPO is implicitly handled by argument, but safe to add
                if env.get("BORG_REPO"): exports.append(f"export BORG_REPO='{env['BORG_REPO']}'")

                # Quote arguments for remote shell
                # Simple quoting strategy: quote if contains space or single quote
                remote_parts = []
                for arg in cmd_list:
                    if " " in arg or "'" in arg:
                        remote_parts.append(f"'{arg}'")
                    else:
                        remote_parts.append(arg)
                remote_cmd_str = " ".join(remote_parts)
                
                full_remote_cmd = " && ".join(exports + [remote_cmd_str])
                
                ssh_cmd.append(full_remote_cmd)
                
                # Execute locally (force_local=True ensures run_borg_thread checks backup_op logic on the full ssh cmd)
                job_name = job['name']
                self.after(0, lambda jn=job_name: self.run_borg_thread(ssh_cmd, force_local=True, on_complete=on_complete_refresh, task_name=f"Job: {jn}"))

        else:
            # Local execution
            # Pruning Logic (Preserved from original code, only for Local)
            prune_cmd = None
            if job.get("prune_enabled", False):
                d = job.get("keep_daily", 7)
                w = job.get("keep_weekly", 4)
                m = job.get("keep_monthly", 6)
                keep_last = job.get("keep_last", 0)
                
                prefix = f"{job['name'].replace(' ', '_')}-"
                
                prune_cmd = [
                    self.borg_bin, "prune", "--list", "--stats",
                    "--prefix", prefix,
                    "--keep-daily", str(d),
                    "--keep-weekly", str(w),
                    "--keep-monthly", str(m)
                ]
                if int(keep_last) > 0:
                    prune_cmd.extend(["--keep-last", str(keep_last)])

            def on_complete_local():
                if prune_cmd:
                    self.log(f"Pruning Job: {job['name']}", "INFO")
                    self.run_borg_thread(prune_cmd, env_override=env, on_complete=on_complete_refresh, force_local=True, task_name=f"Prune: {job['name']}")
                else:
                    on_complete_refresh()

            job_name = job['name']
            self.after(0, lambda jn=job_name: self.run_borg_thread(cmd_list, env_override=env, force_local=True, on_complete=on_complete_local, task_name=f"Job: {jn}"))

    def _build_env_for_repo(self, details):
        env = os.environ.copy()
        env["BORG_REPO"] = details["path"]
        ssh_cmd = "ssh -o StrictHostKeyChecking=accept-new"
        
        if details.get("ssh_password") and shutil.which("sshpass"):
             env["SSHPASS"] = details["ssh_password"]
             env["BORG_RSH"] = f"sshpass -e {ssh_cmd}"
        else:
             env["BORG_RSH"] = ssh_cmd

        if details.get("repo_passphrase"):
            env["BORG_PASSPHRASE"] = details["repo_passphrase"]
        elif details.get("pass_command"):
            env["BORG_PASSCOMMAND"] = details["pass_command"]
        
        env["BORG_RELOCATED_REPO_ACCESS_IS_OK"] = "no"
        return env

    # --- DASHBOARD BUILDER (MODIFIED) ---
    def _build_dashboard_tab(self):
        self.dash_container = ttk.Frame(self.tab_dashboard, padding=20)
        self.dash_container.pack(fill=tk.BOTH, expand=True)

        # Header with action buttons
        header_frame = ttk.Frame(self.dash_container)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        self.dash_repo_label = ttk.Label(header_frame, text="No Repository Selected")
        self.dash_repo_label.pack(side=tk.LEFT)
        
        # Right side: Action buttons + Refresh
        self.dash_refresh_btn = ttk.Button(header_frame, text=f"{icon('refresh')} Refresh", command=self._refresh_dashboard)
        self.dash_refresh_btn.pack(side=tk.RIGHT, padx=2)
        ttk.Button(header_frame, text=f"{icon('log')} Logs", command=lambda: self._switch_tab("logs")).pack(side=tk.RIGHT, padx=2)
        ttk.Button(header_frame, text=f"{icon('prune')} Maint", command=lambda: self._switch_tab("maintenance")).pack(side=tk.RIGHT, padx=2)
        ttk.Button(header_frame, text=f"{icon('mount')} Mounts", command=lambda: self._switch_tab("mounts")).pack(side=tk.RIGHT, padx=2)
        ttk.Button(header_frame, text=f"{icon('add')} + Backup", command=lambda: self._switch_tab("backup")).pack(side=tk.RIGHT, padx=2)

        # === ROW 1: Main Stats Cards ===
        self.cards_frame = ttk.Frame(self.dash_container)
        self.cards_frame.pack(fill=tk.X, pady=5)
        for i in range(4): self.cards_frame.columnconfigure(i, weight=1)

        # Variables for Row 1
        self.var_health = tk.StringVar(value="--")
        self.var_health_desc = tk.StringVar(value="Checking...")
        self.var_archives = tk.StringVar(value="0")
        self.var_last_backup = tk.StringVar(value="--")
        self.var_last_archive_name = tk.StringVar(value="--")
        self.var_dedup_size = tk.StringVar(value="0 B")
        self.var_orig_size = tk.StringVar(value="0 B")
        self.var_size_comparison = tk.StringVar(value="")
        self.var_savings = tk.StringVar(value="0%")
        self.var_jobs_active = tk.StringVar(value="0")
        self.var_next_run = tk.StringVar(value="--")

        # Row 1 Cards
        self._create_card(self.cards_frame, 0, f"{icon('status')} Status", self.var_health, "card_status", 
                         self.var_health_desc)
        self._create_card(self.cards_frame, 1, f"{icon('archive')} Archives", self.var_archives, "card_archive", 
                         self.var_last_backup, sub_pre="Last: ", extra_var=self.var_last_archive_name)
        self._create_card(self.cards_frame, 2, f"{icon('storage')} Storage", self.var_dedup_size, "card_storage", 
                         self.var_size_comparison, extra_var=self.var_savings)
        self._create_card(self.cards_frame, 3, f"{icon('schedule')} Schedule", self.var_jobs_active, "card_sched", 
                         self.var_next_run, sub_pre="Next: ")

        # Variables for Row 2
        self.var_server_host = tk.StringVar(value="--")
        self.var_server_uptime = tk.StringVar(value="--")
        self.var_server_mem = tk.StringVar(value="--")
        self.var_server_disk = tk.StringVar(value="--")

        # Row 2 Cards with emojis (Source Server)
        self._create_card(self.cards_frame, 0, f"{icon('server')} Source", self.var_server_host, "card_server", row=1)
        self._create_card(self.cards_frame, 1, f"{icon('time')} Uptime", self.var_server_uptime, "card_server", row=1)
        self._create_card(self.cards_frame, 2, f"{icon('memory')} RAM", self.var_server_mem, "card_server", row=1)
        self._create_card(self.cards_frame, 3, f"{icon('disk')} Disk", self.var_server_disk, "card_server", row=1)

        # Variables for Row 3 (Repo Server)
        self.var_repo_host = tk.StringVar(value="--")
        self.var_repo_mem = tk.StringVar(value="--")         # Main: percentage like "45%"
        self.var_repo_mem_detail = tk.StringVar(value="--")  # Sub: "4G / 8G"
        self.var_repo_size = tk.StringVar(value="--")
        self.var_repo_disk = tk.StringVar(value="--")        # Main: percentage like "45% used"
        self.var_repo_disk_detail = tk.StringVar(value="--") # Sub: "120G / 500G"

        # Row 3 Cards (Repo Server - where backups are stored)
        self._create_card(self.cards_frame, 0, f"{icon('storage')} Repo Host", self.var_repo_host, "card_repo", row=2)
        self._create_card(self.cards_frame, 1, f"{icon('memory')} RAM", self.var_repo_mem, "card_repo", row=2, sub_var=self.var_repo_mem_detail)
        self._create_card(self.cards_frame, 2, f"{icon('disk')} Disk", self.var_repo_disk, "card_repo", row=2, sub_var=self.var_repo_disk_detail)
        self._create_card(self.cards_frame, 3, f"{icon('archive')} Repo Size", self.var_repo_size, "card_repo", row=2)

        # === TWO COLUMN LAYOUT: Running Backup | Upcoming Schedules ===
        mid_frame = ttk.Frame(self.dash_container)
        mid_frame.pack(fill=tk.BOTH, expand=False, pady=5) # expand=False to keep it compact
        mid_frame.columnconfigure(0, weight=1)
        mid_frame.columnconfigure(1, weight=1)
        
        # LEFT: Running Backup Monitor (detailed)
        self.running_frame = ttk.LabelFrame(mid_frame, text="Running Backup", padding=5)
        self.running_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        
        self.var_run_status = tk.StringVar(value="No backup running")
        self.var_run_job = tk.StringVar(value="--")
        self.var_run_file = tk.StringVar(value="--")
        self.var_run_progress = tk.StringVar(value="0 files")
        self.var_run_elapsed = tk.StringVar(value="00:00:00")
        
        # New stats vars
        self.var_run_orig = tk.StringVar(value="0 B")
        self.var_run_comp = tk.StringVar(value="0 B")
        self.var_run_dedup = tk.StringVar(value="0 B")
        
        # Top: Status + Cancel
        run_top = ttk.Frame(self.running_frame)
        run_top.pack(fill=tk.X, pady=(0, 5))
        self.lbl_run_indicator = ttk.Label(run_top, text="●", foreground="gray")
        self.lbl_run_indicator.pack(side=tk.LEFT)
        ttk.Label(run_top, textvariable=self.var_run_status, font=("", 10, "bold")).pack(side=tk.LEFT, padx=5)
        ttk.Label(run_top, textvariable=self.var_run_elapsed, foreground=self.get_theme_color("text_meta")).pack(side=tk.LEFT, padx=10)
        self.btn_cancel = ttk.Button(run_top, text=f"{icon('stop')} Cancel", command=self._cancel_running_backup, state=tk.DISABLED, width=10)
        self.btn_cancel.pack(side=tk.RIGHT)

        # Stats Grid
        stats_frame = ttk.Frame(self.running_frame)
        stats_frame.pack(fill=tk.X, pady=2)
        
        # Row 1: Files count
        ttk.Label(stats_frame, text="Files:", foreground=self.get_theme_color("text_meta")).grid(row=0, column=0, sticky="w")
        ttk.Label(stats_frame, textvariable=self.var_run_progress).grid(row=0, column=1, sticky="w", padx=(5, 10))
        
        # Row 2: Stats (Original | Compressed | Dedup)
        ttk.Label(stats_frame, text="Original:", foreground=self.get_theme_color("text_meta")).grid(row=1, column=0, sticky="w")
        ttk.Label(stats_frame, textvariable=self.var_run_orig, foreground=self.get_theme_color("stat_orig")).grid(row=1, column=1, sticky="w", padx=(5, 10))
        
        ttk.Label(stats_frame, text="Compressed:", foreground=self.get_theme_color("text_meta")).grid(row=1, column=2, sticky="w")
        ttk.Label(stats_frame, textvariable=self.var_run_comp, foreground=self.get_theme_color("stat_comp")).grid(row=1, column=3, sticky="w", padx=(5, 10))
        
        ttk.Label(stats_frame, text="Dedup:", foreground=self.get_theme_color("text_meta")).grid(row=1, column=4, sticky="w")
        ttk.Label(stats_frame, textvariable=self.var_run_dedup, foreground=self.get_theme_color("stat_dedup")).grid(row=1, column=5, sticky="w", padx=(5, 0))

        # Bottom: Current File
        run_file = ttk.Frame(self.running_frame, padding=(0, 5, 0, 0))
        run_file.pack(fill=tk.X)
        ttk.Label(run_file, text="Current:", foreground=self.get_theme_color("text_meta")).pack(side=tk.LEFT)
        ttk.Label(run_file, textvariable=self.var_run_file, foreground=self.get_theme_color("text_meta")).pack(side=tk.LEFT, padx=5)
        
        # RIGHT: Upcoming Schedules (compact)
        sched_frame = ttk.LabelFrame(mid_frame, text="Upcoming Schedules", padding=5)
        sched_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        
        self.schedule_list = ttk.Treeview(sched_frame, columns=("Job", "Source", "Time", "In"), 
                                          show='headings', height=4) # Reduced height
        self.schedule_list.heading("Job", text="Job")
        self.schedule_list.heading("Source", text="Source")
        self.schedule_list.heading("Time", text="Time")
        self.schedule_list.heading("In", text="Runs In")
        self.schedule_list.column("Job", width=120)
        self.schedule_list.column("Source", width=80)
        self.schedule_list.column("Time", width=50)
        self.schedule_list.column("In", width=60)
        
        sched_scroll = ttk.Scrollbar(sched_frame, orient="vertical", command=self.schedule_list.yview)
        self.schedule_list.configure(yscrollcommand=sched_scroll.set)
        
        self.schedule_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sched_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.after(1000, self._refresh_upcoming_schedules)
        # Recent Jobs History (replaces repo details)
        hist_frame = ttk.LabelFrame(self.dash_container, text="Recent Jobs", padding=5)
        hist_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        columns = ("Job", "Source", "Status", "Size", "Started", "Duration")
        self.history_list = ttk.Treeview(hist_frame, columns=columns, show='headings', height=5)
        
        self.history_list.heading("Job", text="Job Name")
        self.history_list.heading("Source", text="Source")
        self.history_list.heading("Status", text="Status")
        self.history_list.heading("Size", text="Size (Orig → Comp)")
        self.history_list.heading("Started", text="Started")
        self.history_list.heading("Duration", text="Duration")
        
        self.history_list.column("Job", width=150)
        self.history_list.column("Source", width=80)
        self.history_list.column("Status", width=70)
        self.history_list.column("Size", width=130)
        self.history_list.column("Started", width=110)
        self.history_list.column("Duration", width=70)
        
        self.history_list.pack(fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(hist_frame, orient=tk.VERTICAL, command=self.history_list.yview)
        self.history_list.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.history_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Cache for job details (for double-click popup)
        self.history_cache = {}
        self.history_list.bind("<Double-1>", self._on_history_double_click)
        
        self.after(2000, self._refresh_history)

    def _fetch_remote_history(self, ssh_helper):
        """Fetch cron history logs from remote server."""
        if not ssh_helper:
            return []
        
        # Path to the history log we defined in CronManager
        log_path = ".config/borg_manager/logs/cron_history.jsonl"
        cmd = f"cat {log_path} 2>/dev/null | tail -n 50"
        
        success, output, _ = ssh_helper.execute(cmd, timeout=5)
        if not success:
            return []
            
        entries = []
        for line in output.splitlines():
            if not line.strip(): continue
            try:
                # Basic JSON parsing
                entry = json.loads(line)
                # Ensure it has an ID
                if "id" not in entry: entry["id"] = "cron" + str(hash(line))[-6:]
                entries.append(entry)
            except: pass
            
        return entries

    def _refresh_history(self):
        """Refresh the recent jobs history table."""
        if not hasattr(self, 'history_list'): return
        
        # Clear
        for item in self.history_list.get_children():
            self.history_list.delete(item)
            
        history = list(self.config_manager.get_history()) # Copy local history
        
        # --- FETCH REMOTE HISTORY ---
        # 1. Fetch from active server if remote
        if self.active_source_id != "__local__" and self.active_ssh_helper:
            remote_entries = self._fetch_remote_history(self.active_ssh_helper)
            # Tag them
            for r in remote_entries:
                r["source"] = self.active_source_id
            history.extend(remote_entries)
            
        # 2. If we are Local, also check local cron history file
        if self.active_source_id == "__local__":
            local_cron_path = os.path.expanduser("~/.config/borg_manager/logs/cron_history.jsonl")
            if os.path.exists(local_cron_path):
                try:
                    with open(local_cron_path, 'r') as f:
                        lines = f.readlines()[-50:] # last 50
                        for line in lines:
                             try:
                                 entry = json.loads(line)
                                 entry["id"] = "cron" + str(hash(line))[-6:]
                                 entry["source"] = "__local__ (Cron)"
                                 history.append(entry)
                             except: pass
                except: pass

        # Sort by start time (newest first)
        def parse_time(t_str):
            try:
                # Try standard format
                return datetime.datetime.strptime(t_str, "%Y-%m-%d %H:%M") 
            except:
                return datetime.datetime.min
                
        history.sort(key=lambda x: parse_time(x.get("start", "")), reverse=True)
        
        # Display
        for h in history:
            # Add icon to status
            status = h.get('status', 'Unknown')
            icon = "🟢" if status == "Success" else "🔴" if status == "Failed" else "⚪"
            if status == "Cancelled": icon = "⛔"
            
            # Format Stats
            stats = h.get('stats', {})
            size_str = "--"
            if stats:
                orig = stats.get('original', '0 B')
                comp = stats.get('compressed', '0 B')
                size_str = f"{orig} → {comp}"
            
            # Get source info
            source_id = h.get('source', '__local__')
            if source_id == '__local__':
                source_name = 'Local'
            else:
                srv = self.config_manager.get_source_server(source_id)
                source_name = srv.get('name', source_id)[:10] if srv else source_id[:10]
            
            # Generate unique item ID and cache full data
            item_id = h.get('id', str(hash(str(h))))
            self.history_cache[item_id] = h
            
            self.history_list.insert('', tk.END, iid=item_id, values=(
                h.get('job', 'Unknown'),
                source_name,
                f"{icon} {status}",
                size_str,
                h.get('start', '--'),
                h.get('duration', '--')
            ))
    
    def _on_history_double_click(self, event):
        """Show job details popup on double-click."""
        sel = self.history_list.selection()
        if not sel:
            return
        
        item_id = sel[0]
        job_data = self.history_cache.get(item_id, {})
        
        if not job_data:
            return
        
        # Create popup
        popup = tk.Toplevel(self)
        popup.title("Job Details")
        popup.geometry("450x350")
        popup.transient(self)
        popup.configure(bg=self.get_theme_color("bg_window"))
        
        main = ttk.Frame(popup, padding=15)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Job name header
        job_name = job_data.get('job', 'Unknown Job')
        ttk.Label(main, text=job_name, font=("", 14, "bold")).pack(anchor=tk.W)
        
        # Status with color
        status = job_data.get('status', 'Unknown')
        status_color = "#27ae60" if status == "Success" else "#e74c3c" if status == "Failed" else "gray"
        ttk.Label(main, text=f"Status: {status}", foreground=status_color, font=("", 11)).pack(anchor=tk.W, pady=(5, 10))
        
        # Details frame
        details = ttk.Frame(main)
        details.pack(fill=tk.BOTH, expand=True)
        
        def add_row(label, value, row):
            ttk.Label(details, text=label, foreground="gray").grid(row=row, column=0, sticky=tk.W, pady=2)
            ttk.Label(details, text=str(value)).grid(row=row, column=1, sticky=tk.W, padx=10, pady=2)
        
        add_row("Source:", job_data.get('source', 'Unknown'), 0)
        add_row("Repository:", job_data.get('repo', 'Unknown'), 1)
        add_row("Started:", job_data.get('start', '--'), 2)
        add_row("Duration:", job_data.get('duration', '--'), 3)
        
        # Stats section
        stats = job_data.get('stats', {})
        if stats:
            ttk.Separator(main, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
            ttk.Label(main, text="Statistics", font=("", 11, "bold")).pack(anchor=tk.W)
            
            stats_frame = ttk.Frame(main)
            stats_frame.pack(fill=tk.X, pady=5)
            
            add_stat = lambda l, v, r: [
                ttk.Label(stats_frame, text=l, foreground="gray").grid(row=r, column=0, sticky=tk.W),
                ttk.Label(stats_frame, text=str(v)).grid(row=r, column=1, sticky=tk.W, padx=10)
            ]
            add_stat("Original Size:", stats.get('original', '--'), 0)
            add_stat("Compressed Size:", stats.get('compressed', '--'), 1)
            add_stat("Deduplicated Size:", stats.get('deduplicated', '--'), 2)
            add_stat("Files:", stats.get('nfiles', '--'), 3)
        
        # Error message if failed
        error = job_data.get('error', '')
        if error:
            ttk.Separator(main, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
            ttk.Label(main, text="Error:", foreground="#e74c3c", font=("", 10, "bold")).pack(anchor=tk.W)
            error_text = tk.Text(main, height=3, wrap=tk.WORD, bg=self.get_theme_color("bg_card"))
            error_text.insert("1.0", error)
            error_text.config(state=tk.DISABLED)
            error_text.pack(fill=tk.X, pady=5)
        
        ttk.Button(main, text="Close", command=popup.destroy).pack(pady=10)
    
    def get_theme_color(self, key_or_hex):
        """Get color from current theme, or return hex if not a key."""
        theme = THEME_COLORS.get(self.current_theme, THEME_COLORS["light"])
        return theme.get(key_or_hex, key_or_hex)

    def toggle_theme(self):
        new_theme = "dark" if self.current_theme == "light" else "light"
        self.current_theme = new_theme
        self.config_manager.config["theme"] = new_theme
        self.config_manager.save_config()
        
        # Re-initialize UI
        for widget in self.winfo_children():
            if isinstance(widget, tk.Menu): continue # Don't destroy menu
            widget.destroy()
        self._init_ui()
        self.refresh_repo_display()
        
        # Restore active tab if possible (defaulting to Dashboard)

    def _create_card(self, parent, col, title, var, bg_key, sub_var=None, sub_pre="", icon=None, extra_var=None, row=0):
        bg = self.get_theme_color(bg_key)
        fg_main = self.get_theme_color("text_main")
        fg_sub = self.get_theme_color("text_sub")
        fg_meta = self.get_theme_color("text_meta")
        
        f = tk.Frame(parent, bg=bg, relief="ridge", bd=2)
        f.grid(row=row, column=col, sticky="nsew", padx=5, pady=3)
        
        # Title
        tk.Label(f, text=title, bg=bg, fg=fg_sub).pack(pady=(8, 2))
        
        # Main value
        tk.Label(f, textvariable=var, bg=bg, fg=fg_main).pack(pady=3)
        
        # Sub information
        if sub_var:
            s = tk.Frame(f, bg=bg)
            s.pack(pady=(0,3))
            if sub_pre: 
                tk.Label(s, text=sub_pre, bg=bg, fg=fg_meta).pack(side=tk.LEFT)
            tk.Label(s, textvariable=sub_var, bg=bg, fg=fg_sub).pack(side=tk.LEFT)
            
        if extra_var:
             tk.Label(f, textvariable=extra_var, bg=bg, fg=fg_meta).pack(pady=(0, 5))
    
    def _refresh_dashboard(self):
        """Refresh all dashboard data including schedules and history."""
        self.run_info()
        self._refresh_upcoming_schedules()
        if hasattr(self, '_refresh_history'):
            self._refresh_history()
    
    def _refresh_upcoming_schedules(self):
        """Refresh the upcoming schedules list on dashboard."""
        if not hasattr(self, 'schedule_list'):
            return
            
        # Clear existing
        for item in self.schedule_list.get_children():
            self.schedule_list.delete(item)
        
        jobs = self.config_manager.config.get("jobs", {})
        now = datetime.datetime.now()
        upcoming = []
        
        for job_id, job in jobs.items():
            if not job.get("internal_enabled", False) and not job.get("cron_enabled", False):
                continue
            # Parse multiple times
            raw_time = str(job.get("time", "03:00"))
            time_slots = [t.strip() for t in raw_time.split(',') if t.strip()]
            
            # Find closest next run
            best_diff = 999999
            best_in_text = ""
            best_slot = ""
            
            valid_slot_found = False
            for t_str in time_slots:
                try:
                    h, m = map(int, t_str.split(":"))
                    job_time = now.replace(hour=h, minute=m, second=0)
                    if job_time < now:
                        job_time += datetime.timedelta(days=1)
                    
                    diff_min = int((job_time - now).total_seconds() / 60)
                    if diff_min < best_diff:
                        best_diff = diff_min
                        best_slot = t_str
                        valid_slot_found = True
                        if diff_min < 60:
                            best_in_text = f"{diff_min}m"
                        else:
                            best_in_text = f"{diff_min // 60}h {diff_min % 60}m"
                except:
                    continue
            
            if not valid_slot_found:
                continue

            sched_type = "Int" if job.get("internal_enabled") else "Cron"
            
            # Get source name
            source_id = job.get('source', '__local__')
            if source_id == '__local__':
                source_name = 'Local'
            else:
                srv = self.config_manager.get_source_server(source_id)
                source_name = srv.get('name', source_id)[:8] if srv else source_id[:8]
            
            upcoming.append((best_diff, job["name"], source_name, best_slot, 
                           f"{job.get('frequency', 'Daily')} ({sched_type})", best_in_text))
        
        # Sort by time
        upcoming.sort(key=lambda x: x[0])
        for _, name, source, time, freq, in_text in upcoming:
            self.schedule_list.insert('', tk.END, values=(name, source, time, in_text))
    
    def _cancel_running_backup(self):
        """Cancel the currently running backup."""
        if self.current_process and self.is_running:
            if messagebox.askyesno("Cancel Backup", "Are you sure you want to cancel the running backup?"):
                try:
                    self.current_process.terminate()
                    self.log("Backup CANCELLED by user", "ERROR")
                    self.var_run_status.set("Cancelled")
                    self.lbl_run_indicator.config(foreground="red")
                    self.btn_cancel.config(state=tk.DISABLED)
                except:
                    pass
    
    def _update_running_backup_ui(self, job_name=None, files=None, orig=None, comp=None, dedup=None, current_file=None):
        """Update dashboard running backup panel. Only updates provided values."""
        if job_name:
            self.var_run_status.set(f"Running: {job_name}")
            self.lbl_run_indicator.config(foreground="green")
            self.btn_cancel.config(state=tk.NORMAL)
        
        if files is not None:
            self.var_run_progress.set(f"{files} files")
        if orig is not None:
            self.var_run_orig.set(orig)
        if comp is not None:
            self.var_run_comp.set(comp)
        if dedup is not None:
            self.var_run_dedup.set(dedup)
        
        if current_file is not None:
            if len(current_file) > 50:
                current_file = "..." + current_file[-47:]
            self.var_run_file.set(current_file or "--")
    
    def _reset_running_backup_ui(self):
        """Reset dashboard running backup panel to idle state."""
        self.var_run_status.set("No backup running")
        self.var_run_job.set("--")
        self.var_run_file.set("--")
        self.var_run_progress.set("0 files")
        self.var_run_elapsed.set("00:00:00")
        
        self.var_run_orig.set("0 B")
        self.var_run_comp.set("0 B")
        self.var_run_dedup.set("0 B")
        
        self.lbl_run_indicator.config(foreground="gray")
        self.btn_cancel.config(state=tk.DISABLED)
    
    def _save_backup_history(self, duration_str, status, task_name=None, start_time_str=None):
        """Save backup history entry - must be called on main thread to access StringVars."""
        try:
            # Check for cancelled status
            if hasattr(self, 'var_run_status') and self.var_run_status.get() == "Cancelled":
                status = "Cancelled"
            
            repo_name = self.config_manager.config.get("current_repo", "Unknown")
            
            # Capture stats from UI - this is now safe since we're on main thread
            files_str = self.var_run_progress.get() if hasattr(self, 'var_run_progress') else "0 files"
            nfiles = files_str.split()[0] if files_str else "0"
            
            stats = {
                "original": self.var_run_orig.get() if hasattr(self, 'var_run_orig') else "0 B",
                "compressed": self.var_run_comp.get() if hasattr(self, 'var_run_comp') else "0 B",
                "deduplicated": self.var_run_dedup.get() if hasattr(self, 'var_run_dedup') else "0 B",
                "nfiles": nfiles
            }
            
            # Use provided task_name or fallback
            display_name = task_name or getattr(self, 'current_task_name', 'Manual Backup') or "Manual Backup"
            if not start_time_str:
                start_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            
            self.config_manager.add_history_entry(
                display_name, repo_name, status, duration_str, start_time_str, stats,
                source=self.active_source_id
            )
            
            # Send desktop notification
            if status == "Success":
                send_notification(
                    "✓ Backup Complete",
                    f"{display_name} completed in {duration_str}",
                    "normal"
                )
            elif status in ("Failed", "Error"):
                send_notification(
                    "✗ Backup Failed",
                    f"{display_name} failed - check logs",
                    "critical"
                )
            
            # Refresh dashboard history
            if hasattr(self, '_refresh_history'):
                self._refresh_history()
                
        except Exception as e:
            logger.error(f"Error saving backup history: {e}")

    def _parse_borg_progress(self, line):
        """Parse borg progress output line and final stats."""
        # Clean ANSI codes (common with SSH/PTY)
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_line = ansi_escape.sub('', line).strip()
        
        try:
            # Pattern 1: Real-time progress like "1.54 MB O 100 kB C 50 kB D 1234 N /path"
            match = re.search(r'([\d.]+\s+[A-Za-z]+)\s+O\s+([\d.]+\s+[A-Za-z]+)\s+C\s+([\d.]+\s+[A-Za-z]+)\s+D\s+(\d+)\s+N\s+(.*)', clean_line)
            if match:
                orig = match.group(1)
                comp = match.group(2)
                dedup = match.group(3)
                files = match.group(4)
                path = match.group(5)
                self._update_running_backup_ui(files=files, orig=orig, comp=comp, dedup=dedup, current_file=path)
                return
            
            # Pattern 2: Final stats "This archive: X.XX GB  Y.YY GB  Z.ZZ MB"
            # Borg outputs: This archive:  1.23 GB   1.10 GB   500.00 MB
            stats_match = re.search(r'This archive:\s+([\d.]+\s+[A-Za-z]+)\s+([\d.]+\s+[A-Za-z]+)\s+([\d.]+\s+[A-Za-z]+)', clean_line)
            if stats_match:
                orig = stats_match.group(1)
                comp = stats_match.group(2)
                dedup = stats_match.group(3)
                self._update_running_backup_ui(orig=orig, comp=comp, dedup=dedup)
                return
            
            # Pattern 3: Number of files "Number of files: 12345"
            files_match = re.search(r'Number of files:\s+(\d+)', clean_line)
            if files_match:
                files = files_match.group(1)
                self._update_running_backup_ui(files=files)
                return
                
        except Exception:
            pass

    def _build_archives_tab(self):
        frame = ttk.Frame(self.tab_archives, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Search/Filter Box
        search_frame = ttk.Frame(frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(search_frame, text="🔍 Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.archive_search_var = tk.StringVar()
        self.archive_search_entry = ttk.Entry(search_frame, textvariable=self.archive_search_var, width=30)
        self.archive_search_entry.pack(side=tk.LEFT, padx=5)
        self.archive_search_var.trace_add("write", lambda *args: self._filter_archives())
        ttk.Button(search_frame, text="Clear", command=lambda: self.archive_search_var.set("")).pack(side=tk.LEFT, padx=5)
        
        # Store all archives for filtering
        self._all_archives = []

        # COLUMNS: Added "Age" and renamed "Time" to "Date"
        cols = ("Name", "Date", "Age", "ID")
        self.archive_tree = ttk.Treeview(frame, columns=cols, show='headings', selectmode='browse')
        
        self.archive_tree.heading("Name", text="Archive Name")
        self.archive_tree.heading("Date", text="Date Created")
        self.archive_tree.heading("Age", text="Age")
        self.archive_tree.heading("ID", text="ID")
        
        self.archive_tree.column("Name", width=300)
        self.archive_tree.column("Date", width=140, anchor="center") # Fixed width for date
        self.archive_tree.column("Age", width=100, anchor="center")  # "2 hours ago"
        self.archive_tree.column("ID", width=250) # Keep ID visible but pushed to right

        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.archive_tree.yview)
        self.archive_tree.configure(yscrollcommand=scroll.set)
        
        self.archive_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        btn_frame = ttk.Frame(frame, padding=5)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text=f"{icon('refresh')} Refresh", command=self.refresh_archives).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=f"{icon('info')} Info", command=self.show_archive_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=f"{icon('mount')} Mount", command=self.mount_archive).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=f"{icon('refresh')} Recreate", command=self.recreate_archive).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="⇄ Diff", command=self.diff_archives).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=f"{icon('delete')} Delete", command=self.delete_archive).pack(side=tk.RIGHT, padx=5)

    def _filter_archives(self):
        """Filter archive list based on search text."""
        search_text = self.archive_search_var.get().lower()
        
        # Clear current tree
        for item in self.archive_tree.get_children():
            self.archive_tree.delete(item)
        
        # Re-populate with filtered items
        for archive in self._all_archives:
            name, date, age, archive_id = archive
            if search_text in name.lower() or search_text in date.lower():
                self.archive_tree.insert('', tk.END, values=archive)

    def _build_mounts_tab(self):
        frame = ttk.Frame(self.tab_mounts, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        # (Same as before)
        cols = ("Mount Point", "Source")
        
        # Container for tree and scrollbar
        tree_container = ttk.Frame(frame)
        tree_container.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar (pack RIGHT first)
        scroll = ttk.Scrollbar(tree_container, orient="vertical")
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Treeview (pack LEFT fill BOTH)
        self.mount_tree = ttk.Treeview(tree_container, columns=cols, show='headings', selectmode='browse', yscrollcommand=scroll.set)
        self.mount_tree.heading("Mount Point", text="Mount Point")
        self.mount_tree.heading("Source", text="Source")
        self.mount_tree.column("Mount Point", width=400)
        self.mount_tree.column("Source", width=400)
        
        self.mount_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.config(command=self.mount_tree.yview)

        btn_frame = ttk.Frame(frame, padding=5)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text=f"{icon('refresh')} Refresh", command=self.refresh_mounts).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=f"{icon('stop')} Unmount", command=self.unmount_selected_mount).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=f"{icon('open')} Open", command=self.open_mounted_folder).pack(side=tk.LEFT, padx=5)

    def _build_backup_tab(self):
        frame = ttk.Frame(self.tab_backup, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        # (Same as before but stripped down since Scheduler is the main feature now)
        ttk.Label(frame, text="One-Time Backup").pack(anchor=tk.W)
        
        ttk.Label(frame, text="Archive Name:").pack(anchor=tk.W)
        self.backup_name_var = tk.StringVar(value="manual-backup")
        ttk.Entry(frame, textvariable=self.backup_name_var, width=50).pack(anchor=tk.W, pady=5)

        split_frame = ttk.Frame(frame)
        split_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        inc_frame = ttk.LabelFrame(split_frame, text="Includes")
        inc_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.list_includes = tk.Listbox(inc_frame, bg=self.get_theme_color("bg_card"), fg=self.get_theme_color("text_main"))
        self.list_includes.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        btn_inc = ttk.Frame(inc_frame)
        btn_inc.pack(fill=tk.X)
        ttk.Button(btn_inc, text=f"{icon('open')} Browser", command=self.open_interactive_selector).pack(side=tk.TOP, fill=tk.X, pady=2)
        ttk.Button(btn_inc, text=f"{icon('add')} Add", command=lambda: self.add_path(self.list_includes)).pack(side=tk.LEFT)
        ttk.Button(btn_inc, text=f"{icon('remove')} Remove", command=lambda: self.remove_path(self.list_includes)).pack(side=tk.RIGHT)

        exc_frame = ttk.LabelFrame(split_frame, text="Excludes")
        exc_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        self.list_excludes = tk.Listbox(exc_frame, bg=self.get_theme_color("bg_card"), fg=self.get_theme_color("text_main"))
        self.list_excludes.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        btn_exc = ttk.Frame(exc_frame)
        btn_exc.pack(fill=tk.X)
        ttk.Button(btn_exc, text=f"{icon('add')} Add", command=lambda: self.add_path(self.list_excludes)).pack(side=tk.LEFT)
        ttk.Button(btn_exc, text=f"{icon('remove')} Remove", command=lambda: self.remove_path(self.list_excludes)).pack(side=tk.RIGHT)

        ttk.Button(frame, text=f"{icon('backup')} START BACKUP", command=self.start_backup).pack(pady=15, ipady=5)
        
    def open_interactive_selector(self):
        def on_confirm(includes, excludes):
            # Clear old lists? Or append? Let's append to be safe
            for i in includes:
                self.list_includes.insert(tk.END, i)
            for e in excludes:
                self.list_excludes.insert(tk.END, e)
            
            messagebox.showinfo("Imported", f"Added {len(includes)} items to Include and {len(excludes)} items to Exclude.")

        FileSelectorDialog(self, on_confirm, ssh_helper=self.active_ssh_helper)

    def _build_schedule_tab(self):
        # Master-Detail Layout
        paned = tk.PanedWindow(self.tab_schedule, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # LEFT: List of Jobs
        left_frame = ttk.Frame(paned, width=220)
        paned.add(left_frame)
        
        # Header with icon
        header_left = ttk.Frame(left_frame)
        header_left.pack(fill=tk.X, pady=5)
        ttk.Label(header_left, text="Backup Jobs").pack(side=tk.LEFT, padx=5)
        
        self.job_listbox = tk.Listbox(left_frame, exportselection=False, bg=self.get_theme_color("bg_card"), fg=self.get_theme_color("text_main"))
        self.job_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.job_listbox.bind("<<ListboxSelect>>", self._on_job_select)
        
        # Job action buttons
        job_btn_frame = ttk.Frame(left_frame)
        job_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(job_btn_frame, text=f"{icon('add')} New Job", command=self._create_new_job).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        ttk.Button(job_btn_frame, text=f"{icon('run')} Run Now", command=self._run_selected_job_now).pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=2)

        # RIGHT: Job Details (Now Scrollable)
        self.right_frame = ttk.Frame(paned)
        paned.add(self.right_frame)
        
        # === ACTION BUTTONS (Fixed at Bottom) ===
        act_frame = ttk.Frame(self.right_frame)
        act_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=10, padx=5)
        
        ttk.Button(act_frame, text=f"{icon('save')} Save Job", command=self._save_current_job).pack(side=tk.RIGHT, padx=5)
        ttk.Button(act_frame, text=f"{icon('schedule')} Cron Script", command=self._update_cron_for_job).pack(side=tk.RIGHT, padx=5)
        ttk.Button(act_frame, text=f"{icon('delete')} Delete", command=self._delete_current_job).pack(side=tk.LEFT, padx=5)
        
        # --- Scrollable Container Setup ---
        self.canvas = tk.Canvas(self.right_frame, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.right_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame_id = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def _configure_scroll_region(event):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

        def _configure_canvas_width(event):
            self.canvas.itemconfig(self.scrollable_frame_id, width=event.width)

        self.scrollable_frame.bind("<Configure>", _configure_scroll_region)
        self.canvas.bind("<Configure>", _configure_canvas_width)

        # Mousewheel binding
        def _on_mousewheel(event):
            if self.notebook.select() == str(self.tab_schedule):
                 self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        # Bind mousewheel to canvas and all children (recursively is hard, but we can bind to active frame)
        self.canvas.bind_all("<MouseWheel>", _on_mousewheel)
        # Linux might need Button-4/5
        self.canvas.bind_all("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind_all("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))

        # --- Job Details Form (Variables) ---
        self.job_var_id = tk.StringVar()
        self.job_var_name = tk.StringVar()
        self.job_var_source = tk.StringVar(value="__local__")  # NEW: Source server
        self.job_var_repo = tk.StringVar()
        self.job_var_time = tk.StringVar()
        self.job_var_freq = tk.StringVar()
        self.job_var_day = tk.StringVar()
        self.job_var_cron = tk.BooleanVar()
        self.job_var_internal = tk.BooleanVar()

        # Pruning Vars
        self.job_var_prune = tk.BooleanVar()
        self.job_var_keep_d = tk.StringVar(value="7")
        self.job_var_keep_w = tk.StringVar(value="4")
        self.job_var_keep_m = tk.StringVar(value="6")
        self.job_var_keep_last = tk.StringVar(value="0")
        
        # Use scrollable_frame as parent for all widgets
        content_parent = self.scrollable_frame

        # === SECTION 1: Job Identity ===
        identity_grp = ttk.LabelFrame(content_parent, text="Job Settings", padding=10)
        identity_grp.pack(fill=tk.X, pady=5, padx=5)
        
        # Name row
        name_row = ttk.Frame(identity_grp)
        name_row.pack(fill=tk.X, pady=3)
        ttk.Label(name_row, text="Job Name:", width=12).pack(side=tk.LEFT)
        ttk.Entry(name_row, textvariable=self.job_var_name, width=30).pack(side=tk.LEFT, padx=5)
        
        # Source Server row (NEW)
        source_row = ttk.Frame(identity_grp)
        source_row.pack(fill=tk.X, pady=3)
        ttk.Label(source_row, text="Source:", width=12).pack(side=tk.LEFT)
        self.source_combo = ttk.Combobox(source_row, textvariable=self.job_var_source, state="readonly", width=25)
        self.source_combo.pack(side=tk.LEFT, padx=5)
        self.source_combo.bind("<<ComboboxSelected>>", self._on_source_changed)
        
        ttk.Label(source_row, text="Repository:").pack(side=tk.LEFT, padx=(20, 5))
        self.repo_combo = ttk.Combobox(source_row, textvariable=self.job_var_repo, state="readonly", width=25)
        self.repo_combo.pack(side=tk.LEFT)
        
        # Populate source combo
        self._refresh_source_combo()

        # === SECTION 2: Schedule Type ===
        type_grp = ttk.LabelFrame(content_parent, text="Schedule Type", padding=10)
        type_grp.pack(fill=tk.X, pady=5, padx=5)
        
        # Two clear options
        opt_frame = ttk.Frame(type_grp)
        opt_frame.pack(fill=tk.X)
        
        # Internal timer option
        int_frame = ttk.Frame(opt_frame)
        int_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Checkbutton(int_frame, text="Internal Timer", variable=self.job_var_internal, 
                       command=self._on_internal_toggle).pack(anchor=tk.W)
        ttk.Label(int_frame, text="Runs when app is open", foreground="gray").pack(anchor=tk.W, padx=20)
        
        # Cron option
        cron_frame = ttk.Frame(opt_frame)
        cron_frame.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=5)
        ttk.Checkbutton(cron_frame, text="System Cron", variable=self.job_var_cron, 
                       command=self._on_cron_toggle).pack(anchor=tk.W)
        self.lbl_cron_status = ttk.Label(cron_frame, text="Runs in background", foreground="gray")
        self.lbl_cron_status.pack(anchor=tk.W, padx=20)

        # === SECTION 3: Schedule Time ===
        time_grp = ttk.LabelFrame(content_parent, text="When to Run", padding=10)
        time_grp.pack(fill=tk.X, pady=5, padx=5)
        
        time_row = ttk.Frame(time_grp)
        time_row.pack(fill=tk.X)
        
        # Frequency
        ttk.Label(time_row, text="Frequency:").pack(side=tk.LEFT)
        self.combo_freq = ttk.Combobox(time_row, textvariable=self.job_var_freq, 
                                       values=["Daily", "Weekly", "Monthly"], state="readonly", width=10)
        self.combo_freq.pack(side=tk.LEFT, padx=5)
        self.combo_freq.bind("<<ComboboxSelected>>", self._toggle_day_input)

        # Day (conditional)
        self.lbl_day = ttk.Label(time_row, text="Day:")
        self.combo_day = ttk.Combobox(time_row, textvariable=self.job_var_day, state="readonly", width=12)
        self.lbl_day.pack(side=tk.LEFT, padx=(20, 5))
        self.combo_day.pack(side=tk.LEFT)

        # Time
        ttk.Label(time_row, text="Time:").pack(side=tk.LEFT, padx=(20, 5))
        ttk.Entry(time_row, textvariable=self.job_var_time, width=15).pack(side=tk.LEFT)
        ttk.Label(time_row, text="(HH:MM, HH:MM...)", foreground="gray").pack(side=tk.LEFT, padx=5)
        
        # === SECTION 4: Pruning ===
        prune_grp = ttk.LabelFrame(content_parent, text="Auto-Prune After Backup", padding=10)
        prune_grp.pack(fill=tk.X, pady=5, padx=5)
        
        prune_row = ttk.Frame(prune_grp)
        prune_row.pack(fill=tk.X)
        
        ttk.Checkbutton(prune_row, text="Enable Auto-Pruning", variable=self.job_var_prune).pack(side=tk.LEFT)
        ttk.Label(prune_row, text="Keep:").pack(side=tk.LEFT, padx=(20, 5))
        
        # Last/Daily/Weekly/Monthly
        ttk.Entry(prune_row, textvariable=self.job_var_keep_last, width=3).pack(side=tk.LEFT)
        ttk.Label(prune_row, text="last").pack(side=tk.LEFT, padx=(2, 10))
        
        ttk.Entry(prune_row, textvariable=self.job_var_keep_d, width=3).pack(side=tk.LEFT)
        ttk.Label(prune_row, text="daily").pack(side=tk.LEFT, padx=(2, 10))
        
        ttk.Entry(prune_row, textvariable=self.job_var_keep_w, width=3).pack(side=tk.LEFT)
        ttk.Label(prune_row, text="weekly").pack(side=tk.LEFT, padx=(2, 10))
        
        ttk.Entry(prune_row, textvariable=self.job_var_keep_m, width=3).pack(side=tk.LEFT)
        ttk.Label(prune_row, text="monthly").pack(side=tk.LEFT, padx=2)

        # === SECTION 5: Paths ===
        list_grp = ttk.LabelFrame(content_parent, text="Backup Paths", padding=5)
        list_grp.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Interactive Browser Button
        ttk.Button(list_grp, text=f"{icon('open')} Browse", command=self.open_job_browser).pack(fill=tk.X, padx=5, pady=2)
        
        # Paths container
        paths_container = ttk.Frame(list_grp)
        paths_container.pack(fill=tk.BOTH, expand=True, pady=5)
        
        
        # Includes
        inc_f = ttk.Frame(paths_container)
        inc_f.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2)
        
        ttk.Label(inc_f, text="Include Paths:").pack()
        
        # Pack buttons FIRST (at bottom) so they don't get pushed off
        btn_inc = ttk.Frame(inc_f)
        btn_inc.pack(side=tk.BOTTOM, fill=tk.X, pady=2)
        ttk.Button(btn_inc, text=f"{icon('add')} Add", command=lambda: self.add_path(self.job_list_inc)).pack(side=tk.LEFT, expand=True, fill=tk.X)
        ttk.Button(btn_inc, text=f"{icon('remove')} Remove", command=lambda: self.remove_path(self.job_list_inc)).pack(side=tk.RIGHT, expand=True, fill=tk.X)
        
        # Then pack list (fill remaining space)
        self.job_list_inc = tk.Listbox(inc_f, height=6, bg=self.get_theme_color("bg_card"), fg=self.get_theme_color("text_main"))
        self.job_list_inc.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Excludes
        exc_f = ttk.Frame(paths_container)
        exc_f.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=2)
        
        ttk.Label(exc_f, text="Exclude Paths:").pack()
        
        # Pack buttons FIRST (at bottom)
        btn_exc = ttk.Frame(exc_f)
        btn_exc.pack(side=tk.BOTTOM, fill=tk.X, pady=2)
        ttk.Button(btn_exc, text=f"{icon('add')} Add", command=lambda: self.add_path(self.job_list_exc)).pack(side=tk.LEFT, expand=True, fill=tk.X)
        ttk.Button(btn_exc, text=f"{icon('remove')} Remove", command=lambda: self.remove_path(self.job_list_exc)).pack(side=tk.RIGHT, expand=True, fill=tk.X)
        
        # Then pack list
        self.job_list_exc = tk.Listbox(exc_f, height=6, bg=self.get_theme_color("bg_card"), fg=self.get_theme_color("text_main"))
        self.job_list_exc.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        self._refresh_job_list()
    
    def _run_selected_job_now(self):
        """Run the currently selected job immediately."""
        sel = self.job_listbox.curselection()
        if not sel:
            messagebox.showwarning("No Job Selected", "Please select a job to run.")
            return
        
        # Get job ID from selection
        idx = sel[0]
        jobs = self.config_manager.config.get("jobs", {})
        job_ids = list(jobs.keys())
        if idx < len(job_ids):
            job_id = job_ids[idx]
            if messagebox.askyesno("Run Now?", f"Run job '{jobs[job_id].get('name', 'Unknown')}' now?"):
                self._run_job_now(job_id)

    def _refresh_source_combo(self):
        """Populate source server dropdown."""
        servers = self.config_manager.get_source_servers()
        values = []
        for sid, srv in servers.items():
            name = srv.get("name", sid)
            values.append(f"{sid}|{name}")
        self.source_combo["values"] = values
        
        # Select first (Local) by default if nothing selected
        if values and not self.job_var_source.get():
            self.job_var_source.set(values[0])
        self._on_source_changed()
    
    def _on_source_changed(self, event=None):
        """Update repo dropdown based on selected source."""
        source_val = self.job_var_source.get()
        source_id = source_val.split("|")[0] if "|" in source_val else source_val
        
        srv = self.config_manager.get_source_server(source_id)
        if srv:
            # Repos are now a dict, get keys as list
            repos = list(srv.get("repos", {}).keys())
            self.repo_combo["values"] = repos
            if repos and not self.job_var_repo.get():
                self.job_var_repo.set(repos[0])
            elif repos and self.job_var_repo.get() not in repos:
                self.job_var_repo.set(repos[0])
        else:
            # Fallback to empty
            self.repo_combo["values"] = []

    def _on_internal_toggle(self):
        """Enforce mutual exclusivity: Internal -> Disable Cron"""
        if self.job_var_internal.get():
            self.job_var_cron.set(False)

    def _on_cron_toggle(self):
        """Enforce mutual exclusivity: Cron -> Disable Internal"""
        if self.job_var_cron.get():
            self.job_var_internal.set(False)

    def _toggle_day_input(self, event=None):
        freq = self.job_var_freq.get()
        if freq == "Daily":
            self.lbl_day.pack_forget()
            self.combo_day.pack_forget()
            self.job_var_day.set("")
        elif freq == "Weekly":
            self.lbl_day.config(text="Day of Week:")
            self.lbl_day.pack(side=tk.LEFT, padx=(20, 5))
            self.combo_day['values'] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
            self.combo_day.pack(side=tk.LEFT)
        elif freq == "Monthly":
            self.lbl_day.config(text="Day (1-31):")
            self.lbl_day.pack(side=tk.LEFT, padx=(20, 5))
            self.combo_day['values'] = [str(i) for i in range(1, 32)]
            self.combo_day.pack(side=tk.LEFT)

    def open_job_browser(self):
        def on_confirm(includes, excludes):
            for i in includes:
                self.job_list_inc.insert(tk.END, i)
            for e in excludes:
                self.job_list_exc.insert(tk.END, e)
            messagebox.showinfo("Imported", f"Added {len(includes)} items to Include and {len(excludes)} items to Exclude.")

        FileSelectorDialog(self, on_confirm, ssh_helper=self.active_ssh_helper)

    def _refresh_job_list(self):
        self.job_listbox.delete(0, tk.END)
        self.jobs_cache = [] # Store IDs
        for jid, job in self.config_manager.config.get("jobs", {}).items():
            self.jobs_cache.append(jid)
            name = job.get("name", "Unnamed")
            time = job.get("time", "")
            freq = job.get("frequency", "Daily")
            cron = " [CRON]" if job.get("cron_enabled") else ""
            self.job_listbox.insert(tk.END, f"{name} ({freq} @ {time}){cron}")
    
    def _create_new_job(self):
        new_id = str(uuid.uuid4())
        repo_name = self.config_manager.config.get("current_repo", "")
        if not repo_name:
             messagebox.showerror("No Repo", "Please select an Active Repository in the top bar before creating a job.")
             return

        new_job = {
            "id": new_id,
            "name": "New Backup Job",
            "repo": repo_name,
            "time": "02:00",
            "frequency": "Daily",
            "day": "",
            "internal_enabled": False,
            "cron_enabled": False,
            "includes": [],
            "excludes": [],
            "prune_enabled": False,
            "keep_daily": 7,
            "keep_weekly": 4,
            "keep_monthly": 6
        }
        self.config_manager.config["jobs"][new_id] = new_job
        self.config_manager.save_config()
        self._refresh_job_list()
        self.job_listbox.selection_set(tk.END)
        self._on_job_select(None)

    def _on_job_select(self, event):
        sel = self.job_listbox.curselection()
        if not sel: return
        
        idx = sel[0]
        job_id = self.jobs_cache[idx]
        job = self.config_manager.config["jobs"].get(job_id)
        if not job: return

        # Load into UI
        self.job_var_id.set(job_id)
        self.job_var_name.set(job["name"])
        
        # Source server (NEW) - set source first, then repo
        source_id = job.get("source", "__local__")
        servers = self.config_manager.get_source_servers()
        if source_id in servers:
            srv = servers[source_id]
            self.job_var_source.set(f"{source_id}|{srv.get('name', source_id)}")
        else:
            self.job_var_source.set("__local__|Local Machine")
        self._on_source_changed()  # Refresh repo combo
        
        self.job_var_repo.set(job.get("repo", "Unknown"))
        self.job_var_time.set(job["time"])
        self.job_var_freq.set(job.get("frequency", "Daily"))
        self.job_var_day.set(job.get("day", ""))
        self.job_var_internal.set(job.get("internal_enabled", False))
        self.job_var_cron.set(job.get("cron_enabled", False))
        
        self.job_var_prune.set(job.get("prune_enabled", False))
        self.job_var_keep_d.set(job.get("keep_daily", "7"))
        self.job_var_keep_w.set(job.get("keep_weekly", "4"))
        self.job_var_keep_m.set(job.get("keep_monthly", "6"))
        self.job_var_keep_last.set(job.get("keep_last", "0"))
        
        self._toggle_day_input()

        # Load Lists
        self.job_list_inc.delete(0, tk.END)
        for i in job.get("includes", []): self.job_list_inc.insert(tk.END, i)
        
        self.job_list_exc.delete(0, tk.END)
        for e in job.get("excludes", []): self.job_list_exc.insert(tk.END, e)

        # Check Script Existence
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', job["name"])
        script_path = os.path.join(SCRIPTS_DIR, f"job_{job_id}_{safe_name}.sh")
        if os.path.exists(script_path):
             self.lbl_cron_status.config(text="Script Generated")
        else:
             self.lbl_cron_status.config(text="(Script missing)")

    def _save_current_job(self):
        job_id = self.job_var_id.get()
        if not job_id: return

        job = self.config_manager.config["jobs"].get(job_id, {})
        
        # Check if time changed - if so, clear last_run to allow re-running today
        old_time = job.get("time", "")
        new_time = self.job_var_time.get()
        if old_time != new_time:
            job["last_run"] = None  # Clear so it can run today with new time
        
        job["name"] = self.job_var_name.get()
        
        # Set repo if not already set (for new jobs from manual backup)
        if not job.get("repo") or job.get("repo") == "None":
            repo_from_ui = self.job_var_repo.get()
            if repo_from_ui and repo_from_ui != "Unknown":
                job["repo"] = repo_from_ui
            else:
                # Fallback to current active repo
                job["repo"] = self.config_manager.config.get("current_repo", "")
        
        job["time"] = new_time
        job["frequency"] = self.job_var_freq.get()
        job["day"] = self.job_var_day.get()
        
        # Source server - default to active if not set
        source_val = self.job_var_source.get()
        if source_val and "|" in source_val:
            job["source"] = source_val.split("|")[0]
        elif source_val:
            job["source"] = source_val
        else:
            job["source"] = self.active_source_id or "__local__"
        
        # Repo - default to current_repo if not set
        repo_val = self.job_var_repo.get()
        if repo_val and repo_val not in ("Unknown", "None", ""):
            job["repo"] = repo_val
        else:
            job["repo"] = self.config_manager.config.get("current_repo", "")
        
        job["internal_enabled"] = self.job_var_internal.get()
        job["cron_enabled"] = self.job_var_cron.get()
        job["includes"] = list(self.job_list_inc.get(0, tk.END))
        job["excludes"] = list(self.job_list_exc.get(0, tk.END))
        
        # Pruning fields
        job["prune_enabled"] = self.job_var_prune.get()
        job["keep_daily"] = self.job_var_keep_d.get()
        job["keep_weekly"] = self.job_var_keep_w.get()
        job["keep_monthly"] = self.job_var_keep_m.get()
        job["keep_last"] = self.job_var_keep_last.get()

        # SAFETY: If Internal is enabled, force disable Cron system-side
        if job["internal_enabled"]:
            if job["cron_enabled"]: # It should be False by UI logic, but double check
                job["cron_enabled"] = False
            
            # Ensure no stale cron job exists for this ID
            try:
                CronManager.update_crontab(job_id, "", "", enable=False, ssh_helper=self.active_ssh_helper)
                self.lbl_cron_status.config(text="Cron Removed (Internal Active)")
            except: pass
        
        self.config_manager.save_job(job)
        self._refresh_job_list()
        
        # Refresh dashboard upcoming schedules
        if hasattr(self, '_refresh_upcoming_schedules'):
            self._refresh_upcoming_schedules()
        
        messagebox.showinfo("Saved", "Job settings saved.")
        self.log(f"User updated Job: {job['name']}", "AUDIT")

    def _delete_current_job(self):
        job_id = self.job_var_id.get()
        if not job_id: return
        if messagebox.askyesno("Delete", "Delete this job? This will also remove it from Cron if installed."):
            # Try remove from cron first
            try:
                CronManager.update_crontab(job_id, "", "", enable=False, ssh_helper=self.active_ssh_helper)
            except: pass
            
            self.config_manager.delete_job(job_id)
            self._refresh_job_list()
            # Clear UI fields?
            self.job_var_id.set("")
            self.job_var_name.set("")
            self.log(f"User deleted Job ID: {job_id}", "AUDIT")

    def _update_cron_for_job(self):
        self._save_current_job() # Ensure data is fresh
        job_id = self.job_var_id.get()
        job = self.config_manager.config["jobs"].get(job_id)
        
        repo_config = self.config_manager.get_repo_details(job["repo"])
        if not repo_config:
            messagebox.showerror("Error", "Repository configuration not found. Cannot generate script.")
            return

        try:
            # 1. Generate Script
            script_path = CronManager.generate_job_script(
                job, 
                repo_config, 
                self.config_manager.config.get("borg_binary", "borg"),
                ssh_helper=self.active_ssh_helper
            )
            
            # 2. Update Crontab
            if job["cron_enabled"]:
                success = CronManager.update_crontab(
                    job_id, 
                    script_path, 
                    job["time"], 
                    frequency=job.get("frequency", "Daily"),
                    day=job.get("day", ""),
                    enable=True,
                    ssh_helper=self.active_ssh_helper
                )
                if success:
                    messagebox.showinfo("Success", f"Script generated at:\n{script_path}\n\nCron job UPDATED successfully.")
                else:
                    messagebox.showerror("Error", "Failed to update crontab. Check terminal/permissions.")
            else:
                # Remove from cron if disabled
                CronManager.update_crontab(job_id, script_path, "", enable=False, ssh_helper=self.active_ssh_helper)
                messagebox.showinfo("Success", f"Script generated at:\n{script_path}\n\nCron job REMOVED (as per checkbox).")
            
            self.log(f"User updated Cron for Job: {job['name']}", "AUDIT")
            self.lbl_cron_status.config(text="Script Updated")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update cron: {e}")

    # --- QUEUE TAB ---
    def _build_queue_tab(self):
        frame = ttk.Frame(self.tab_queue, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        ttk.Label(frame, text="Job Queue Manager", font=("", 14, "bold")).pack(pady=10)
        ttk.Label(frame, text="Jobs waiting for execution (FIFO)", foreground="gray").pack(pady=(0, 10))
        
        # Queue List
        cols = ("Job Name", "Repository", "Scheduled Time", "Added At")
        self.queue_tree = ttk.Treeview(frame, columns=cols, show='headings', height=15)
        
        self.queue_tree.heading("Job Name", text="Job Name")
        self.queue_tree.heading("Repository", text="Repository")
        self.queue_tree.heading("Scheduled Time", text="Scheduled For")
        self.queue_tree.heading("Added At", text="Added At")
        
        self.queue_tree.column("Job Name", width=200)
        self.queue_tree.column("Repository", width=200)
        self.queue_tree.column("Scheduled Time", width=120)
        self.queue_tree.column("Added At", width=120)
        
        self.queue_tree.pack(fill=tk.BOTH, expand=True)
        
        # Buttons
        btn_frame = ttk.Frame(frame, padding=10)
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(btn_frame, text=f"{icon('start')} Run Selected Now", command=self._force_run_queued).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=f"{icon('delete')} Remove Selected", command=self._remove_queued_job).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=f"{icon('close')} Clear Queue", command=self._clear_queue).pack(side=tk.RIGHT, padx=5)
        
        self._refresh_queue_ui()
        
    def _refresh_queue_ui(self):
        if not hasattr(self, 'queue_tree'): return
        
        # Clear
        for item in self.queue_tree.get_children():
            self.queue_tree.delete(item)
            
        # Display Running Job First
        if self.is_running:
            task_name = getattr(self, 'current_task_name', 'Running Task') or "Task"
            self.queue_tree.insert('', tk.END, iid="running", values=(
                f"▶ {task_name}",
                "Active",
                "Now",
                datetime.datetime.now().strftime("%H:%M:%S")
            ))

        # Populate
        for i, job in enumerate(self.job_queue):
            self.queue_tree.insert('', tk.END, iid=i, values=(
                job.get('name'),
                job.get('repo'),
                job.get('trigger_time'),
                job.get('added_at')
            ))
            
    def _force_run_queued(self):
        sel = self.queue_tree.selection()
        if not sel: return
        idx = int(sel[0])
        if idx < len(self.job_queue):
            job = self.job_queue.pop(idx)
            self._run_job_now(job['id'])
            self._refresh_queue_ui()
            
    def _remove_queued_job(self):
        sel = self.queue_tree.selection()
        if not sel: return
        idx = int(sel[0])
        if idx < len(self.job_queue):
            del self.job_queue[idx]
            self._refresh_queue_ui()
            
    def _clear_queue(self):
        if messagebox.askyesno("Clear Queue", "Remove all pending jobs?"):
            self.job_queue.clear()
            self._refresh_queue_ui()

    # --- MAINTENANCE & LOGS ---

    def _build_maintenance_tab(self):
        frame = ttk.Frame(self.tab_maintenance, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Prune Group (Manual)
        prune_frame = ttk.LabelFrame(frame, text="Manual Prune (For Active Repo)")
        prune_frame.pack(fill=tk.X, pady=10)
        
        grid_f = ttk.Frame(prune_frame)
        grid_f.pack(padx=10, pady=10)
        
        self.keep_daily = tk.StringVar(value="7")
        self.keep_weekly = tk.StringVar(value="4")
        self.keep_monthly = tk.StringVar(value="6")
        
        ttk.Label(grid_f, text="Keep Daily:").grid(row=0, column=0, padx=5)
        ttk.Entry(grid_f, textvariable=self.keep_daily, width=5).grid(row=0, column=1)
        
        ttk.Label(grid_f, text="Keep Weekly:").grid(row=0, column=2, padx=5)
        ttk.Entry(grid_f, textvariable=self.keep_weekly, width=5).grid(row=0, column=3)
        
        ttk.Label(grid_f, text="Keep Monthly:").grid(row=0, column=4, padx=5)
        ttk.Entry(grid_f, textvariable=self.keep_monthly, width=5).grid(row=0, column=5)

        ttk.Button(prune_frame, text=f"{icon('prune')} Run Prune (Dry Run First)", command=self.run_prune).pack(pady=5)

        # Other Tools
        tools_frame = ttk.LabelFrame(frame, text="Other Tools")
        tools_frame.pack(fill=tk.X, pady=10)
        ttk.Button(tools_frame, text=f"{icon('info')} Check Integrity", command=self.run_check).pack(side=tk.LEFT, padx=10, pady=10)
        ttk.Button(tools_frame, text=f"{icon('archive')} Compact (Free Space)", command=self.run_compact).pack(side=tk.LEFT, padx=10, pady=10)
        ttk.Button(tools_frame, text=f"{icon('info')} Inspect Lock Owner", command=self.inspect_lock_owner).pack(side=tk.LEFT, padx=10, pady=10)
        ttk.Button(tools_frame, text=f"{icon('lock')} Break Lock", command=self.run_break_lock).pack(side=tk.LEFT, padx=10, pady=10)
        
        # Log Management
        log_frame = ttk.LabelFrame(frame, text="Log Management")
        log_frame.pack(fill=tk.X, pady=10)
        ttk.Button(log_frame, text=f"{icon('settings')} Configure Log Retention", command=self.open_log_settings).pack(side=tk.LEFT, padx=10, pady=10)
        ttk.Button(log_frame, text=f"{icon('open')} View Logs Folder", command=lambda: self.open_folder(LOGS_DIR)).pack(side=tk.LEFT, padx=10)

    def open_folder(self, path):
        if platform.system() == "Darwin": subprocess.run(["open", path])
        elif platform.system() == "Linux": subprocess.run(["xdg-open", path])
        elif platform.system() == "Windows": os.startfile(path)

    def open_log_settings(self):
        win = tk.Toplevel(self)
        win.title("Log Retention Settings")
        win.geometry("400x250")
        win.configure(bg=self.get_theme_color("bg_window"))
        
        current = self.config_manager.config.get("log_settings", {})
        v_active = tk.StringVar(value=str(current.get("active_days", 7)))
        v_archive = tk.StringVar(value=str(current.get("archive_days", 90)))
        
        ttk.Label(win, text="Active Logs (Text format)").pack(pady=(15, 5))
        f1 = ttk.Frame(win); f1.pack()
        ttk.Label(f1, text="Keep active for (days):").pack(side=tk.LEFT)
        ttk.Entry(f1, textvariable=v_active, width=5).pack(side=tk.LEFT, padx=5)

        ttk.Label(win, text="Archived Logs (Compressed .gz)").pack(pady=(15, 5))
        f2 = ttk.Frame(win); f2.pack()
        ttk.Label(f2, text="Keep archives for (days):").pack(side=tk.LEFT)
        ttk.Entry(f2, textvariable=v_archive, width=5).pack(side=tk.LEFT, padx=5)
        
        def save():
            try:
                ad = int(v_active.get())
                ar = int(v_archive.get())
                self.config_manager.config["log_settings"] = {"active_days": ad, "archive_days": ar}
                self.config_manager.save_config()
                self.log("User updated Log Retention Settings", "AUDIT")
                messagebox.showinfo("Saved", "Settings saved. Applied on next restart.")
                win.destroy()
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numbers.")

        ttk.Button(win, text="Save Settings", command=save).pack(pady=20)

    def _build_logs_tab(self):
        main_frame = ttk.Frame(self.tab_logs)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- PROGRESS PANEL (Collapsible) ---
        self.progress_frame = ttk.LabelFrame(main_frame, text="🔄 Backup Progress", padding=10)
        self.progress_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Progress Variables
        self.var_progress_status = tk.StringVar(value="Idle")
        self.var_progress_elapsed = tk.StringVar(value="00:00:00")
        self.var_progress_files = tk.StringVar(value="0 files")
        self.var_progress_original = tk.StringVar(value="0 B")
        self.var_progress_compressed = tk.StringVar(value="0 B")
        self.var_progress_dedup = tk.StringVar(value="0 B")
        self.var_progress_current = tk.StringVar(value="--")
        
        # Top row: Status and Time
        top_row = ttk.Frame(self.progress_frame)
        top_row.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(top_row, text="Status:").pack(side=tk.LEFT)
        self.lbl_progress_status = ttk.Label(top_row, textvariable=self.var_progress_status, 
                                              foreground="gray")
        self.lbl_progress_status.pack(side=tk.LEFT, padx=(5, 20))
        
        ttk.Label(top_row, text="Elapsed:").pack(side=tk.LEFT)
        ttk.Label(top_row, textvariable=self.var_progress_elapsed,
                 foreground="#2196F3").pack(side=tk.LEFT, padx=5)
        
        # Middle row: Metrics
        metrics_row = ttk.Frame(self.progress_frame)
        metrics_row.pack(fill=tk.X, pady=5)
        
        # Files
        f1 = ttk.Frame(metrics_row)
        f1.pack(side=tk.LEFT, padx=10)
        ttk.Label(f1, text="Files:").pack(side=tk.LEFT)
        ttk.Label(f1, textvariable=self.var_progress_files).pack(side=tk.LEFT, padx=3)
        
        # Original (O)
        f2 = ttk.Frame(metrics_row)
        f2.pack(side=tk.LEFT, padx=10)
        ttk.Label(f2, text="Original:").pack(side=tk.LEFT)
        ttk.Label(f2, textvariable=self.var_progress_original, 
                 foreground="#4CAF50").pack(side=tk.LEFT, padx=3)
        
        # Compressed (C)
        f3 = ttk.Frame(metrics_row)
        f3.pack(side=tk.LEFT, padx=10)
        ttk.Label(f3, text="Compressed:").pack(side=tk.LEFT)
        ttk.Label(f3, textvariable=self.var_progress_compressed,
                 foreground="#FF9800").pack(side=tk.LEFT, padx=3)
        
        # Deduplicated (D)
        f4 = ttk.Frame(metrics_row)
        f4.pack(side=tk.LEFT, padx=10)
        ttk.Label(f4, text="Dedup:").pack(side=tk.LEFT)
        ttk.Label(f4, textvariable=self.var_progress_dedup,
                 foreground="#9C27B0").pack(side=tk.LEFT, padx=3)
        
        # Bottom row: Current file
        current_row = ttk.Frame(self.progress_frame)
        current_row.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Label(current_row, text="Current:").pack(side=tk.LEFT)
        self.lbl_current_file = ttk.Label(current_row, textvariable=self.var_progress_current, 
                                          foreground="#666")
        self.lbl_current_file.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Progress tracking state
        self.progress_start_time = None
        self.progress_timer_id = None
        
        # --- LOG TEXT AREA ---
        log_container = ttk.Frame(main_frame)
        log_container.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = tk.Text(log_container, bg="black", fg="white")
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scroll = ttk.Scrollbar(log_container, command=self.log_text.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scroll.set)
        
        # Tags for coloring
        self.log_text.tag_config("INFO", foreground="cyan")
        self.log_text.tag_config("ERROR", foreground="red")
        self.log_text.tag_config("SUCCESS", foreground="lightgreen")
        self.log_text.tag_config("AUDIT", foreground="orange")
        self.log_text.tag_config("SYSTEM", foreground="gray")
    
    def _start_progress_timer(self):
        """Start the elapsed time counter for backup progress."""
        self.progress_start_time = time.time()
        self.var_progress_status.set("Running...")
        self.lbl_progress_status.config(foreground="#4CAF50")
        self._update_progress_timer()
    
    def _update_progress_timer(self):
        """Update the elapsed time display."""
        if self.progress_start_time is None:
            return
        elapsed = int(time.time() - self.progress_start_time)
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        self.var_progress_elapsed.set(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        self.progress_timer_id = self.after(1000, self._update_progress_timer)
    
    def _stop_progress_timer(self, success=True):
        """Stop the elapsed time counter."""
        if self.progress_timer_id:
            self.after_cancel(self.progress_timer_id)
            self.progress_timer_id = None
        self.progress_start_time = None
        if success:
            self.var_progress_status.set("Completed")
            self.lbl_progress_status.config(foreground="#4CAF50")
        else:
            self.var_progress_status.set("Failed")
            self.lbl_progress_status.config(foreground="#F44336")
    
    def _reset_progress(self):
        """Reset progress panel to initial state."""
        self.var_progress_status.set("Idle")
        self.lbl_progress_status.config(foreground="gray")
        self.var_progress_elapsed.set("00:00:00")
        self.var_progress_files.set("0 files")
        self.var_progress_original.set("0 B")
        self.var_progress_compressed.set("0 B")
        self.var_progress_dedup.set("0 B")
        self.var_progress_current.set("--")

    # --- LOGIC & COMMANDS ---

    def log(self, message, level="INFO"):
        # 1. Update GUI
        try:
            self.log_text.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}\n", level)
            self.log_text.see(tk.END)
        except: pass
        
        # 2. Write to File
        if hasattr(self, 'log_manager'):
            self.log_manager.write(message, level)

    def get_env(self):
        # Default env getter uses the CURRENTLY SELECTED repo in top bar
        name, details = self.config_manager.get_current_repo_details()
        if not details: return None
        return self._build_env_for_repo(details)

    def run_borg_thread(self, cmd_list, env_override=None, on_complete=None, stream_output=True, task_name="Task", force_local=False):
        if self.is_running:
            self.log("BUSY: Cannot start new process, one is already running.", "ERROR")
            return

        self.current_task_name = task_name # Track name for Queue UI
        env = env_override if env_override else self.get_env()
        
        # Check if running remotely
        use_ssh = self.active_ssh_helper is not None and not force_local

        # Determine if this is a backup/create operation (to enable progress tracking)
        # Check substrings in case of complex commands (e.g. ssh ... 'borg create')
        is_backup_op = any("create" in str(arg) for arg in cmd_list)
        
        # Capture task name before thread starts (will be cleared in finally block)
        captured_task_name = task_name

        def target():
            self.is_running = True
            start_time = datetime.datetime.now()  # Track start time for all operations
            
            if self.state() == "normal": 
                if self.notebook.select() != self.tab_dashboard:
                    self.notebook.select(self.tab_logs)
            
            # Build command string for SSH or list for local
            if use_ssh:
                # Convert cmd_list to string, using 'borg' as binary on remote
                cmd_parts = []
                for arg in cmd_list:
                    if arg == self.borg_bin:
                        cmd_parts.append("borg")
                    else:
                        # Quote arguments with spaces
                        if " " in arg or "'" in arg:
                            cmd_parts.append(f'"{arg}"')
                        else:
                            cmd_parts.append(arg)
                
                cmd_str = " ".join(cmd_parts)
                
                # Add environment variables for repo
                if env:
                    env_exports = []
                    # Critical: Export SSHPASS if used (required for sshpass -e)
                    if env.get("SSHPASS"):
                        env_exports.append(f"export SSHPASS='{env['SSHPASS']}'")
                    if env.get("BORG_REPO"):
                        env_exports.append(f"export BORG_REPO='{env['BORG_REPO']}'")
                    if env.get("BORG_PASSPHRASE"):
                        env_exports.append(f"export BORG_PASSPHRASE='{env['BORG_PASSPHRASE']}'")
                    if env.get("BORG_PASSCOMMAND"):
                        env_exports.append(f"export BORG_PASSCOMMAND='{env['BORG_PASSCOMMAND']}'")
                    if env.get("BORG_RSH"):
                        env_exports.append(f"export BORG_RSH='{env['BORG_RSH']}'")
                    
                    if env_exports:
                        cmd_str = " && ".join(env_exports) + " && " + cmd_str
                
                self.log(f"[SSH] Running: {cmd_str[:100]}...", "INFO")
            else:
                self.log(f"Running: {' '.join(cmd_list)}", "INFO")
            
            # Start progress tracking for backup operations
            if is_backup_op:
                job_name = "Manual Backup"
                for arg in cmd_list:
                    if "::" in arg:
                        job_name = arg.split("::")[-1]
                        break
                
                self.after(0, self._reset_running_backup_ui) 
                self.after(0, lambda: self._update_running_backup_ui(job_name))
                self.after(0, self._start_progress_timer)
            
            success = False
            try:
                if use_ssh:
                    # Execute via SSH
                    def log_callback(line):
                        if is_backup_op:
                            self.after(0, lambda l=line: self._parse_borg_progress(l))
                            
                        # Clean up formatting for readability
                        # Split by \r (carriage return) which acts as a reset for progress bars
                        parts = re.split(r'[\r\n]+', line)
                        for part in parts:
                            if not part.strip(): continue
                            self.after(0, lambda p=part: self.log_text.insert(tk.END, p + "\n"))
                            self.after(0, lambda: self.log_text.see(tk.END))
                    
                    success, error = self.active_ssh_helper.execute_stream(cmd_str, log_callback)
                    if not success and error:
                        self.log(f"SSH Error: {error}", "ERROR")
                else:
                    # Local execution
                    process = subprocess.Popen(
                        cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                        stdin=subprocess.DEVNULL, env=env, text=True, bufsize=1, universal_newlines=True
                    )
                    self.current_process = process
                    if stream_output:
                        for line in process.stdout:
                            if is_backup_op:
                                self.after(0, lambda l=line: self._parse_borg_progress(l))
                            self.log_text.insert(tk.END, line)
                            self.log_text.see(tk.END)
                    process.wait()
                    success = process.returncode == 0
                
                if success: 
                    self.log("Operation Completed Successfully.", "SUCCESS")
                else: 
                    self.log("Operation Failed.", "ERROR")
            except Exception as e:
                self.after(0, lambda: self.log(f"Error starting thread: {e}", "ERROR"))
            finally:
                self.is_running = False
                self.current_task_name = None # Clear task name
                self.after(0, self._process_queue) # Check for next job
                
                # Update UI elements
                # Update UI elements
                # self.after(0, self._update_status_indicator) # Method does not exist
                if hasattr(self, '_refresh_queue_ui'):
                    self.after(0, self._refresh_queue_ui)
                
                # Record History FIRST (before reset) - must schedule on main thread for StringVar access
                # Then stop progress and reset UI
                if is_backup_op:
                    # Capture elapsed time now (in thread context)
                    if hasattr(self, 'elapsed_seconds') and self.elapsed_seconds > 0:
                        duration_sec = self.elapsed_seconds
                    else:
                        duration_sec = 0
                    
                    m, s = divmod(duration_sec, 60)
                    h, m = divmod(m, 60)
                    duration_str = f"{h:02d}:{m:02d}:{s:02d}"
                    
                    status = "Success" if success else "Failed"
                    start_time_str = start_time.strftime("%Y-%m-%d %H:%M")
                    
                    # Schedule stats capture and history save on main thread BEFORE reset
                    self.after(0, lambda dur=duration_str, st=status, name=captured_task_name, stime=start_time_str: 
                               self._save_backup_history(dur, st, name, stime))
                    self.after(50, lambda: self._stop_progress_timer(success))
                    self.after(100, self._reset_running_backup_ui)
                else:
                    # Non-backup operations - simpler history
                    try:
                        status = "Success" if success else "Failed"
                        repo_name = self.config_manager.config.get("current_repo", "Unknown")
                        
                        # Calculate duration from start_time
                        end_time = datetime.datetime.now()
                        duration_sec = int((end_time - start_time).total_seconds())
                        m, s = divmod(duration_sec, 60)
                        h, m = divmod(m, 60)
                        duration_str = f"{h:02d}:{m:02d}:{s:02d}"
                        
                        start_time_str = start_time.strftime("%Y-%m-%d %H:%M")
                        
                        self.config_manager.add_history_entry(
                            captured_task_name, repo_name, status, duration_str, start_time_str, {},
                            source=self.active_source_id
                        )
                        if hasattr(self, '_refresh_history'):
                            self.after(0, self._refresh_history)
                    except Exception as e:
                        logger.error(f"Error saving non-backup history: {e}")
                        
                if on_complete: self.after(0, on_complete)
        threading.Thread(target=target, daemon=True).start()

    def run_borg_quick(self, cmd_list):
        env = self.get_env()
        if not env: return False, "Environment setup failed"
        
        # Check for remote execution
        if self.active_ssh_helper:
            # Build remote command
            cmd_parts = []
            for arg in cmd_list:
                if arg == self.borg_bin:
                    cmd_parts.append("borg")
                else:
                    # Simple quoting for safety
                    if " " in arg or "'" in arg or '"' in arg:
                        cmd_parts.append(f"'{arg}'")
                    else:
                        cmd_parts.append(arg)
            cmd_str = " ".join(cmd_parts)
            
            # Add env vars inline for the SSH command (simpler than full session)
            prefixes = []
            if env.get("BORG_REPO"):
                prefixes.append(f"export BORG_REPO='{env['BORG_REPO']}'")
            if env.get("BORG_PASSPHRASE"):
                prefixes.append(f"export BORG_PASSPHRASE='{env['BORG_PASSPHRASE']}'")
            elif env.get("BORG_PASSCOMMAND"):
                prefixes.append(f"export BORG_PASSCOMMAND='{env['BORG_PASSCOMMAND']}'")
            if env.get("SSHPASS"):
                 prefixes.append(f"export SSHPASS='{env['SSHPASS']}'")
            
            full_cmd = "; ".join(prefixes + [cmd_str])
            
            success, stdout, stderr = self.active_ssh_helper.execute(full_cmd, timeout=30)
            if not success:
                return False, stderr if stderr else stdout
            return True, stdout
            
        try:
            result = subprocess.run(cmd_list, capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
            if result.returncode != 0: return False, result.stderr
            return True, result.stdout
        except Exception as e: return False, str(e)

    # --- This contains the logic to detect if the repo is local or remote (SSH) and fetch the specific hardware stats (Uptime, RAM, Disk). ---
    def _fetch_server_stats(self):
        """Fetch stats from the SOURCE SERVER (not repo server).
        
        When running remotely, this shows the source server's stats.
        When running locally, this shows the local machine's stats.
        """
        # Reset UI placeholders
        self.after(0, lambda: [
            self.var_server_host.set("Loading..."),
            self.var_server_uptime.set("..."),
            self.var_server_mem.set("..."),
            self.var_server_disk.set("...")
        ])
        
        hostname, uptime, mem, disk = "Unknown", "N/A", "N/A", "N/A"
        
        if self.active_ssh_helper:
            # --- REMOTE SOURCE SERVER MODE ---
            # Get stats from the SOURCE server via SSH helper
            remote_cmd = (
                "echo '---HOST---'; hostname; "
                "echo '---UP---'; uptime -p 2>/dev/null || uptime; "
                "echo '---MEM---'; free -m | grep Mem; "
                "echo '---DISK---'; df -h / | tail -1"
            )
            
            try:
                success, stdout, stderr = self.active_ssh_helper.execute(remote_cmd, timeout=10)
                if success and stdout:
                    out = stdout
                    if "---HOST---" in out: 
                        hostname = out.split("---HOST---")[1].split("---UP---")[0].strip()
                    if "---UP---" in out: 
                        uptime = out.split("---UP---")[1].split("---MEM---")[0].strip().replace("up ", "")
                    if "---MEM---" in out:
                        m_line = out.split("---MEM---")[1].split("---DISK---")[0].strip().split()
                        if len(m_line) >= 3:
                            t, u = int(m_line[1]), int(m_line[2])
                            mem = f"{int((u/t)*100)}% ({u}M/{t}M)"
                    if "---DISK---" in out:
                        d_line = out.split("---DISK---")[1].strip().split()
                        if len(d_line) >= 5: 
                            disk = f"{d_line[4]} used"
                else:
                    hostname = "SSH Error"
            except Exception as e: 
                hostname = "Conn Error"
                logger.error(f"Stats fetch error: {e}")
        else:
            # --- LOCAL MODE ---
            hostname = platform.node()
            
            try:
                if platform.system() == "Linux":
                    with open('/proc/uptime', 'r') as f:
                        seconds = int(float(f.readline().split()[0]))
                        uptime = str(datetime.timedelta(seconds=seconds))
                else: 
                    uptime = "N/A (Win)"
            except: pass

            try:
                if platform.system() == "Linux":
                    res = subprocess.run(["free", "-m"], capture_output=True, text=True)
                    m_parts = res.stdout.splitlines()[1].split()
                    t, u = int(m_parts[1]), int(m_parts[2])
                    mem = f"{int((u/t)*100)}% ({u}M/{t}M)"
            except: pass
            
            try:
                res = subprocess.run(["df", "-h", "/"], capture_output=True, text=True)
                disk = res.stdout.splitlines()[-1].split()[4] + " used"
            except: pass

        # Update UI on Main Thread
        self.after(0, lambda: [
            self.var_server_host.set(hostname),
            self.var_server_uptime.set(uptime),
            self.var_server_mem.set(mem),
            self.var_server_disk.set(disk)
        ])

    def _fetch_repo_server_stats(self):
        """Fetch disk stats from the REPO SERVER (where backups are stored).
        
        This requires SSH access to the repo server and runs df to get disk info.
        """
        # Reset placeholders
        self.after(0, lambda: [
            self.var_repo_disk.set("Loading..."),
            self.var_repo_disk_detail.set("...")
        ])
        
        name, details = self.config_manager.get_current_repo_details()
        if not details:
            self.after(0, lambda: [
                self.var_repo_disk.set("N/A"),
                self.var_repo_disk_detail.set("No repo")
            ])
            return
        
        path = details.get("path", "")
        
        # Parse repo host from path (ssh://user@host/path)
        ssh_pattern = re.compile(r"ssh://([^@]+)@([^/:]+)(?::(\d+))?(/.*)") 
        match = ssh_pattern.match(path)
        
        if not match:
            # Local repo - get local disk stats
            try:
                if platform.system() == "Windows":
                    import ctypes
                    free_bytes = ctypes.c_ulonglong(0)
                    total_bytes = ctypes.c_ulonglong(0)
                    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                        ctypes.c_wchar_p(path[:3]), None, ctypes.pointer(total_bytes), ctypes.pointer(free_bytes)
                    )
                    used_bytes = total_bytes.value - free_bytes.value
                    used_pct = int((used_bytes / total_bytes.value) * 100) if total_bytes.value else 0
                    detail = f"{format_bytes(used_bytes)} / {format_bytes(total_bytes.value)}"
                    self.after(0, lambda: [
                        self.var_repo_disk.set(f"{used_pct}% used"),
                        self.var_repo_disk_detail.set(detail)
                    ])
                else:
                    res = subprocess.run(["df", "-h", path], capture_output=True, text=True)
                    parts = res.stdout.splitlines()[-1].split()
                    if len(parts) >= 5:
                        # parts: Filesystem Size Used Avail Use% Mounted
                        used = parts[2]
                        total = parts[1]
                        pct = parts[4]
                        self.after(0, lambda: [
                            self.var_repo_disk.set(f"{pct} used"),
                            self.var_repo_disk_detail.set(f"{used} / {total}")
                        ])
            except Exception as e:
                logger.error(f"Local disk stats error: {e}")
            return
        
        # SSH repo - use SOURCE SERVER to connect to repo server
        user, host, port, remote_path = match.groups()
        
        if not self.active_ssh_helper:
            self.after(0, lambda: [
                self.var_repo_disk.set("N/A"),
                self.var_repo_disk_detail.set("No source"),
                self.var_repo_mem.set("N/A"),
                self.var_repo_mem_detail.set("No source")
            ])
            return
        
        def worker():
            disk_pct = "Error"
            disk_detail = "Error"
            mem_pct = "Error"
            mem_detail = "Error"
            
            try:
                # Build SSH command to run FROM source server TO repo server
                # Get both disk and RAM stats in one SSH call
                port_arg = f"-p {port}" if port else ""
                ssh_cmd = (
                    f"ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 {port_arg} {user}@{host} "
                    f"'echo DISK; df -h {remote_path} | tail -1; echo MEM; free -m | grep Mem' 2>/dev/null"
                )
                
                success, stdout, stderr = self.active_ssh_helper.execute(ssh_cmd, timeout=15)
                
                if success and stdout:
                    # Parse disk stats
                    if "DISK" in stdout and "MEM" in stdout:
                        disk_part = stdout.split("MEM")[0].replace("DISK", "").strip()
                        mem_part = stdout.split("MEM")[1].strip()
                        
                        # Disk parsing
                        parts = disk_part.split()
                        if len(parts) >= 5:
                            used = parts[2]
                            total = parts[1]
                            disk_pct = f"{parts[4]} used"
                            disk_detail = f"{used} / {total}"
                        
                        # RAM parsing: Mem: total used free shared buff/cache available
                        m_parts = mem_part.split()
                        if len(m_parts) >= 3:
                            t, u = int(m_parts[1]), int(m_parts[2])
                            pct = int((u / t) * 100) if t > 0 else 0
                            mem_pct = f"{pct}%"
                            mem_detail = f"{u}M / {t}M"
                else:
                    disk_pct = "N/A"
                    disk_detail = "SSH error"
                    mem_pct = "N/A"
                    mem_detail = "SSH error"
            except Exception as e:
                logger.error(f"Repo server stats error: {e}")
                disk_pct = "N/A"
                disk_detail = "Error"
                mem_pct = "N/A"
                mem_detail = "Error"
            
            self.after(0, lambda: [
                self.var_repo_disk.set(disk_pct),
                self.var_repo_disk_detail.set(disk_detail),
                self.var_repo_mem.set(mem_pct),
                self.var_repo_mem_detail.set(mem_detail)
            ])
        
        threading.Thread(target=worker, daemon=True).start()

    # --- SPECIFIC ACTIONS (Archives, Repo, etc) ---

    def refresh_repo_display(self):
        # Update source label
        if hasattr(self, 'source_label'):
            if self.active_source_id:
                srv = self.config_manager.get_source_server(self.active_source_id)
                source_name = srv.get("name", self.active_source_id) if srv else self.active_source_id
                if self.active_source_id == "__local__":
                    source_name = "Local Machine"
                self.source_label.config(text=source_name)
            else:
                self.source_label.config(text="None")
        
        # Update repo label
        name, _ = self.config_manager.get_current_repo_details()
        text = name if name else "None Selected"
        self.repo_label.config(text=text)
        
        # Update dashboard label (remove duplicate - just show repo there)
        if hasattr(self, 'dash_repo_label'):
            self.dash_repo_label.config(text=text)
        
        if name:
            self.run_info()
            self.refresh_archives()

    def run_info(self):
        """Runs borg info --json and parses it for the dashboard."""
        # 1. Clear text immediately to show we are working (if text widget exists)
        if hasattr(self, 'dash_info_text'):
            self.dash_info_text.config(state=tk.NORMAL)
            self.dash_info_text.delete(1.0, tk.END)
            self.dash_info_text.insert(tk.END, "Loading info...\n")
            self.dash_info_text.config(state=tk.DISABLED)

        # 2. Trigger Server Stats (The new feature)
        # This runs in its own thread so it doesn't block
        threading.Thread(target=self._fetch_server_stats, daemon=True).start()
        
        # 2b. Trigger Repo Server Stats (disk space on backup destination)
        threading.Thread(target=self._fetch_repo_server_stats, daemon=True).start()

        # 3. Define the Borg Info Worker (Internal function, fixes the AttributeError)
        def worker():
            # A. Basic Info (Text for detail view)
            success_text, out_text = self.run_borg_quick([self.borg_bin, "info"])
            
            # B. Stats (JSON)
            success_json, out_json = self.run_borg_quick([self.borg_bin, "info", "--json"])
            
            # C. Archives List (for count and last backup time check)
            success_list, out_list = self.run_borg_quick([self.borg_bin, "list", "--json", "--last", "1"])

            # D. Update UI on Main Thread
            def update_ui():
                # --- Update Raw Text & Health Status ---
                if success_text:
                    if hasattr(self, 'dash_info_text'):
                        self.dash_info_text.config(state=tk.NORMAL)
                        self.dash_info_text.delete(1.0, tk.END)
                        self.dash_info_text.insert(tk.END, out_text)
                        self.dash_info_text.config(state=tk.DISABLED)
                    self.var_health.set("ONLINE")
                    self.var_health_desc.set("Repository accessible")
                    if hasattr(self, 'dash_repo_label'):
                        self.dash_repo_label.config(foreground="green")
                else:
                    if hasattr(self, 'dash_info_text'):
                        self.dash_info_text.config(state=tk.NORMAL)
                        self.dash_info_text.delete(1.0, tk.END)
                        self.dash_info_text.insert(tk.END, f"Error reaching repo:\n{out_text}")
                        self.dash_info_text.config(state=tk.DISABLED)
                    self.var_health.set("ERROR")
                    self.var_health_desc.set("Connection failed")
                    if hasattr(self, 'dash_repo_label'):
                        self.dash_repo_label.config(foreground="red")
                    return

                # --- Update Storage Stats ---
                if success_json:
                    try:
                        data = json.loads(out_json)
                        # Borg 1.2+ puts stats in cache.stats, older in repository.stats
                        stats = data.get("cache", {}).get("stats", {}) or data.get("repository", {}).get("stats", {})
                        
                        dedup = stats.get("unique_csize", 0)
                        orig = stats.get("total_size", 0)
                        
                        self.var_dedup_size.set(format_bytes(dedup))
                        self.var_orig_size.set(format_bytes(orig))
                        
                        # Size comparison display: "12 GB → 3.5 GB"
                        self.var_size_comparison.set(f"{format_bytes(orig)} → {format_bytes(dedup)}")
                        
                        if orig > 0:
                            saved = ((orig - dedup) / orig) * 100
                            self.var_savings.set(f"💰 {saved:.1f}% saved")
                        else:
                            self.var_savings.set("0% saved")
                    except Exception as e:
                        logger.warning(f"JSON Parse Error (Info): {e}")

                # --- Update Last Backup Time & Archive Name ---
                if success_list:
                    try:
                        data = json.loads(out_list)
                        archives = data.get("archives", [])
                        if archives:
                            last_archive = archives[-1]
                            self.var_last_backup.set(time_since(last_archive["time"]))
                            # Show truncated archive name
                            name = last_archive.get("name", "Unknown")
                            if len(name) > 20:
                                name = name[:17] + "..."
                            self.var_last_archive_name.set(f"{name}")
                        else:
                            self.var_last_backup.set("Never")
                            self.var_last_archive_name.set("No archives yet")
                    except: pass

                # --- Update Active Jobs Count & Next Run ---
                jobs = self.config_manager.config.get("jobs", {})
                active_int = sum(1 for j in jobs.values() if j.get("internal_enabled"))
                active_cron = sum(1 for j in jobs.values() if j.get("cron_enabled"))
                self.var_jobs_active.set(f"{active_int} Int / {active_cron} Cron")
                
                # Find next scheduled run time
                next_run = "--"
                for job in jobs.values():
                    if job.get("internal_enabled"):
                        job_time = job.get("time", "03:00")
                        next_run = job_time
                        break
                self.var_next_run.set(next_run)
                
                # --- Update Repo Server Info (Row 3) ---
                try:
                    name, details = self.config_manager.get_current_repo_details()
                    if details:
                        path = details.get("path", "")
                        
                        # Parse repo host from path (ssh://user@host/path)
                        ssh_pattern = re.compile(r"ssh://([^@]+)@([^/:]+)(?::(\d+))?(/.*)") 
                        match = ssh_pattern.match(path)
                        
                        if match:
                            user, host, port, remote_path = match.groups()
                            self.var_repo_host.set(host)
                        else:
                            self.var_repo_host.set("Local")
                        
                        # Repo size (already calculated above - use dedup size)
                        if hasattr(self, 'var_dedup_size'):
                            self.var_repo_size.set(self.var_dedup_size.get())
                    else:
                        self.var_repo_host.set("--")
                        self.var_repo_size.set("--")
                except Exception as e:
                    logger.warning(f"Error updating repo server info: {e}")

            # Schedule the UI update
            self.after(0, update_ui)

        # 4. Start the Borg Info Worker
        threading.Thread(target=worker, daemon=True).start()

    def refresh_archives(self):
        # Clear existing items and stored archives
        for item in self.archive_tree.get_children(): 
            self.archive_tree.delete(item)
        self._all_archives = []
            
        def worker():
            success, out = self.run_borg_quick([self.borg_bin, "list", "--json"])
            if success:
                try:
                    data = json.loads(out)
                    archives = data.get("archives", [])
                    
                    # Update count on dashboard
                    self.after(0, lambda: self.var_archives.set(str(len(archives))))
                    
                    # SORT: Newest First
                    archives.sort(key=lambda x: x['time'], reverse=True)

                    for archive in archives:
                        # Parse Time
                        raw_time = archive['time']
                        display_time = raw_time
                        age = "--"
                        
                        try:
                            # 1. Format friendly date: 2025-12-05 08:08
                            clean_ts = raw_time.split(".")[0] # Remove microseconds
                            dt = datetime.datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S")
                            display_time = dt.strftime("%Y-%m-%d %H:%M")
                            
                            # 2. Calculate Age using existing helper
                            age = time_since(raw_time)
                        except Exception as e:
                            logger.debug(f"Time parse error: {e}")

                        # Store for filtering and insert into tree
                        values = (archive['name'], display_time, age, archive['id'])
                        self._all_archives.append(values)
                        self.after(0, lambda v=values: self.archive_tree.insert('', tk.END, values=v))
                        
                except json.JSONDecodeError: 
                    self.after(0, lambda: messagebox.showerror("Error", "Failed to parse JSON from Borg."))
            else:
                 # Add Error Row
                 self.after(0, lambda: self.archive_tree.insert('', tk.END, values=("ERROR", "Check Dashboard", "", "")))
        
        threading.Thread(target=worker, daemon=True).start()

    def show_archive_info(self):
        sel = self.archive_tree.selection()
        if not sel: return
        name = self.archive_tree.item(sel[0])['values'][0]
        def worker():
            cmd = [self.borg_bin, "info", f"::{name}"]
            success, content = self.run_borg_quick(cmd)
            if not success:
                content = f"Failed: {content}"
            self.after(0, lambda: self._display_info_popup(name, content))
        threading.Thread(target=worker, daemon=True).start()

    def _display_info_popup(self, title, content):
        win = tk.Toplevel(self)
        win.title(f"{title}")
        win.geometry("700x500")
        win.configure(bg=self.get_theme_color("bg_window"))
        
        bg_card = self.get_theme_color("bg_card")
        fg_text = self.get_theme_color("text_main")
        
        text = tk.Text(win, wrap=tk.WORD, padx=10, pady=10, bg=bg_card, fg=fg_text, 
                      relief="flat", insertbackground=fg_text)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, content)
        text.config(state=tk.DISABLED)
        ttk.Button(win, text=f"{icon('close')} Close", command=win.destroy).pack(pady=10)

    def delete_archive(self):
        sel = self.archive_tree.selection()
        if not sel: return
        name = self.archive_tree.item(sel[0])['values'][0]
        if messagebox.askyesno("Confirm", f"Delete '{name}'?"):
            self.log(f"User deleted archive: {name}", "AUDIT")
            self.run_borg_thread([self.borg_bin, "delete", f"::{name}"], on_complete=self.refresh_archives, task_name=f"Delete: {name}")

    def diff_archives(self):
        """Compare two archives to show what changed between them."""
        if not self._all_archives or len(self._all_archives) < 2:
            messagebox.showinfo("Info", "Need at least 2 archives to compare.")
            return
        
        # Create selection dialog
        win = tk.Toplevel(self)
        win.title("Compare Archives")
        win.geometry("500x300")
        win.configure(bg=self.get_theme_color("bg_window"))
        win.transient(self)
        win.grab_set()
        
        ttk.Label(win, text="Select two archives to compare:").pack(pady=10)
        
        # Archive 1 (older)
        frame1 = ttk.Frame(win)
        frame1.pack(fill=tk.X, padx=20, pady=5)
        ttk.Label(frame1, text="Archive 1 (older):").pack(side=tk.LEFT)
        archive1_var = tk.StringVar()
        archive1_combo = ttk.Combobox(frame1, textvariable=archive1_var, width=40, state="readonly")
        archive1_combo['values'] = [a[0] for a in self._all_archives]
        if len(self._all_archives) >= 2:
            archive1_combo.current(1)  # Second newest (older)
        archive1_combo.pack(side=tk.LEFT, padx=10)
        
        # Archive 2 (newer)
        frame2 = ttk.Frame(win)
        frame2.pack(fill=tk.X, padx=20, pady=5)
        ttk.Label(frame2, text="Archive 2 (newer):").pack(side=tk.LEFT)
        archive2_var = tk.StringVar()
        archive2_combo = ttk.Combobox(frame2, textvariable=archive2_var, width=40, state="readonly")
        archive2_combo['values'] = [a[0] for a in self._all_archives]
        if len(self._all_archives) >= 1:
            archive2_combo.current(0)  # Newest
        archive2_combo.pack(side=tk.LEFT, padx=10)
        
        result_holder = {"archive1": None, "archive2": None}
        
        def compare():
            a1 = archive1_var.get()
            a2 = archive2_var.get()
            if not a1 or not a2:
                messagebox.showwarning("Warning", "Please select both archives.")
                return
            if a1 == a2:
                messagebox.showwarning("Warning", "Please select different archives.")
                return
            result_holder["archive1"] = a1
            result_holder["archive2"] = a2
            win.destroy()
        
        btn_frame = ttk.Frame(win)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Compare", command=compare).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Cancel", command=win.destroy).pack(side=tk.LEFT, padx=10)
        
        self.wait_window(win)
        
        # Run diff if archives selected
        if result_holder["archive1"] and result_holder["archive2"]:
            a1, a2 = result_holder["archive1"], result_holder["archive2"]
            self.log(f"Comparing archives: {a1} vs {a2}", "INFO")
            
            def worker():
                cmd = [self.borg_bin, "diff", f"::{a1}", f"::{a2}"]
                success, output = self.run_borg_quick(cmd)
                if success:
                    title = f"Diff: {a1} → {a2}"
                    self.after(0, lambda: self._display_info_popup(title, output if output else "No differences found."))
                else:
                    self.after(0, lambda: messagebox.showerror("Error", f"Diff failed: {output}"))
            
            threading.Thread(target=worker, daemon=True).start()

    def mount_archive(self):
        sel = self.archive_tree.selection()
        if not sel: return
        name = self.archive_tree.item(sel[0])['values'][0]
        
        # Use remote browser if SSH helper is active
        if self.active_ssh_helper:
            mount_point = self.browse_remote_directory(select_files=False)
        else:
            mount_point = filedialog.askdirectory(title="Select Mount Point (Must be empty)")
        
        if mount_point:
            messagebox.showinfo("Info", f"Mounting to {mount_point}.\nCheck the logs.")
            self.log(f"User mounting archive {name} to {mount_point}", "AUDIT")
            self.run_borg_thread([self.borg_bin, "mount", f"::{name}", mount_point], task_name=f"Mount: {name}")

    def recreate_archive(self):
        # Reusing the logic from previous version, simplified for brevity here
        sel = self.archive_tree.selection()
        if not sel: return
        name = self.archive_tree.item(sel[0])['values'][0]
        mount_point = os.path.join(os.getcwd(), "mnt_recreate_tmp")
        os.makedirs(mount_point, exist_ok=True)
        env = self.get_env()
        self.log(f"Mounting {name} for inspection...", "INFO")
        
        def mount_and_open():
            cmd = [self.borg_bin, "mount", f"::{name}", mount_point]
            # Use Popen and wait for mount
            proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Wait for mount point to appear
            mounted = False
            for _ in range(10):
                time.sleep(0.5)
                if os.path.ismount(mount_point):
                    mounted = True
                    break
                # Fallback for systems where ismount is unreliable
                if platform.system() == "Darwin" and os.path.exists(mount_point) and os.listdir(mount_point):
                    mounted = True
                    break
            
            if mounted:
                self.after(0, lambda: self._open_recreate_dialog(mount_point, proc, name))
            else:
                 proc.terminate()
                 self.after(0, lambda: messagebox.showerror("Mount Failed", "Could not mount archive for inspection"))
        threading.Thread(target=mount_and_open, daemon=True).start()

    def _open_recreate_dialog(self, mount_point, mount_proc, archive_name):
        def on_confirm(includes, excludes):
            rel_excludes = []
            for exc in excludes:
                if exc.startswith(mount_point):
                    rel = os.path.relpath(exc, mount_point)
                    rel_excludes.append(rel)
            self._unmount_and_proceed(mount_point, mount_proc, archive_name, rel_excludes)
        def on_cancel():
            subprocess.run(["borg", "umount", mount_point])
        FileSelectorDialog(self, on_confirm, root_path=mount_point, on_cancel_callback=on_cancel)

    def _unmount_and_proceed(self, mount_path, proc, archive_name, excludes):
        subprocess.run(["borg", "umount", mount_path]) 
        if not excludes: return
        cmd = [self.borg_bin, "recreate", "--stats", "--progress", f"::{archive_name}"]
        for e in excludes: cmd.extend(["--exclude", e])
        if messagebox.askyesno("Recreate", f"Remove {len(excludes)} items from '{archive_name}'?"):
             self.log(f"User triggered recreate for: {archive_name}", "AUDIT")
             self.run_borg_thread(cmd, on_complete=self.refresh_archives, task_name=f"Recreate: {archive_name}")

    def refresh_mounts(self):
        for item in self.mount_tree.get_children(): self.mount_tree.delete(item)
        def worker():
            mounts = []
            try:
                if self.active_ssh_helper:
                    # Run mount command on source server
                    success, output, _ = self.active_ssh_helper.execute("mount | grep -E 'borgfs|fuse.borg'")
                    if success and output:
                        for line in output.strip().splitlines():
                            if "borgfs" in line or "fuse.borg" in line:
                                parts = line.split(" on ")
                                if len(parts) >= 2:
                                    mounts.append((parts[1].split(" type ")[0], parts[0]))
                else:
                    # Local mount check
                    res = subprocess.run(["mount"], capture_output=True, text=True)
                    for line in res.stdout.splitlines():
                        if "borgfs" in line or "fuse.borgfs" in line:
                            parts = line.split(" on ")
                            if len(parts) >= 2: mounts.append((parts[1].split(" type ")[0], parts[0]))
            except: pass
            self.after(0, lambda: [self.mount_tree.insert('', tk.END, values=(m[0], m[1])) for m in mounts])
        threading.Thread(target=worker, daemon=True).start()

    def unmount_selected_mount(self):
        sel = self.mount_tree.selection()
        if not sel: return
        mp = self.mount_tree.item(sel[0])['values'][0]
        if messagebox.askyesno("Unmount", f"Unmount {mp}?"):
            self.log(f"User unmounting {mp}", "AUDIT")
            self.run_borg_thread([self.borg_bin, "umount", mp], on_complete=self.refresh_mounts, task_name=f"Unmount: {mp}")

    def open_mounted_folder(self):
        sel = self.mount_tree.selection()
        if not sel: return
        mp = self.mount_tree.item(sel[0])['values'][0]
        
        if self.active_ssh_helper:
            # Remote mount - use SFTP browser on Windows, xdg-open on Linux
            if platform.system() == "Windows":
                self._open_sftp_browser(mp)
            else:
                # Linux - open file manager with SFTP URL
                srv = self.config_manager.get_source_server(self.active_source_id)
                host = srv.get("host", "") if srv else ""
                sftp_url = f"sftp://{host}{mp}"
                subprocess.run(["xdg-open", sftp_url])
        else:
            # Local mount
            if platform.system() == "Darwin": subprocess.run(["open", mp])
            elif platform.system() == "Linux": subprocess.run(["xdg-open", mp])
            elif platform.system() == "Windows": os.startfile(mp)
    
    def _open_sftp_browser(self, start_path="/"):
        """Dual-pane SFTP file browser (like WinSCP) - Local on left, Remote on right."""
        if not self.active_ssh_helper:
            return
        
        dialog = tk.Toplevel(self)
        srv = self.config_manager.get_source_server(self.active_source_id)
        source_name = srv.get("name", self.active_source_id) if srv else "Remote"
        dialog.title(f"File Transfer - {source_name}")
        dialog.geometry("1000x600")
        dialog.transient(self)
        dialog.configure(bg=self.get_theme_color("bg_window"))
        
        # State for both panes
        local_path = [os.path.expanduser("~")]
        remote_path = [start_path]
        local_items = []
        remote_items = []
        
        # Status bar
        status_var = tk.StringVar(value="Ready")
        
        # Main container with two panes
        panes = ttk.PanedWindow(dialog, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # === LEFT PANE: LOCAL ===
        local_frame = ttk.LabelFrame(panes, text="Local (This PC)", padding=5)
        panes.add(local_frame, weight=1)
        
        # Local path bar
        local_path_frame = ttk.Frame(local_frame)
        local_path_frame.pack(fill=tk.X)
        local_path_var = tk.StringVar(value=local_path[0])
        ttk.Entry(local_path_frame, textvariable=local_path_var, width=35).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(local_path_frame, text="↑", width=2, command=lambda: local_go_up()).pack(side=tk.LEFT)
        
        # Local file list
        local_tree = ttk.Treeview(local_frame, columns=("name", "size"), show="headings", height=20)
        local_tree.heading("name", text="Name")
        local_tree.heading("size", text="Size")
        local_tree.column("name", width=250)
        local_tree.column("size", width=80)
        local_scroll = ttk.Scrollbar(local_frame, orient="vertical", command=local_tree.yview)
        local_tree.configure(yscrollcommand=local_scroll.set)
        local_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        local_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # === CENTER: Transfer Buttons ===
        center_frame = ttk.Frame(panes)
        panes.add(center_frame, weight=0)
        
        ttk.Label(center_frame, text="\n\n").pack()  # Spacer
        ttk.Button(center_frame, text="→\nCopy to\nRemote", command=lambda: copy_to_remote()).pack(pady=10)
        ttk.Button(center_frame, text="←\nCopy to\nLocal", command=lambda: copy_to_local()).pack(pady=10)
        
        # === RIGHT PANE: REMOTE ===
        remote_frame = ttk.LabelFrame(panes, text=f"Remote ({source_name})", padding=5)
        panes.add(remote_frame, weight=1)
        
        # Remote path bar
        remote_path_frame = ttk.Frame(remote_frame)
        remote_path_frame.pack(fill=tk.X)
        remote_path_var = tk.StringVar(value=remote_path[0])
        ttk.Entry(remote_path_frame, textvariable=remote_path_var, width=35).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(remote_path_frame, text="↑", width=2, command=lambda: remote_go_up()).pack(side=tk.LEFT)
        
        # Remote file list
        remote_tree = ttk.Treeview(remote_frame, columns=("name", "size"), show="headings", height=20)
        remote_tree.heading("name", text="Name")
        remote_tree.heading("size", text="Size")
        remote_tree.column("name", width=250)
        remote_tree.column("size", width=80)
        remote_scroll = ttk.Scrollbar(remote_frame, orient="vertical", command=remote_tree.yview)
        remote_tree.configure(yscrollcommand=remote_scroll.set)
        remote_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        remote_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Status bar at bottom
        ttk.Label(dialog, textvariable=status_var, foreground="gray").pack(fill=tk.X, padx=10)
        
        # === FUNCTIONS ===
        def refresh_local():
            local_tree.delete(*local_tree.get_children())
            local_items.clear()
            path = local_path[0]
            local_path_var.set(path)
            
            # Add parent
            if path != "/" and os.path.dirname(path) != path:
                local_tree.insert("", tk.END, values=("📁 ..", ""))
                local_items.append(("..", True))
            
            try:
                for name in sorted(os.listdir(path)):
                    full_path = os.path.join(path, name)
                    is_dir = os.path.isdir(full_path)
                    prefix = "📁 " if is_dir else "📄 "
                    size = "" if is_dir else self._format_size(os.path.getsize(full_path))
                    local_tree.insert("", tk.END, values=(prefix + name, size))
                    local_items.append((name, is_dir))
            except Exception as e:
                status_var.set(f"Error: {e}")
        
        def refresh_remote():
            remote_tree.delete(*remote_tree.get_children())
            remote_items.clear()
            path = remote_path[0]
            remote_path_var.set(path)
            status_var.set(f"Loading {path}...")
            dialog.update()
            
            # Add parent
            if path != "/":
                remote_tree.insert("", tk.END, values=("📁 ..", ""))
                remote_items.append(("..", True))
            
            items = self.active_ssh_helper.list_dir(path)
            for name, is_dir in items:
                if name.startswith("."):
                    continue
                prefix = "📁 " if is_dir else "📄 "
                remote_tree.insert("", tk.END, values=(prefix + name, ""))
                remote_items.append((name, is_dir))
            
            status_var.set(f"{len(remote_items)} items")
        
        def local_go_up():
            parent = os.path.dirname(local_path[0])
            if parent and parent != local_path[0]:
                local_path[0] = parent
                refresh_local()
        
        def remote_go_up():
            remote_path[0] = os.path.dirname(remote_path[0].rstrip("/")) or "/"
            refresh_remote()
        
        def on_local_double_click(event):
            sel = local_tree.selection()
            if not sel:
                return
            idx = local_tree.index(sel[0])
            if idx >= len(local_items):
                return
            name, is_dir = local_items[idx]
            if name == "..":
                local_go_up()
            elif is_dir:
                local_path[0] = os.path.join(local_path[0], name)
                refresh_local()
        
        def on_remote_double_click(event):
            sel = remote_tree.selection()
            if not sel:
                return
            idx = remote_tree.index(sel[0])
            if idx >= len(remote_items):
                return
            name, is_dir = remote_items[idx]
            if name == "..":
                remote_go_up()
            elif is_dir:
                if remote_path[0] == "/":
                    remote_path[0] = "/" + name
                else:
                    remote_path[0] = remote_path[0].rstrip("/") + "/" + name
                refresh_remote()
        
        local_tree.bind("<Double-1>", on_local_double_click)
        remote_tree.bind("<Double-1>", on_remote_double_click)
        
        def copy_to_local():
            sel = remote_tree.selection()
            if not sel:
                messagebox.showinfo("Info", "Select a file on the right (remote) pane.")
                return
            idx = remote_tree.index(sel[0])
            if idx >= len(remote_items):
                return
            name, is_dir = remote_items[idx]
            if is_dir or name == "..":
                messagebox.showinfo("Info", "Cannot copy folders. Select a file.")
                return
            
            remote_file = remote_path[0].rstrip("/") + "/" + name
            local_file = os.path.join(local_path[0], name)
            
            status_var.set(f"Downloading {name}...")
            dialog.update()
            
            def do_download():
                success, error = self.active_ssh_helper.download_file(remote_file, local_file)
                if success:
                    self.after(0, lambda: status_var.set(f"Downloaded: {name}"))
                    self.after(0, refresh_local)
                else:
                    self.after(0, lambda: status_var.set(f"Failed: {error}"))
            
            threading.Thread(target=do_download, daemon=True).start()
        
        def copy_to_remote():
            sel = local_tree.selection()
            if not sel:
                messagebox.showinfo("Info", "Select a file on the left (local) pane.")
                return
            idx = local_tree.index(sel[0])
            if idx >= len(local_items):
                return
            name, is_dir = local_items[idx]
            if is_dir or name == "..":
                messagebox.showinfo("Info", "Cannot copy folders. Select a file.")
                return
            
            local_file = os.path.join(local_path[0], name)
            remote_file = remote_path[0].rstrip("/") + "/" + name
            
            status_var.set(f"Uploading {name}...")
            dialog.update()
            
            def do_upload():
                # Use SCP via SSH helper
                success, _, error = self.active_ssh_helper.execute(
                    f"cat > '{remote_file}'",
                    timeout=300
                )
                # For now, show not implemented - upload requires more work
                self.after(0, lambda: messagebox.showinfo("Upload", 
                    f"Upload functionality requires additional implementation.\n\n"
                    f"To copy to remote, use:\n"
                    f"scp {local_file} {self.active_ssh_helper.host}:{remote_file}"))
                self.after(0, lambda: status_var.set("Ready"))
            
            threading.Thread(target=do_upload, daemon=True).start()
        
        # Initial load
        refresh_local()
        refresh_remote()
    
    def _format_size(self, size):
        """Format bytes to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.0f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def add_path(self, listbox):
        """Add a directory path - uses remote browser if source is remote."""
        if self.active_ssh_helper:
            path = self.browse_remote_directory()
        else:
            path = filedialog.askdirectory()
        if path:
            listbox.insert(tk.END, path)
    
    def add_file(self, listbox):
        """Add a file path - uses remote browser if source is remote."""
        if self.active_ssh_helper:
            path = self.browse_remote_directory(select_files=True)
        else:
            path = filedialog.askopenfilename()
        if path:
            listbox.insert(tk.END, path)
    
    def browse_remote_directory(self, select_files=False):
        """Open a dialog to browse remote server filesystem.
        
        Args:
            select_files: If True, allow selecting files. If False, directories only.
        
        Returns:
            str: Selected path or None if cancelled
        """
        if not self.active_ssh_helper:
            return None
        
        dialog = tk.Toplevel(self)
        dialog.title(f"Browse: {self.active_source_id}")
        dialog.geometry("500x450")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg=self.get_theme_color("bg_window"))
        
        result = {"path": None}
        current_path = ["/"]  # Use list for mutability in nested function
        
        # Header with current path
        header = ttk.Frame(dialog)
        header.pack(fill=tk.X, padx=10, pady=10)
        
        path_var = tk.StringVar(value="/")
        ttk.Label(header, text="Location:").pack(side=tk.LEFT)
        path_entry = ttk.Entry(header, textvariable=path_var, width=40)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        def go_to_path(event=None):
            current_path[0] = path_var.get()
            refresh_list()
        
        path_entry.bind("<Return>", go_to_path)
        ttk.Button(header, text="Go", command=go_to_path).pack(side=tk.LEFT)
        ttk.Button(header, text="Home", command=lambda: go_home()).pack(side=tk.LEFT, padx=5)
        
        # File list
        list_frame = ttk.Frame(dialog)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        listbox = tk.Listbox(list_frame, font=("", 10), 
                            bg=self.get_theme_color("bg_card"),
                            fg=self.get_theme_color("text_main"))
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        items_cache = []  # Store (name, is_dir) for each list item
        
        def refresh_list():
            listbox.delete(0, tk.END)
            items_cache.clear()
            
            path = current_path[0]
            path_var.set(path)
            
            # Add parent directory option
            if path != "/":
                listbox.insert(tk.END, "📁 ..")
                items_cache.append(("..", True))
            
            # Fetch remote listing
            items = self.active_ssh_helper.list_dir(path)
            
            for name, is_dir in items:
                if name.startswith("."):
                    continue  # Skip hidden files
                prefix = "📁 " if is_dir else "📄 "
                listbox.insert(tk.END, prefix + name)
                items_cache.append((name, is_dir))
        
        def on_double_click(event):
            sel = listbox.curselection()
            if not sel:
                return
            idx = sel[0]
            name, is_dir = items_cache[idx]
            
            if name == "..":
                # Go up one level
                current_path[0] = os.path.dirname(current_path[0].rstrip("/")) or "/"
                refresh_list()
            elif is_dir:
                # Navigate into directory
                if current_path[0] == "/":
                    current_path[0] = "/" + name
                else:
                    current_path[0] = current_path[0].rstrip("/") + "/" + name
                refresh_list()
            elif select_files:
                # Select file
                result["path"] = current_path[0].rstrip("/") + "/" + name
                dialog.destroy()
        
        listbox.bind("<Double-1>", on_double_click)
        
        def go_home():
            home = self.active_ssh_helper.get_home()
            current_path[0] = home
            refresh_list()
        
        def select_current():
            sel = listbox.curselection()
            if sel:
                idx = sel[0]
                name, is_dir = items_cache[idx]
                if name == "..":
                    result["path"] = os.path.dirname(current_path[0].rstrip("/")) or "/"
                elif is_dir or select_files:
                    result["path"] = current_path[0].rstrip("/") + "/" + name
            else:
                # Select current directory
                result["path"] = current_path[0]
            dialog.destroy()
        
        # Buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, pady=10, padx=10)
        
        btn_text = "Select" if select_files else "Select Folder"
        ttk.Button(btn_frame, text=btn_text, command=select_current).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Initial load
        go_home()
        
        dialog.wait_window()
        return result["path"]
    
    def remove_path(self, listbox):
        sel = listbox.curselection()
        if sel: listbox.delete(sel[0])

    def start_backup(self):
        includes = self.list_includes.get(0, tk.END)
        if not includes:
            messagebox.showerror("Error", "No include paths specified.")
            return
        excludes = self.list_excludes.get(0, tk.END)
        name_base = self.backup_name_var.get()
        archive_name = f"{name_base}-{datetime.datetime.now().strftime('%Y-%m-%d-%H%M')}"
        cmd = [self.borg_bin, "create", "--stats", "--progress", "--compression", "zstd,6"]
        for exc in excludes: cmd.extend(["--exclude", exc])
        cmd.append(f"::{archive_name}")
        cmd.extend(includes)
        
        # Store backup config for potential scheduling
        self._last_backup_config = {
            "name": name_base,
            "includes": list(includes),
            "excludes": list(excludes),
            "source": self.active_source_id,
            "repo": self.config_manager.config.get("current_repo", "")
        }
        
        def on_backup_complete():
            self.refresh_archives()
            # Ask user if they want to schedule this backup
            self._ask_schedule_backup()
        
        if messagebox.askyesno("Confirm Backup", f"Create archive '{archive_name}'?"):
            self.log(f"User started manual backup: {archive_name}", "AUDIT")
            self.run_borg_thread(cmd, on_complete=on_backup_complete, task_name=f"Backup: {archive_name}")
    
    def _ask_schedule_backup(self):
        """Ask user if they want to schedule the backup they just ran."""
        result = messagebox.askyesno(
            "Schedule This Backup?",
            "Backup completed successfully!\n\n"
            "Would you like to schedule this backup to run automatically?\n\n"
            "• Yes - Create a scheduled job with the same paths\n"
            "• No - Go to Archives to view your backup"
        )
        
        if result:
            # Open scheduler tab and create new job with same config
            self.notebook.select(self.tab_schedule)
            self._create_scheduled_job_from_backup()
        else:
            # Open archives tab and select latest archive
            self.notebook.select(self.tab_archives)
            self._highlight_latest_archive()
    
    def _create_scheduled_job_from_backup(self):
        """Create a new scheduled job pre-filled with last backup's config."""
        if not hasattr(self, '_last_backup_config'):
            return
        
        config = self._last_backup_config
        
        # Create new job ID
        import uuid
        job_id = str(uuid.uuid4())
        
        # Get current repo
        repo_name, _ = self.config_manager.get_current_repo_details()
        
        # Set job variables
        self.job_var_id.set(job_id)
        self.job_var_name.set(config["name"])
        self.job_var_repo.set(config.get("repo") or repo_name or "")
        self.job_var_source.set(config.get("source") or self.active_source_id or "")
        self.job_var_time.set("03:00")  # Default time
        self.job_var_freq.set("Daily")
        self.job_var_internal.set(False)
        self.job_var_cron.set(False)
        
        # Clear and populate path lists
        self.job_list_inc.delete(0, tk.END)
        for path in config["includes"]:
            self.job_list_inc.insert(tk.END, path)
        
        self.job_list_exc.delete(0, tk.END)
        for path in config["excludes"]:
            self.job_list_exc.insert(tk.END, path)
        
        # Show message
        messagebox.showinfo(
            "New Job Created",
            f"A new job '{config['name']}' has been pre-filled with your backup settings.\n\n"
            "Please:\n"
            "1. Enable 'Internal Timer' or 'System Cron'\n"
            "2. Set the schedule (time, frequency)\n"
            "3. Click 'Save Job' to save"
        )
    
    def _highlight_latest_archive(self):
        """Select the latest archive in the archive tree."""
        children = self.archive_tree.get_children()
        if children:
            # First item is latest (sorted newest first)
            self.archive_tree.selection_set(children[0])
            self.archive_tree.see(children[0])

    def run_prune(self):
        d, w, m = self.keep_daily.get(), self.keep_weekly.get(), self.keep_monthly.get()
        # Add --info for better logging
        cmd = [self.borg_bin, "prune", "--list", "--stats", "--info", "--keep-daily", d, "--keep-weekly", w, "--keep-monthly", m]
        if messagebox.askyesno("Prune", "Run DRY RUN first? (Recommended)"): cmd.append("--dry-run")
        
        if self.is_running:
             if messagebox.askyesno("System Busy", "Maintenance task cannot run immediately. Add to Queue?"):
                 self._queue_command("Prune", cmd, on_complete=self.refresh_archives)
             return

        self.log("User started manual prune", "AUDIT")
        self.run_borg_thread(cmd, on_complete=self.refresh_archives, task_name="Prune")
    def run_compact(self):
        if messagebox.askyesno("Compact", "Reclaim space?"):
            cmd = [self.borg_bin, "compact", "--progress", "--info"]
            if self.is_running:
                 if messagebox.askyesno("System Busy", "Maintenance task cannot run immediately. Add to Queue?"):
                     self._queue_command("Compact", cmd)
                 return
            self.log("User started compact", "AUDIT")
            self.run_borg_thread(cmd, task_name="Compact")
    def run_check(self):
        if messagebox.askyesno("Check", "Run integrity check?"): 
            cmd = [self.borg_bin, "check", "--progress", "--info"]
            if self.is_running:
                 if messagebox.askyesno("System Busy", "Maintenance task cannot run immediately. Add to Queue?"):
                     self._queue_command("Integrity Check", cmd)
                 return
            self.log("User started integrity check", "AUDIT")
            self.run_borg_thread(cmd, task_name="Integrity Check")
    def run_break_lock(self):
        if messagebox.askyesno("Break Lock", "Force break lock?"): 
            cmd = [self.borg_bin, "break-lock", "--info"]
            if self.is_running:
                 if messagebox.askyesno("System Busy", "Maintenance task cannot run immediately. Add to Queue?"):
                     self._queue_command("Break Lock", cmd)
                 return
            self.log("User started break-lock", "AUDIT")
            self.run_borg_thread(cmd, task_name="Break Lock")
    def inspect_lock_owner(self):
        """Inspect lock owner - runs on source server via SSH if remote."""
        name, details = self.config_manager.get_current_repo_details()
        if not details: 
            messagebox.showwarning("No Repo", "Please select a repository first.")
            return
        
        path = details["path"]
        
        def worker():
            lock_info = ""
            
            # Regex to find ssh://user@host:port/path
            ssh_pattern = re.compile(r"ssh://([^@]+)@([^/:]+)(?::(\d+))?(/.*)") 
            match = ssh_pattern.match(path)
            
            if match:
                # SSH REPO - extract path and run command on source server
                user, host, port, remote_path = match.groups()
                lock_path = f"{remote_path}/lock.exclusive"
                
                if self.active_ssh_helper:
                    # Execute via SSH helper (runs on source server)
                    cmd = f"ls -1 {lock_path} 2>/dev/null || echo 'No lock found'"
                    success, output, error = self.active_ssh_helper.execute(cmd, timeout=10)
                    
                    if success and "No lock found" not in output:
                        lock_info = f"Lock detected at {host}:{lock_path}\n\nLOCKED BY:\n{output}"
                    elif success:
                        lock_info = "No lock.exclusive directory found.\nThe repository might not be locked."
                    else:
                        lock_info = f"Error checking lock: {error}"
                else:
                    lock_info = "No active SSH connection.\nPlease select a source server first."
            else:
                # LOCAL REPO
                lock_path = os.path.join(path, "lock.exclusive")
                if os.path.exists(lock_path) and os.path.isdir(lock_path):
                    try:
                        files = os.listdir(lock_path)
                        lock_info = f"Lock detected at local path: {lock_path}\n\nLOCKED BY:\n" + "\n".join(files)
                    except Exception as e:
                        lock_info = f"Error reading lock dir: {e}"
                else:
                    lock_info = "No local lock.exclusive directory found.\nThe repository might not be locked."

            self.after(0, lambda: self._display_info_popup("Lock Inspector", lock_info))

        threading.Thread(target=worker, daemon=True).start()

    # --- REPO MANAGER ---
    def open_repo_manager(self):
        win = tk.Toplevel(self)
        
        # Get source info
        srv = self.config_manager.get_source_server(self.active_source_id) if self.active_source_id else None
        source_name = srv.get("name", self.active_source_id) if srv else "Local"
        # Repos are now stored directly as dict under source server
        source_repos = srv.get("repos", {}) if srv else {}
        
        win.title(f"Repository Manager - {source_name}")
        win.configure(bg=self.get_theme_color("bg_window"))
        win.geometry("500x550")
        
        # Header showing which source
        header = ttk.Label(win, text=f"Repositories for: {source_name}", font=("", 11, "bold"), foreground="#27ae60")
        header.pack(pady=10)
        
        listbox = tk.Listbox(win, bg=self.get_theme_color("bg_card"), fg=self.get_theme_color("text_main"))
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Show repos for this source
        for name in source_repos.keys():
            listbox.insert(tk.END, name)

        def load_selected():
            sel = listbox.curselection()
            if sel:
                name = listbox.get(sel[0])
                self.config_manager.config["current_repo"] = name
                self.config_manager.save_config()
                self.refresh_repo_display()
                win.destroy()
        
        # REFACTORED: Unified Form for Add and Edit
        def show_repo_form(repo_name=None):
            form = tk.Toplevel(win)
            form.title("Edit Repository" if repo_name else "Add Repository")
            form.configure(bg=self.get_theme_color("bg_window"))
            form.geometry("600x700")
            form.minsize(550, 500)
            
            # --- SCROLLABLE CONTAINER ---
            container = ttk.Frame(form)
            container.pack(fill=tk.BOTH, expand=True)
            
            canvas = tk.Canvas(container, bg=self.get_theme_color("bg_window"), highlightthickness=0)
            scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
            
            main_frame = ttk.Frame(canvas, padding=20) # Renamed to main_frame to keep compatibility
            
            # Dynamic Scrollbar Logic
            def update_scroll_region(event):
                try:
                    bbox = canvas.bbox("all")
                    if not bbox: return
                    canvas.configure(scrollregion=bbox)
                    
                    if bbox[3] > canvas.winfo_height():
                        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                        canvas.bind_all("<MouseWheel>", _on_mousewheel)
                    else:
                        scrollbar.pack_forget()
                        canvas.unbind_all("<MouseWheel>")
                except:
                    pass
            
            main_frame.bind("<Configure>", update_scroll_region)
            container.bind("<Configure>", lambda e: update_scroll_region(None))
            
            canvas.create_window((0, 0), window=main_frame, anchor="nw") 
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            def _on_mousewheel(event):
                canvas.yview_scroll(int(-1*(event.delta/120)), "units")


            # Data container
            data = {"name": "", "path": "", "repo_pass": "", "cmd_pass": "", "ssh_pass": ""}
            
            # Load if editing
            if repo_name:
                # FIX: Load from active source server, not global 'repos' key which may not exist
                details = {}
                if self.active_source_id:
                    srv = self.config_manager.get_source_server(self.active_source_id)
                    if srv:
                        details = srv.get("repos", {}).get(repo_name, {})
                else:
                    # Fallback if no source active (should not happen in this view)
                     details = self.config_manager.config.get("repos", {}).get(repo_name, {})
                
                data["name"] = repo_name
                data["path"] = details.get("path", "")
                data["repo_pass"] = details.get("repo_passphrase", "")
                data["cmd_pass"] = details.get("pass_command", "")
                data["ssh_pass"] = details.get("ssh_password", "")

            # UI Helpers - now packs into main_frame
            def add_field(label, var_key, show=None):
                f = ttk.Frame(main_frame)
                f.pack(fill=tk.X, padx=10, pady=5)
                ttk.Label(f, text=label).pack(anchor=tk.W)
                v = tk.StringVar(value=data[var_key])
                e = ttk.Entry(f, textvariable=v, show=show, width=50)
                e.pack(anchor=tk.W, fill=tk.X)
                return v

            # Fields
            name_var = add_field("Friendly Name (e.g. Server Backup):", "name")
            if repo_name: name_var.set(repo_name); # If editing, name is typically fixed or handled carefully
            
            path_var = add_field("Repo Path (ssh://user@host/path):", "path")
            
            # --- Repository Type Selection (Only for new repos) ---
            repo_type_var = tk.StringVar(value="existing")
            encryption_mode_var = tk.StringVar(value="repokey")
            
            if not repo_name:  # Only show for new repos
                type_frame = ttk.LabelFrame(main_frame, text="Repository Type", padding=10)
                type_frame.pack(fill=tk.X, padx=10, pady=10)
                
                # Encryption mode frame - created BEFORE radio buttons that reference it
                enc_frame = ttk.LabelFrame(main_frame, text="Encryption Mode (for new repos)", padding=10)
                
                enc_modes = [
                    ("repokey", "repokey (Recommended - key in repo, needs passphrase)"),
                    ("repokey-blake2", "repokey-blake2 (Faster, modern)"),
                    ("keyfile", "keyfile (Key stored locally, needs passphrase)"),
                    ("keyfile-blake2", "keyfile-blake2 (Faster, key stored locally)"),
                    ("authenticated", "authenticated (No encryption, just authentication)"),
                    ("none", "none (No encryption - NOT recommended)")
                ]
                
                for mode, desc in enc_modes:
                    ttk.Radiobutton(enc_frame, text=desc, variable=encryption_mode_var, value=mode).pack(anchor=tk.W)
                
                # Toggle function for showing/hiding encryption options
                def toggle_enc_frame():
                    if repo_type_var.get() == "new":
                        enc_frame.pack(fill=tk.X, padx=10, pady=5, after=type_frame)
                    else:
                        enc_frame.pack_forget()
                
                ttk.Radiobutton(
                    type_frame, 
                    text="Connect to Existing Repository (already initialized)", 
                    variable=repo_type_var, 
                    value="existing",
                    command=toggle_enc_frame
                ).pack(anchor=tk.W, pady=2)
                
                ttk.Radiobutton(
                    type_frame, 
                    text="Initialize New Repository (borg init)", 
                    variable=repo_type_var, 
                    value="new",
                    command=toggle_enc_frame
                ).pack(anchor=tk.W, pady=2)
                
                # Info label
                info_lbl = ttk.Label(type_frame, text="", foreground="gray", wraplength=450)
                info_lbl.pack(anchor=tk.W, pady=(5,0))
                
                def update_info(*args):
                    if repo_type_var.get() == "existing":
                        info_lbl.config(text="Use this if the borg repository is already set up on the server.")
                    else:
                        info_lbl.config(text="Use this to create a brand new borg repository. This will run 'borg init'.")
                
                repo_type_var.trace_add("write", update_info)
                update_info()
            
            ttk.Label(main_frame, text="--- Encryption ---", foreground="blue").pack(pady=(10,0))
            repo_pass_var = add_field("Repo Passphrase (Required for encrypted repos):", "repo_pass", show="*")
            cmd_pass_var = add_field("OR Passphrase Command (Advanced):", "cmd_pass")

            ttk.Label(main_frame, text="--- Connection ---", foreground="blue").pack(pady=(10,0))
            ssh_pass_var = add_field("SSH Password (Optional, if no SSH Key):", "ssh_pass", show="*")
            
            # --- SSH SETUP (SOURCE -> REPO) ---
            # Added here as per request to move it from Server Dialog
            ssh_setup_frame = ttk.LabelFrame(main_frame, text="SSH Setup (Source Server → This Repo)", padding=10)
            ssh_setup_frame.pack(fill=tk.X, padx=10, pady=10)
            
            def do_setup_repo_ssh():
                # 1. Get Repo ID/Host from Path
                p = path_var.get().strip()
                match = re.match(r'ssh://([^/]+)', p)
                if not match:
                    messagebox.showerror("Invalid Path", "Repo path must start with ssh://user@host/...", parent=form)
                    return
                repo_host_str = match.group(1)
                
                # 2. Identify Source
                source_lbl = f"Source Server: {source_name}"
                
                # 3. Ask for Repo Password
                msg = f"install SSH key from\n[{source_name}]\nto\n[{repo_host_str}]"
                repo_pw = simpledialog.askstring("Repo Password", 
                    f"Enter password for {repo_host_str}\nto {msg}:", show="*", parent=form)
                if not repo_pw: return
                
                def worker():
                    self.log(f"Setting up SSH Key: {source_name} -> {repo_host_str}", "INFO")
                    try:
                        # If Source is Remote
                        if self.active_ssh_helper:
                            helper = self.active_ssh_helper
                            # Check for key on source
                            res, out, _ = helper.execute("test -f ~/.ssh/id_ed25519 && echo YES || echo NO")
                            if "NO" in out:
                                self.log("Generating key on remote source...", "INFO")
                                helper.execute("ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N '' -q")
                            
                            # Copy ID
                            cmd = f"sshpass -p '{repo_pw}' ssh-copy-id -o StrictHostKeyChecking=accept-new -i ~/.ssh/id_ed25519.pub {repo_host_str}"
                            success, out, err = helper.execute(cmd, timeout=60)
                            if success:
                                self.log("SSH Key Installed on Repo (from Remote Source)", "SUCCESS")
                                self.after(0, lambda: messagebox.showinfo("Success", "SSH Key installed!", parent=form))
                            else:
                                raise Exception(err or out)
                        else:
                            # Source is Local
                            key_path = os.path.expanduser("~/.ssh/id_ed25519")
                            if not os.path.exists(key_path):
                                self.log("Generating local key...", "INFO")
                                subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", ""], check=True)
                            
                            if not shutil.which("sshpass"):
                                raise Exception("sshpass tool is missing on local machine.")
                                
                            cmd = ["sshpass", "-p", repo_pw, "ssh-copy-id", "-o", "StrictHostKeyChecking=accept-new", 
                                   "-i", f"{key_path}.pub", repo_host_str]
                            res = subprocess.run(cmd, capture_output=True, text=True)
                            if res.returncode == 0:
                                self.log("SSH Key Installed on Repo (from Local)", "SUCCESS")
                                self.after(0, lambda: messagebox.showinfo("Success", "SSH Key installed!", parent=form))
                            else:
                                raise Exception(res.stderr)

                    except Exception as e:
                        self.log(f"Failed to setup SSH: {e}", "ERROR")
                        self.after(0, lambda: messagebox.showerror("Error", str(e), parent=form))

                threading.Thread(target=worker, daemon=True).start()

            ttk.Button(ssh_setup_frame, text="🔑 Send SSH Key (Source → Repo)", command=do_setup_repo_ssh).pack(fill=tk.X)
            ttk.Label(ssh_setup_frame, text="Auto-fills password for future backups.", font=("", 8), foreground="gray").pack(pady=(5,0))


            # Status label for showing init progress
            status_label = ttk.Label(main_frame, text="", foreground="blue")
            status_label.pack(pady=5)

            def save():
                n = name_var.get().strip()
                p = path_var.get().strip()
                if not n or not p:
                    messagebox.showerror("Error", "Name and Path are required")
                    return
                
                # Check if we need to initialize
                if not repo_name and repo_type_var.get() == "new":
                    passphrase = repo_pass_var.get().strip()
                    enc_mode = encryption_mode_var.get()
                    
                    # Validate passphrase for encrypted modes
                    if enc_mode not in ["none", "authenticated"] and not passphrase:
                        messagebox.showerror("Error", "Passphrase is required for encrypted repositories")
                        return
                    
                    # Run borg init in a thread
                    def run_init():
                        status_label.config(text="⏳ Initializing repository...")
                        form.update()
                        
                        try:
                            # Check if we have SSH helper for remote execution
                            if self.active_ssh_helper:
                                # Build command to run on remote source server
                                env_exports = [
                                    f"export BORG_REPO='{p}'"
                                ]
                                if passphrase:
                                    env_exports.append(f"export BORG_PASSPHRASE='{passphrase}'")
                                elif cmd_pass_var.get().strip():
                                    env_exports.append(f"export BORG_PASSCOMMAND='{cmd_pass_var.get().strip()}'")
                                
                                # Handle SSH password for repo server access
                                ssh_pw = ssh_pass_var.get().strip()
                                if ssh_pw:
                                    env_exports.append(f"export SSHPASS='{ssh_pw}'")
                                    env_exports.append("export BORG_RSH='sshpass -e ssh -o StrictHostKeyChecking=accept-new'")
                                else:
                                    env_exports.append("export BORG_RSH='ssh -o StrictHostKeyChecking=accept-new'")
                                
                                cmd_str = " && ".join(env_exports) + f" && borg init --encryption {enc_mode}"
                                
                                self.log(f"[SSH] Running borg init on source server...", "INFO")
                                success, stdout, stderr = self.active_ssh_helper.execute(cmd_str, timeout=120)
                                
                                if success:
                                    self.log(f"Repository initialized successfully: {p}", "SUCCESS")
                                    form.after(0, lambda: finish_save(n, p))
                                else:
                                    error_msg = stderr or stdout or "Unknown error"
                                    self.log(f"Failed to initialize repository: {error_msg}", "ERROR")
                                    form.after(0, lambda: status_label.config(text=f"❌ Init failed: {error_msg[:100]}"))
                                    form.after(0, lambda: messagebox.showerror("Initialization Failed", f"Error: {error_msg}"))
                            else:
                                # Local execution (Linux/Mac where borg is installed locally)
                                env = os.environ.copy()
                                env["BORG_REPO"] = p
                                
                                if passphrase:
                                    env["BORG_PASSPHRASE"] = passphrase
                                elif cmd_pass_var.get().strip():
                                    env["BORG_PASSCOMMAND"] = cmd_pass_var.get().strip()
                                
                                ssh_pw = ssh_pass_var.get().strip()
                                if ssh_pw and shutil.which("sshpass"):
                                    env["SSHPASS"] = ssh_pw
                                    env["BORG_RSH"] = "sshpass -e ssh -o StrictHostKeyChecking=accept-new"
                                else:
                                    env["BORG_RSH"] = "ssh -o StrictHostKeyChecking=accept-new"
                                
                                cmd = [self.borg_bin, "init", "--encryption", enc_mode]
                                proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
                                
                                if proc.returncode == 0:
                                    self.log(f"Repository initialized successfully: {p}", "SUCCESS")
                                    form.after(0, lambda: finish_save(n, p))
                                else:
                                    error_msg = proc.stderr or proc.stdout or "Unknown error"
                                    self.log(f"Failed to initialize repository: {error_msg}", "ERROR")
                                    form.after(0, lambda: status_label.config(text=f"❌ Init failed: {error_msg[:100]}"))
                                    form.after(0, lambda: messagebox.showerror("Initialization Failed", f"Error: {error_msg}"))
                        except subprocess.TimeoutExpired:
                            form.after(0, lambda: status_label.config(text="❌ Init timed out"))
                            form.after(0, lambda: messagebox.showerror("Timeout", "Repository initialization timed out"))
                        except Exception as e:
                            form.after(0, lambda: status_label.config(text=f"❌ Error: {str(e)}"))
                            form.after(0, lambda: messagebox.showerror("Error", str(e)))
                    
                    threading.Thread(target=run_init, daemon=True).start()
                else:
                    # Existing repo or editing - just save
                    finish_save(n, p)
            
            def finish_save(n, p):
                self.config_manager.add_repo(
                    n, p, 
                    pass_cmd=cmd_pass_var.get().strip(),
                    ssh_password=ssh_pass_var.get().strip(),
                    repo_passphrase=repo_pass_var.get().strip()
                )
                
                # Refresh listbox from source server repos
                listbox.delete(0, tk.END)
                updated_srv = self.config_manager.get_source_server(self.active_source_id)
                if updated_srv:
                    for r in updated_srv.get("repos", {}).keys():
                        listbox.insert(tk.END, r)
                
                self.log(f"User added/updated Repo: {n}", "AUDIT")
                form.destroy()

            ttk.Button(form, text="Save", command=save).pack(pady=20)



        def edit_selected():
            sel = listbox.curselection()
            if not sel: return
            name = listbox.get(sel[0])
            show_repo_form(name)

        def delete_selected():
            sel = listbox.curselection()
            if sel:
                name = listbox.get(sel[0])
                if messagebox.askyesno("Delete", f"Remove config for '{name}'?"):
                    self.config_manager.delete_repo(name)
                    listbox.delete(sel[0])
                    self.log(f"User deleted Repo config: {name}", "AUDIT")

        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill=tk.X, pady=10, padx=10)
        
        # Use grid layout for even spacing
        for i in range(4):
            btn_frame.columnconfigure(i, weight=1)
        
        ttk.Button(btn_frame, text=f"{icon('confirm')} Select", command=load_selected).grid(row=0, column=0, padx=2, sticky="ew")
        ttk.Button(btn_frame, text="➕ Add", command=lambda: show_repo_form(None)).grid(row=0, column=1, padx=2, sticky="ew")
        ttk.Button(btn_frame, text="Edit", command=edit_selected).grid(row=0, column=2, padx=2, sticky="ew")
        ttk.Button(btn_frame, text=f"{icon('delete')} Delete", command=delete_selected).grid(row=0, column=3, padx=2, sticky="ew")

    # --- SOURCE SERVER MANAGER ---
    def open_source_server_manager(self):
        """Manage remote source servers for backup."""
        win = tk.Toplevel(self)
        win.title("Manage Source Servers")
        win.configure(bg=self.get_theme_color("bg_window"))
        win.geometry("700x500")
        
        ttk.Label(win, text="Source Servers (machines to backup)", font=("", 11, "bold")).pack(pady=10)
        
        # Main list
        list_frame = ttk.Frame(win)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("name", "host", "repos")
        tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=12)
        tree.heading("name", text="Name")
        tree.heading("host", text="Host")
        tree.heading("repos", text="Linked Repos")
        tree.column("name", width=150)
        tree.column("host", width=200)
        tree.column("repos", width=300)
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        def refresh_list():
            for item in tree.get_children():
                tree.delete(item)
            servers = self.config_manager.get_source_servers()
            for sid, srv in servers.items():
                name = srv.get("name", sid)
                host = srv.get("host") or "(Local Machine)"
                repos = ", ".join(srv.get("repos", []))
                tree.insert("", tk.END, iid=sid, values=(name, host, repos))
        
        refresh_list()
        
        def show_server_form(server_id=None):
            form = tk.Toplevel(win)
            form.title("Edit Source Server" if server_id else "Add Source Server")
            form.configure(bg=self.get_theme_color("bg_window"))
            form.geometry("600x600") # Increased height, but scrollbar handles overflow
            
            # --- SCROLLABLE CONTAINER ---
            # --- SCROLLABLE CONTAINER ---
            container = ttk.Frame(form)
            container.pack(fill=tk.BOTH, expand=True)
            
            canvas = tk.Canvas(container, bg=self.get_theme_color("bg_window"), highlightthickness=0)
            scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
            
            scrollable_frame = ttk.Frame(canvas, padding=20)
            
            # Dynamic Scrollbar Logic
            def update_scroll_region(event):
                canvas.configure(scrollregion=canvas.bbox("all"))
                # Check if content is taller than canvas
                if canvas.bbox("all")[3] > canvas.winfo_height():
                    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                    canvas.bind_all("<MouseWheel>", _on_mousewheel)
                else:
                    scrollbar.pack_forget()
                    canvas.unbind_all("<MouseWheel>")
            
            scrollable_frame.bind("<Configure>", update_scroll_region)
            container.bind("<Configure>", lambda e: update_scroll_region(None))
            
            # Create window inside canvas
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            # Mousewheel scrolling
            def _on_mousewheel(event):
                canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            
            # Load existing data
            data = {"name": "", "host": "", "ssh_key": "", "repos": []}
            if server_id and server_id != "__local__":
                srv = self.config_manager.get_source_server(server_id)
                if srv:
                    data = {"name": srv.get("name", ""), "host": srv.get("host", ""), 
                            "ssh_key": srv.get("ssh_key", ""), "repos": srv.get("repos", [])}
            
            # --- SECTION 1: SERVER DETAILS ---
            ttk.Label(scrollable_frame, text="1. Server Details", font=("", 11, "bold")).pack(anchor=tk.W, pady=(0,10))

            ttk.Label(scrollable_frame, text="Server Name:").pack(anchor=tk.W)
            name_var = tk.StringVar(value=data["name"])
            ttk.Entry(scrollable_frame, textvariable=name_var, width=50).pack(fill=tk.X, pady=(0, 10))
            
            ttk.Label(scrollable_frame, text="SSH Host (user@hostname):").pack(anchor=tk.W)
            host_var = tk.StringVar(value=data["host"])
            ttk.Entry(scrollable_frame, textvariable=host_var, width=50).pack(fill=tk.X, pady=(0, 10))
            
            ttk.Label(scrollable_frame, text="SSH Key Path (optional - for Manual Key):").pack(anchor=tk.W)
            key_var = tk.StringVar(value=data["ssh_key"] or "")
            key_frame = ttk.Frame(scrollable_frame)
            key_frame.pack(fill=tk.X, pady=(0, 10))
            ttk.Entry(key_frame, textvariable=key_var, width=40).pack(side=tk.LEFT, fill=tk.X, expand=True)
            ttk.Button(key_frame, text="Browse", command=lambda: key_var.set(filedialog.askopenfilename())).pack(side=tk.RIGHT)
            
            # --- SSH SETUP (WORKSTATION -> SOURCE) ---
            ssh_frame = ttk.LabelFrame(scrollable_frame, text="SSH Setup (Workstation → This Server)", padding=10)
            ssh_frame.pack(fill=tk.X, pady=10)
            
            def do_setup_local_ssh():
                host = host_var.get().strip()
                if not host:
                    messagebox.showerror("Error", "Enter SSH Host first.")
                    return
                if host == "(Local Machine)": return
                
                # 1. Find or Generate Local Key
                pubkey_paths = [
                    os.path.expanduser("~/.ssh/id_rsa.pub"),
                    os.path.expanduser("~/.ssh/id_ed25519.pub"),
                    os.path.expanduser("~/.ssh/id_ecdsa.pub")
                ]
                pubkey = None
                for p in pubkey_paths:
                    if os.path.exists(p):
                        with open(p, 'r') as f:
                            pubkey = f.read().strip()
                        break
                
                if not pubkey:
                    if messagebox.askyesno("No SSH Key", "No SSH key found on THIS machine.\nGenerate one now?"):
                        try:
                            key_dir = os.path.expanduser("~/.ssh")
                            if not os.path.exists(key_dir): os.makedirs(key_dir)
                            key_path = os.path.join(key_dir, "id_rsa")
                            subprocess.run(["ssh-keygen", "-t", "rsa", "-N", "", "-f", key_path], check=True)
                            with open(key_path + ".pub", 'r') as f:
                                pubkey = f.read().strip()
                        except Exception as e:
                            messagebox.showerror("Error", f"Failed to generate key: {e}")
                            return
                    else:
                        return

                # 2. Ask for Password
                ssh_user = "root"
                
                if "@" in host:
                    ssh_user, _ = host.split("@", 1)
                
                password = simpledialog.askstring("SSH Password", 
                    f"Enter password for {host}\n(To install SSH key):", show="*", parent=form)
                if not password: return

                # 3. Push Key
                def worker():
                    self.log(f"Pushing SSH key to {host}...", "INFO")
                    try:
                        # Parse host for paramiko
                        p_user = ssh_user
                        p_host = host.split("@")[1] if "@" in host else host
                        p_port = 22
                        if ":" in p_host:
                            p_host, port_str = p_host.rsplit(":", 1)
                            try: p_port = int(port_str)
                            except: pass

                        if HAS_PARAMIKO:
                            import paramiko
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            ssh.connect(p_host, port=p_port, username=p_user, password=password, timeout=10)
                            
                            cmd = f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '{pubkey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
                            stdin, stdout, stderr = ssh.exec_command(cmd)
                            status = stdout.channel.recv_exit_status()
                            ssh.close()
                            
                            if status == 0:
                                self.log(f"SSH key pushed to {host}", "SUCCESS")
                                self.after(0, lambda: messagebox.showinfo("Success", "SSH Key installed successfully!", parent=form))
                            else:
                                err = stderr.read().decode()
                                raise Exception(f"Remote command failed: {err}")
                        else:
                            raise Exception("Paramiko required.")
                    except Exception as e:
                        self.log(f"Failed to push SSH key: {e}", "ERROR")
                        self.after(0, lambda: messagebox.showerror("Error", str(e), parent=form))

                threading.Thread(target=worker, daemon=True).start()

            ttk.Button(ssh_frame, text="🔑 Send SSH Key (Workstation → Source)", command=do_setup_local_ssh).pack(fill=tk.X)
            ttk.Label(ssh_frame, text="Enables password-less access from this app to the source server.", font=("", 8), foreground="gray").pack(pady=(5,0))

            # --- SECTION 2: REPOS ---
            ttk.Label(scrollable_frame, text="2. Linked Repositories", font=("", 11, "bold")).pack(anchor=tk.W, pady=(20, 5))
            
            # Repo selection
            repo_listbox = tk.Listbox(scrollable_frame, selectmode=tk.MULTIPLE, height=5,
                                      bg=self.get_theme_color("bg_card"), fg=self.get_theme_color("text_main"))
            repo_listbox.pack(fill=tk.X, pady=5)
            
            all_repos = list(self.config_manager.config.get("repos", {}).keys())
            for r in all_repos:
                repo_listbox.insert(tk.END, r)
                if r in data["repos"]:
                    repo_listbox.selection_set(all_repos.index(r))
            
            # Note: Repo SSH setup moved to Repo Dialog as per request.
            
            
            def save():
                name = name_var.get().strip()
                host = host_var.get().strip()
                ssh_key = key_var.get().strip() or None
                
                if not name:
                    messagebox.showerror("Error", "Name is required.")
                    return
                
                selected_repos = [repo_listbox.get(i) for i in repo_listbox.curselection()]
                
                # Generate ID from name if new
                sid = server_id or re.sub(r'[^a-zA-Z0-9]', '_', name.lower())
                
                self.config_manager.add_source_server(sid, name, host, ssh_key, selected_repos)
                self.log(f"Source server saved: {name}", "AUDIT")
                form.destroy()
                refresh_list()
            
            ttk.Button(scrollable_frame, text="💾 Save Configuration", command=save).pack(pady=20)
        
        def edit_selected():
            sel = tree.selection()
            if sel:
                show_server_form(sel[0])
        
        def delete_selected():
            sel = tree.selection()
            if sel:
                sid = sel[0]
                if sid == "__local__":
                    messagebox.showwarning("Cannot Delete", "Cannot delete the Local Machine entry.")
                    return
                if messagebox.askyesno("Delete", f"Remove source server '{sid}'?"):
                    self.config_manager.delete_source_server(sid)
                    refresh_list()
        
        def install_borg_on_selected():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select Server", "Please select a source server.")
                return
            srv = self.config_manager.get_source_server(sel[0])
            if not srv or not srv.get("host"):
                messagebox.showwarning("Invalid", "Cannot install on local machine.")
                return
            
            host = srv["host"]
            ssh_key = srv.get("ssh_key")
            
            def worker():
                self.log(f"Installing borg on {host}...", "INFO")
                # Build SSH command
                ssh_cmd = ["ssh"]
                if ssh_key:
                    ssh_cmd += ["-i", ssh_key]
                ssh_cmd.append(host)
                ssh_cmd.append("which borg || (apt-get update && apt-get install -y borgbackup) || (yum install -y borgbackup) || (dnf install -y borgbackup)")
                
                try:
                    result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=120)
                    if result.returncode == 0:
                        self.log(f"Borg installed on {host}", "SUCCESS")
                        messagebox.showinfo("Success", f"Borg installed on {host}")
                    else:
                        self.log(f"Borg install failed: {result.stderr}", "ERROR")
                        messagebox.showerror("Failed", f"Install failed: {result.stderr}")
                except Exception as e:
                    self.log(f"SSH error: {e}", "ERROR")
                    messagebox.showerror("Error", str(e))
            
            threading.Thread(target=worker, daemon=True).start()
        
        def set_active_selected():
            """Set the selected server as the active source server."""
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select Server", "Please select a source server to set as active.")
                return
            
            server_id = sel[0]
            srv = self.config_manager.get_source_server(server_id)
            if not srv:
                return
            
            # Check for Windows - can't use local
            if platform.system() == "Windows" and server_id == "__local__":
                messagebox.showwarning("Not Supported", 
                    "Local Machine cannot be used on Windows.\nPlease select a remote server.")
                return
            
            # Close manager window first to avoid stacking dialogs
            win.destroy()
            
            # Set as active - this will show repo selection dialog if needed
            srv_name = srv.get("name", server_id)
            self.log(f"Active source server changed to: {srv_name}", "AUDIT")
            self._set_active_source(server_id)
            
            # Refresh the main UI - full dashboard refresh
            self.refresh_repo_display()
            self._refresh_dashboard()
        
        # Buttons
        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill=tk.X, pady=10, padx=10)
        
        ttk.Button(btn_frame, text="✓ Set Active", command=set_active_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="➕ Add", command=lambda: show_server_form(None)).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Edit", command=edit_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🗑 Delete", command=delete_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🔧 Install Borg", command=install_borg_on_selected).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="📦 Manage Repos", command=self.open_repo_manager).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Close", command=win.destroy).pack(side=tk.RIGHT, padx=2)

    # --- CRON MANAGER (NEW) ---
    def open_cron_manager(self):
        """Displays raw system crontab lines managed by this app."""
        win = tk.Toplevel(self)
        
        # Show which source's cron we're managing
        if self.active_ssh_helper and self.active_source_id:
            srv = self.config_manager.get_source_server(self.active_source_id)
            source_name = srv.get("name", self.active_source_id) if srv else self.active_source_id
            win.title(f"Manage System Cron - {source_name}")
        else:
            win.title("Manage System Cron - Local")
        
        win.configure(bg=self.get_theme_color("bg_window"))
        win.geometry("650x450")

        lbl = ttk.Label(win, text="System Cron Jobs (Filtered for Borg-GUI)")
        lbl.pack(pady=(10, 5))
        
        ttk.Label(win, text="Note: 'Internal Timer' jobs run inside the app and do not appear here.", foreground="gray").pack(pady=(0, 10))
        
        self.var_show_all_cron = tk.BooleanVar(value=False) # Init var

        listbox = tk.Listbox(win, width=80, bg=self.get_theme_color("bg_card"), fg=self.get_theme_color("text_main"))
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Helper to extract job ID if present
        def get_job_id_from_line(line):
             # Marker format: # BORG_GUI_JOB_{id}
             match = re.search(r"# BORG_GUI_JOB_([a-f0-9\-]+)", line)
             if match: return match.group(1)
             return None

        def refresh():
            listbox.delete(0, tk.END)
            try:
                if self.active_ssh_helper:
                    # Remote crontab via SSH
                    success, output, _ = self.active_ssh_helper.execute("crontab -l 2>/dev/null || true")
                    # If command failed but connected, output might be empty or error msg if 2> not redirected well
                    lines = output.strip().splitlines() if success else []
                else:
                    # Local crontab
                    res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                    lines = res.stdout.strip().splitlines()
                
                show_all = self.var_show_all_cron.get()
                count = 0
                for line in lines:
                    if show_all or "# BORG_GUI_JOB_" in line:
                        listbox.insert(tk.END, line)
                        count += 1
                
                if count == 0:
                     msg = "(No jobs found)" if show_all else "(No Borg-GUI jobs found in crontab)"
                     listbox.insert(tk.END, msg)
            except Exception as e:
                listbox.insert(tk.END, f"Error reading crontab: {e}")

        def delete_selected():
            sel = listbox.curselection()
            if not sel: return
            line = listbox.get(sel[0])
            if "(No Borg" in line: return

            job_id = get_job_id_from_line(line)
            if not job_id:
                messagebox.showerror("Error", "Could not identify Job ID from line.")
                return

            if messagebox.askyesno("Delete", "Remove this cron job from system?"):
                try:
                    # Reuse existing update_crontab logic to remove
                    CronManager.update_crontab(job_id, "", "", enable=False, ssh_helper=self.active_ssh_helper)
                    refresh()
                    self.log(f"User removed cron job via Manager: {job_id}", "AUDIT")
                except Exception as e:
                    messagebox.showerror("Error", str(e))

        refresh()

        btn_frame = ttk.Frame(win, padding=10)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text=f"{icon('refresh')} Refresh", command=refresh).pack(side=tk.LEFT)
        ttk.Checkbutton(btn_frame, text="Show All System Jobs", variable=self.var_show_all_cron, command=refresh).pack(side=tk.LEFT, padx=10) # Add Checkbutton here
        ttk.Button(btn_frame, text=f"{icon('delete')} Delete Selected", command=delete_selected).pack(side=tk.RIGHT)

    def open_dependency_manager(self):
        win = tk.Toplevel(self)
        win.title("🔧 Dependency Manager")
        win.configure(bg=self.get_theme_color("bg_window"))
        win.geometry("800x650")
        
        bg = self.get_theme_color("bg_window")
        fg = self.get_theme_color("text_main")
        
        # Header
        header = tk.Frame(win, bg=bg)
        header.pack(fill=tk.X, padx=20, pady=15)
        tk.Label(header, text="🔧 Dependency Manager", font=(DEFAULT_FONT, 16, "bold"),
                bg=bg, fg=fg).pack(side=tk.LEFT)
        tk.Label(header, text="Check and install required components", font=(DEFAULT_FONT, 10),
                bg=bg, fg="#888").pack(side=tk.LEFT, padx=20)

        # Main container with Card background
        container_bg = self.get_theme_color("bg_card")
        container = tk.Frame(win, bg=container_bg)
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))
        
        # Grid Header with better styling
        headers = [("Component", 140), ("Type", 80), ("Status", 180), ("Action", 250)]
        for i, (txt, w) in enumerate(headers):
            tk.Label(container, text=txt, bg="#27ae60", fg="white", font=(DEFAULT_FONT, 10, "bold"),
                    anchor="w", width=w//7, padx=8).grid(row=0, column=i, sticky="ew", pady=1, padx=1)
        
        row_idx = 1
        text_col = self.get_theme_color("text_main")
        
        row_idx = 1
        text_col = self.get_theme_color("text_main")

        def check_and_add_row(name, type_str, check_func, install_cmd_func=None):
            nonlocal row_idx
            status, status_text = check_func()
            
            fg_color = "#2ecc71" if status else "#e74c3c" # Green / Red
            status_display = "✅ Installed" if status else f"❌ Missing ({status_text})" if status_text else "❌ Missing"
            
            tk.Label(container, text=name, bg=container_bg, fg=text_col).grid(row=row_idx, column=0, sticky="w", padx=10, pady=5)
            tk.Label(container, text=type_str, bg=container_bg, fg=text_col).grid(row=row_idx, column=1, sticky="w", padx=10, pady=5)
            tk.Label(container, text=status_display, bg=container_bg, fg=fg_color).grid(row=row_idx, column=2, sticky="w", padx=10, pady=5)
            
            if not status and install_cmd_func:
                btn_frame = tk.Frame(container, bg=container_bg)
                btn_frame.grid(row=row_idx, column=3, sticky="w", padx=10, pady=5)
                install_cmd_func(btn_frame)
            
            row_idx += 1

        # --- Checks ---
        # 1. System Binaries
        def check_bin(b): return (True, "") if shutil.which(b) else (False, "Not found in PATH")
        
        def sys_install_ui(parent, pkg_names):
            mgr = "apt" if shutil.which("apt") else "dnf" if shutil.which("dnf") else "pacman" if shutil.which("pacman") else "yum"
            cmd = ""
            if mgr == "apt": cmd = f"sudo apt install {' '.join(pkg_names)}"
            elif mgr == "dnf": cmd = f"sudo dnf install {' '.join(pkg_names)}"
            elif mgr == "pacman": cmd = f"sudo pacman -S {' '.join(pkg_names)}"
            
            e = ttk.Entry(parent, width=25)
            e.insert(0, cmd)
            e.config(state="readonly")
            e.pack(side=tk.LEFT)
            ttk.Button(parent, text="Copy", command=lambda: self.clipboard_clear() or self.clipboard_append(cmd)).pack(side=tk.LEFT, padx=2)

        check_and_add_row("borg", "Binary", lambda: check_bin("borg"), lambda f: sys_install_ui(f, ["borgbackup"]))
        check_and_add_row("ssh", "Binary", lambda: check_bin("ssh"), lambda f: sys_install_ui(f, ["openssh-client"]))
        check_and_add_row("sshpass", "Binary", lambda: check_bin("sshpass"), lambda f: sys_install_ui(f, ["sshpass"]))
        
        # 2. Python Packages
        def check_pip(p): return (True, "") if importlib.util.find_spec(p) else (False, "Not found")
        
        def pip_install_ui(parent, pkg):
            def run_pip():
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
                    messagebox.showinfo("Success", f"Installed {pkg}. Please restart the app.")
                    win.destroy()
                    self.open_dependency_manager() # Refresh
                except Exception as e:
                    messagebox.showerror("Error", f"Pip install failed: {e}")

            ttk.Button(parent, text=f"Install {pkg}", command=run_pip).pack(side=tk.LEFT)

        check_and_add_row("pystray", "Python Lib", lambda: check_pip("pystray"), lambda f: pip_install_ui(f, "pystray"))
        check_and_add_row("Pillow", "Python Lib", lambda: check_pip("PIL"), lambda f: pip_install_ui(f, "Pillow"))
        check_and_add_row("matplotlib", "Python Lib", lambda: check_pip("matplotlib"), lambda f: pip_install_ui(f, "matplotlib"))
        
        # 3. System Libraries (Linux Tray)
        def check_appindicator():
            if platform.system() != "Linux": return True, "Not required (Windows/Mac)"
            try:
                import gi
                try:
                    gi.require_version('AppIndicator3', '0.1')
                    return True, ""
                except (ValueError, ImportError):
                    gi.require_version('AyatanaAppIndicator3', '0.1')
                    return True, "Ayatana"
            except:
                return False, "Lib Missing"

        check_and_add_row("AppIndicator3", "System Lib", check_appindicator, 
                          lambda f: sys_install_ui(f, ["gir1.2-appindicator3-0.1", "gir1.2-ayatanaappindicator3-0.1"]))

        # === REMOTE SOURCE SERVER CHECKS ===
        if self.active_ssh_helper:
            # Separator
            row_idx += 1
            tk.Label(container, text="", bg=container_bg).grid(row=row_idx, column=0, pady=5)
            row_idx += 1
            tk.Label(container, text=f"── Source Server: {self.active_source_id} ──", 
                    bg=container_bg, fg="blue", font=("", 10, "bold")).grid(row=row_idx, column=0, columnspan=4, pady=10)
            row_idx += 1
            
            def check_remote_bin(b):
                success, output, _ = self.active_ssh_helper.execute(f"which {b} &>/dev/null && echo OK || echo MISSING")
                if "OK" in output:
                    return (True, "")
                return (False, "Not found")
            
            def remote_install_ui(parent, pkg_names):
                def do_install():
                    # Detect package manager on remote
                    cmd = "apt-get -y install " + " ".join(pkg_names) + " || yum -y install " + " ".join(pkg_names) + " || dnf -y install " + " ".join(pkg_names)
                    full_cmd = f"sudo {cmd}"
                    
                    def run():
                        success, output, error = self.active_ssh_helper.execute(full_cmd, timeout=120)
                        if success:
                            self.after(0, lambda: messagebox.showinfo("Success", f"Installed on source server!"))
                        else:
                            self.after(0, lambda: messagebox.showerror("Error", f"Install failed: {error}"))
                    
                    threading.Thread(target=run, daemon=True).start()
                
                ttk.Button(parent, text="Install", command=do_install).pack(side=tk.LEFT)
            
            check_and_add_row("borg (remote)", "Binary", lambda: check_remote_bin("borg"), lambda f: remote_install_ui(f, ["borgbackup"]))
            check_and_add_row("ssh (remote)", "Binary", lambda: check_remote_bin("ssh"), lambda f: remote_install_ui(f, ["openssh-client"]))
            check_and_add_row("sshpass (remote)", "Binary", lambda: check_remote_bin("sshpass"), lambda f: remote_install_ui(f, ["sshpass"]))

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=20)


    def _build_charts_tab(self):
        if not HAS_MATPLOTLIB:
            ttk.Label(self.tab_charts, text="Matplotlib is required for charts.\nPlease install it: pip install matplotlib").pack(pady=20)
            return

        self.chart_container = ttk.Frame(self.tab_charts)
        self.chart_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header / Connect
        head = ttk.Frame(self.chart_container)
        head.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(head, text=f"{icon('refresh')} Refresh Charts", command=self._refresh_charts).pack(side=tk.RIGHT)
        ttk.Label(head, text="Repository Trends", font=("", 14, "bold")).pack(side=tk.LEFT)
        
        # Scrollable area for charts
        self.charts_canvas_area = ttk.Frame(self.chart_container)
        self.charts_canvas_area.pack(fill=tk.BOTH, expand=True)

    def _refresh_charts(self):
        if not HAS_MATPLOTLIB: return
        
        # Clear previous
        for w in self.charts_canvas_area.winfo_children():
            w.destroy()
            
        history = self.config_manager.get_history()
        if not history:
            ttk.Label(self.charts_canvas_area, text="No history data available.").pack(pady=20)
            return
            
        # Parse Data
        dates = []
        orig_sizes = []
        comp_sizes = []
        durations = []
        
        # Helper to parse size string "1.5 MB" -> MB float
        def parse_sz(s):
            if not s or s == "0 B": return 0.0
            try:
                p = s.split(' ')
                if len(p) < 2: return 0.0
                val = float(p[0])
                unit = p[1].upper()
                if "KB" in unit: val /= 1024
                elif "MB" in unit: pass # Base unit
                elif "GB" in unit: val *= 1024
                elif "TB" in unit: val *= 1024 * 1024
                return val
            except:
                return 0.0
            
        def parse_dur(s):
            # 00:00:10 -> seconds
            try:
                parts = list(map(int, s.split(':')))
                return parts[0]*3600 + parts[1]*60 + parts[2]
            except: return 0
        
        # Get last 30 jobs in chronological order
        chronological_history = list(reversed(history[:30])) 
        
        for h in chronological_history:
             start = h.get('start', '')
             if len(start) > 5: dates.append(start[5:]) 
             else: dates.append("?")
             
             stats = h.get('stats', {})
             orig_sizes.append(parse_sz(stats.get('original', '0 B')))
             comp_sizes.append(parse_sz(stats.get('compressed', '0 B')))
             durations.append(parse_dur(h.get('duration', '00:00:00')))

        # THEME COLORS
        bg = self.get_theme_color("bg_window")
        fg = self.get_theme_color("text_main")
        grid_col = "#555" if self.current_theme == "dark" else "#ddd"
        
        # Plotting
        fig = Figure(figsize=(8, 8), dpi=100)
        fig.patch.set_facecolor(bg)
        
        # 1. Storage Growth
        ax1 = fig.add_subplot(211) # Top
        ax1.set_facecolor(bg)
        ax1.plot(dates, orig_sizes, label="Original (MB)", marker='o', color=self.get_theme_color("stat_orig"))
        ax1.plot(dates, comp_sizes, label="Compressed (MB)", marker='x', color=self.get_theme_color("stat_comp"))
        
        ax1.set_title("Repository Size Trends", color=fg)
        ax1.set_ylabel("Size (MB)", color=fg)
        ax1.tick_params(colors=fg, axis='x', rotation=45)
        ax1.tick_params(colors=fg, axis='y')
        ax1.grid(True, color=grid_col)
        ax1.legend(facecolor=bg, labelcolor=fg)
        
        # 2. Duration Bar Chart
        ax2 = fig.add_subplot(212) # Bottom
        ax2.set_facecolor(bg)
        bars = ax2.bar(dates, durations, color=self.get_theme_color("stat_dedup"), alpha=0.7)
        
        ax2.set_title("Backup Duration (seconds)", color=fg)
        ax2.set_ylabel("Seconds", color=fg)
        ax2.tick_params(colors=fg, axis='x', rotation=45)
        ax2.tick_params(colors=fg, axis='y')
        ax2.grid(True, axis='y', color=grid_col)
        
        fig.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, master=self.charts_canvas_area)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

if __name__ == "__main__":
    app = BorgApp()
    app.mainloop()