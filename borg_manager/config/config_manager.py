"""
Borg Manager - Configuration Manager

Manages application configuration, repositories, source servers, and job history.
"""

import os
import json
import shutil
import uuid
import logging
from typing import Optional, Dict, Any, List

from ..utils.constants import CONFIG_FILE
from ..utils.security import store_passphrase, retrieve_passphrase

logger = logging.getLogger('BorgManager')


class ConfigManager:
    """Manages application configuration, repositories, and job history."""
    
    def __init__(self):
        """Initialize configuration manager and load config."""
        self.active_source_id: Optional[str] = None
        self.config: Dict[str, Any] = {
            "current_repo": None,
            "borg_binary": None,
            "jobs": {},
            "source_servers": {
                "__local__": {
                    "name": "Local Machine",
                    "host": None,
                    "ssh_key": None,
                    "repos": {}
                }
            },
            "log_settings": {
                "active_days": 7,
                "archive_days": 90
            }
        }
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from file, with legacy migration support."""
        # Legacy config support
        old_config = os.path.expanduser("~/.config/borg-gui-config.json")
        if os.path.exists(old_config) and not os.path.exists(CONFIG_FILE):
            try:
                shutil.move(old_config, CONFIG_FILE)
            except Exception:
                pass

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

    def save_config(self) -> None:
        """Save configuration to file."""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving config: {e}")

    # --- HISTORY MANAGEMENT ---
    
    def add_history_entry(self, job_name: str, repo_name: str, status: str, 
                          duration: str, start_time: str, stats: Optional[Dict] = None, 
                          source: Optional[str] = None) -> None:
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
        
    def get_history(self) -> List[Dict]:
        """Get job execution history."""
        return self.config.get("history", [])

    # --- SOURCE SERVER MANAGEMENT ---
    
    def set_active_source(self, source_id: str) -> None:
        """Set the active source server for repo operations."""
        self.active_source_id = source_id
    
    def get_active_source_repos(self) -> Dict:
        """Get repos dict for active source server."""
        if not self.active_source_id:
            return {}
        srv = self.config.get("source_servers", {}).get(self.active_source_id)
        if srv:
            return srv.get("repos", {})
        return {}

    def get_source_servers(self) -> Dict:
        """Returns dict of all source servers."""
        return self.config.get("source_servers", {})
    
    def add_source_server(self, server_id: str, name: str, host: str, 
                          ssh_key: Optional[str] = None, repos: Optional[Dict] = None) -> None:
        """Add or update a source server."""
        if "source_servers" not in self.config:
            self.config["source_servers"] = {}
        
        self.config["source_servers"][server_id] = {
            "name": name,
            "host": host,
            "ssh_key": ssh_key,
            "repos": repos if isinstance(repos, dict) else {}
        }
        self.save_config()
    
    def delete_source_server(self, server_id: str) -> bool:
        """Delete a source server (cannot delete __local__)."""
        if server_id == "__local__":
            return False
        if server_id in self.config.get("source_servers", {}):
            del self.config["source_servers"][server_id]
            self.save_config()
            return True
        return False
    
    def get_source_server(self, server_id: str) -> Optional[Dict]:
        """Get details of a specific source server."""
        return self.config.get("source_servers", {}).get(server_id)

    # --- REPOSITORY MANAGEMENT ---

    def add_repo(self, name: str, path: str, pass_cmd: str = "", 
                 ssh_password: str = "", repo_passphrase: str = "", 
                 source_id: Optional[str] = None) -> None:
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
            "repo_passphrase": "" if stored_in_keyring else repo_passphrase,
            "passphrase_in_keyring": stored_in_keyring
        }
        if not self.config["current_repo"]:
            self.config["current_repo"] = name
        self.save_config()
    
    def get_repo_passphrase(self, name: str, source_id: Optional[str] = None) -> str:
        """Get passphrase for a repo, checking keyring first then config."""
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

    def delete_repo(self, name: str, source_id: Optional[str] = None) -> None:
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

    def get_repo_details(self, name: str, source_id: Optional[str] = None):
        """Get repo details from specified (or active) source server."""
        sid = source_id or self.active_source_id
        if not sid:
            return None
        repos = self.config.get("source_servers", {}).get(sid, {}).get("repos", {})
        return repos.get(name)

    def set_borg_binary(self, path: str) -> None:
        """Set the path to borg binary."""
        self.config["borg_binary"] = path
        self.save_config()
    
    # --- JOB MANAGEMENT ---
    
    def save_job(self, job_data: Dict) -> str:
        """Save a scheduled job configuration."""
        if "id" not in job_data or not job_data["id"]:
            job_data["id"] = str(uuid.uuid4())
        self.config["jobs"][job_data["id"]] = job_data
        self.save_config()
        return job_data["id"]

    def delete_job(self, job_id: str) -> None:
        """Delete a scheduled job."""
        if job_id in self.config["jobs"]:
            del self.config["jobs"][job_id]
            self.save_config()
