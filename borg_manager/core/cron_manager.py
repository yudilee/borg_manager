"""
Borg Manager - Cron Manager

Handles cron job generation and management for scheduled backups.
"""

import os
import re
import stat
import base64
import shutil
import subprocess
import logging
from typing import Optional, Dict, Any, List

from ..utils.constants import SCRIPTS_DIR, LOGS_DIR

logger = logging.getLogger('BorgManager')


class CronManager:
    """Manages cron jobs and backup script generation."""
    
    @staticmethod
    def generate_job_script(job: Dict, repo_config: Dict, borg_bin: str, 
                            ssh_helper=None) -> str:
        """Generates a standalone .sh script for the backup job.
        
        Args:
            job: Job configuration dict
            repo_config: Repository configuration
            borg_bin: Path to borg binary
            ssh_helper: Optional SSHHelper for remote script deployment
            
        Returns:
            Path to generated script
        """
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
            borg_inv = "borg"
        else:
            # Local paths
            if not os.path.exists(SCRIPTS_DIR):
                os.makedirs(SCRIPTS_DIR)
            script_path = os.path.join(SCRIPTS_DIR, f"job_{job_id}_{safe_name}.sh")
            log_file = os.path.join(LOGS_DIR, f"job_{job_id}_cron.log")
            history_file = "$HOME/.config/borg_manager/logs/cron_history.jsonl"
            borg_inv = borg_bin
        
        repo_path = repo_config["path"]
        
        # Build excludes
        args = []
        for exc in job.get("excludes", []):
            args.append(f"--exclude '{exc}'")
        
        # Archive Name Format
        archive_name = f"{safe_name}-$(date +%Y-%m-%d-%H%M)"
        
        # Environment Setup
        env_vars = [f"export BORG_REPO='{repo_path}'"]
        
        if repo_config.get("repo_passphrase"):
            env_vars.append(f"export BORG_PASSPHRASE='{repo_config['repo_passphrase']}'")
        elif repo_config.get("pass_command"):
            env_vars.append(f"export BORG_PASSCOMMAND='{repo_config['pass_command']}'")
             
        rsh_cmd = "ssh -o StrictHostKeyChecking=accept-new"
        if repo_config.get("ssh_password") and shutil.which("sshpass"):
            env_vars.append(f"export SSHPASS='{repo_config['ssh_password']}'")
            rsh_cmd = f"sshpass -e {rsh_cmd}"
        
        env_vars.append(f"export BORG_RSH='{rsh_cmd}'")
        env_vars.append("export BORG_RELOCATED_REPO_ACCESS_IS_OK=no")

        # Script Content
        content = [
            "#!/bin/bash",
            f"# Borg Backup Job: {job['name']}",
            f"# ID: {job_id}",
            "",
            f"echo \"Starting Backup: $(date)\" >> {log_file}",
            "",
            "# Environment Variables"
        ]
        content.extend(env_vars)
        
        # Borg Create Command
        includes_str = "' '".join(job.get("includes", []))
        if includes_str:
            includes_str = f"'{includes_str}'"
        
        borg_cmd = f"{borg_inv} create --stats --compression zstd,6 {' '.join(args)} ::{archive_name} {includes_str}"
        
        content.append("")
        content.append("# Run Backup")
        content.append(f"{borg_cmd} >> {log_file} 2>&1")
        
        # Capture status
        content.append("if [ $? -eq 0 ]; then")
        content.append(f"    echo \"Backup Success: $(date)\" >> {log_file}")
        content.append("    JOB_STATUS=\"Success\"")
        
        # Pruning Logic
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
        
        # JSON History Logging
        content.append("")
        content.append("# --- JSON HISTORY LOGGING ---")
        content.append(f"HISTORY_FILE=\"{history_file}\"")
        content.append("mkdir -p \"$(dirname \"$HISTORY_FILE\")\"")
        content.append("END_TIME=$(date +%Y-%m-%d\\ %H:%M)")
        content.append("DURATION=\"Unknown\"")
        content.append(f"JOB_NAME=\"{job['name']}\"")
        content.append(f"REPO_NAME=\"{repo_config.get('path', 'Unknown')}\"")
        content.append("JSON_ENTRY=\"{\\\"job\\\": \\\"$JOB_NAME\\\", \\\"repo\\\": \\\"$REPO_NAME\\\", \\\"status\\\": \\\"$JOB_STATUS\\\", \\\"duration\\\": \\\"$DURATION\\\", \\\"start\\\": \\\"$END_TIME\\\", \\\"source\\\": \\\"cron\\\"}\"")
        content.append("echo \"$JSON_ENTRY\" >> \"$HISTORY_FILE\"")

        script_content_str = "\n".join(content)

        if ssh_helper:
            # Remote Write using base64 to avoid quoting issues
            b64_content = base64.b64encode(script_content_str.encode('utf-8')).decode('utf-8')
            cmd = f"echo '{b64_content}' | base64 -d > {script_path}"
            success, _, err = ssh_helper.execute(cmd)
            if not success:
                raise Exception(f"Failed to write remote script: {err}")
            ssh_helper.execute(f"chmod +x {script_path}")
        else:
            # Local Write
            with open(script_path, 'w') as f:
                f.write(script_content_str)
            st = os.stat(script_path)
            os.chmod(script_path, st.st_mode | stat.S_IEXEC)
        
        return script_path

    @staticmethod
    def get_installed_cron_lines(ssh_helper=None) -> List[str]:
        """Returns list of cron lines managed by this app."""
        try:
            if ssh_helper:
                success, output, _ = ssh_helper.execute("crontab -l 2>/dev/null || true")
                if not success:
                    return []
                lines = output.strip().splitlines()
            else:
                res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                if res.returncode != 0:
                    return []
                lines = res.stdout.strip().splitlines()
            return [line for line in lines if "# BORG_GUI_JOB_" in line]
        except Exception:
            return []

    @staticmethod
    def update_crontab(job_id: str, script_path: str, time_str: str, 
                       frequency: str = "Daily", day: str = "", 
                       enable: bool = True, ssh_helper=None) -> bool:
        """Reads crontab, removes old entry for this job, adds new one if enable=True."""
        try:
            if ssh_helper:
                success, output, _ = ssh_helper.execute("crontab -l 2>/dev/null || true")
                current_cron = output.strip().splitlines() if success else []
            else:
                res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                current_cron = res.stdout.strip().splitlines() if res.returncode == 0 else []
        except Exception:
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
                    days_map = {"Sunday": 0, "Monday": 1, "Tuesday": 2, "Wednesday": 3, 
                                "Thursday": 4, "Friday": 5, "Saturday": 6}
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
            escaped = cron_text.replace("'", "'\"'\"'")
            cmd = f"echo '{escaped}' | crontab -"
            success, _, error = ssh_helper.execute(cmd)
            return success
        else:
            proc = subprocess.run(["crontab", "-"], input=cron_text, text=True)
            return proc.returncode == 0
