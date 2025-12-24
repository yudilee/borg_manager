"""
Borg Manager - SSH Helper

Cross-platform SSH connection handling for remote command execution.
Uses Paramiko if available (Windows), otherwise system ssh command.
"""

import subprocess
import logging
from typing import Optional, Tuple, List, Callable

logger = logging.getLogger('BorgManager')

# Try to import paramiko
HAS_PARAMIKO = False
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    logger.info("Paramiko not found. Will use system SSH command.")


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
    
    def __init__(self, host: str, ssh_key: Optional[str] = None, 
                 password: Optional[str] = None) -> None:
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
    
    def _parse_host(self) -> None:
        """Parse user@hostname into components."""
        if "@" in self.host:
            self.username, self.hostname = self.host.split("@", 1)
        else:
            self.username = None
            self.hostname = self.host
    
    def execute(self, command: str, timeout: int = 300) -> Tuple[bool, str, str]:
        """Execute command on remote host.
        
        Returns:
            tuple: (success: bool, output: str, error: str)
        """
        if HAS_PARAMIKO:
            return self._execute_paramiko(command, timeout)
        else:
            return self._execute_subprocess(command, timeout)
    
    def _execute_paramiko(self, command: str, timeout: int) -> Tuple[bool, str, str]:
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
    
    def _execute_subprocess(self, command: str, timeout: int) -> Tuple[bool, str, str]:
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
    
    def execute_stream(self, command: str, callback: Callable[[str], None], 
                       timeout: int = 600) -> Tuple[bool, str]:
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
    
    def _stream_paramiko(self, command: str, callback: Callable, 
                         timeout: int) -> Tuple[bool, str]:
        """Stream output using Paramiko with proper progress handling."""
        import time
        
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
            
            while not channel.exit_status_ready() or channel.recv_ready():
                if channel.recv_ready():
                    try:
                        chunk = channel.recv(4096).decode("utf-8", errors="replace")
                        buffer += chunk
                        
                        # Process complete lines (split on \r or \n)
                        while '\r' in buffer or '\n' in buffer:
                            r_pos = buffer.find('\r')
                            n_pos = buffer.find('\n')
                            
                            if r_pos == -1:
                                split_pos = n_pos
                            elif n_pos == -1:
                                split_pos = r_pos
                            else:
                                split_pos = min(r_pos, n_pos)
                            
                            line = buffer[:split_pos]
                            if split_pos + 1 < len(buffer) and buffer[split_pos:split_pos+2] == '\r\n':
                                buffer = buffer[split_pos + 2:]
                            else:
                                buffer = buffer[split_pos + 1:]
                            
                            if line.strip():
                                callback(line.strip())
                    except Exception:
                        pass
                else:
                    time.sleep(0.05)
            
            # Process any remaining buffer content
            if buffer.strip():
                callback(buffer.strip())
            
            exit_code = channel.recv_exit_status()
            client.close()
            
            return (exit_code == 0, "")
        except Exception as e:
            return (False, str(e))
    
    def _stream_subprocess(self, command: str, callback: Callable, 
                           timeout: int) -> Tuple[bool, str]:
        """Stream output using subprocess with proper progress handling."""
        ssh_cmd = ["ssh", "-tt"]  # Force PTY allocation
        if self.ssh_key:
            ssh_cmd.extend(["-i", self.ssh_key])
        ssh_cmd.extend(["-o", "StrictHostKeyChecking=accept-new"])
        ssh_cmd.append(self.host)
        ssh_cmd.append(command)
        
        try:
            process = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0
            )
            
            buffer = ""
            while True:
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
            
            if buffer.strip():
                callback(buffer.strip())
            
            process.wait(timeout=timeout)
            
            return (process.returncode == 0, "")
        except subprocess.TimeoutExpired:
            process.kill()
            return (False, "Command timed out")
        except Exception as e:
            return (False, str(e))
    
    def list_dir(self, path: str) -> List[Tuple[str, bool]]:
        """List directory contents on remote host.
        
        Returns:
            list: List of tuples (name, is_dir) or empty list on error
        """
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
            name = " ".join(parts[8:])
            
            if name in (".", ".."):
                continue
            
            is_dir = permissions.startswith("d")
            items.append((name, is_dir))
        
        return sorted(items, key=lambda x: (not x[1], x[0].lower()))
    
    def get_home(self) -> str:
        """Get home directory on remote host."""
        success, output, error = self.execute("echo $HOME", timeout=10)
        if success:
            return output.strip()
        return "/"
    
    def download_file(self, remote_path: str, local_path: str, 
                      progress_callback: Optional[Callable] = None) -> Tuple[bool, str]:
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
            
            def progress(transferred, total):
                if progress_callback:
                    progress_callback(transferred, total)
            
            sftp.get(remote_path, local_path, callback=progress)
            
            sftp.close()
            client.close()
            return (True, "")
        except Exception as e:
            return (False, str(e))
