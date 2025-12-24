# Borg Backup Manager - User Guide

A full-featured graphical interface for managing BorgBackup repositories, scheduled backups, and archive restoration.

## Table of Contents
- [Quick Start](#quick-start)
- [Features Overview](#features-overview)
- [SSH Remote Backups](#ssh-remote-backups)
- [Scheduling Backups](#scheduling-backups)
- [Archive Management](#archive-management)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)
- [Requirements](#requirements)

---

## Quick Start

### 1. Add a Source Server
1. On first launch, you'll be prompted to add a source server
2. For **local backups**: Select "Local Machine"
3. For **remote backups**: Enter SSH details (user@hostname, SSH key path)

### 2. Add a Repository
1. Click **[>] Manage Repos** or go to Tools > Manage Repos
2. Click **[+] Add**
3. Enter repository path:
   - Local: `/path/to/backup/folder`
   - Remote: `ssh://user@hostname/path`
4. Enter passphrase and save

### 3. Create a Backup
1. Go to **New Backup** tab
2. Add folders with **[+] Add**
3. Optionally add excludes (*.tmp, cache/, etc.)
4. Click **[*] START BACKUP**

### 4. Schedule Backups
1. Go to **Scheduler** tab
2. Click **[+] New Job**
3. Set schedule (Daily/Weekly/Monthly, time)
4. Enable **Internal Timer** or **System Cron**
5. Click **[*] Save Job**

### 5. Restore Files
1. Go to **Archives** tab
2. Select an archive
3. Click **[>] Mount**
4. Browse the mounted folder
5. Copy files you need
6. Click **[x] Unmount** when done

---

## Features Overview

| Tab | Purpose |
|-----|---------|
| Dashboard | Overview, stats, and quick actions |
| Archives | Browse and mount backup archives |
| Mounts | Manage currently mounted archives |
| New Backup | Create manual one-time backups |
| Scheduler | Set up automatic scheduled backups |
| Queue | View pending and running jobs |
| Maintenance | Prune, compact, and verify repositories |
| Logs | View operation logs and history |

---

## SSH Remote Backups

### Source vs. Repository Server
- **Source Server**: Where your data lives (the machine to back up)
- **Repository Server**: Where backups are stored

### Setting Up SSH Keys
1. Generate an SSH key: `ssh-keygen -t ed25519`
2. Copy to remote server: `ssh-copy-id user@hostname`
3. In Borg Manager, specify the key path when adding a source server

### Connection String Format
```
ssh://user@hostname:port/path/to/repo
```
- `port` is optional (defaults to 22)
- For local repos: `/path/to/repo`

---

## Scheduling Backups

### Internal Timer vs. System Cron

| Feature | Internal Timer | System Cron |
|---------|----------------|-------------|
| Requires app running | Yes | No |
| Precision | ~15 second checks | Exact minute |
| Platform support | All | Linux/macOS |
| Setup complexity | None | Automatic crontab |

### Frequency Options
- **Daily**: Runs every day at specified time
- **Weekly**: Runs on specified day of week
- **Monthly**: Runs on specified day of month (1-28)

---

## Archive Management

### Mounting Archives
1. Select archive in Archives tab
2. Click **Mount** 
3. A temporary folder opens with your backed-up files
4. Browse and copy files as needed
5. **Always unmount** when done to release resources

### Pruning Old Archives
Go to **Maintenance** tab > **Prune** to remove old archives based on retention policy:
- Keep last N hourly/daily/weekly/monthly archives
- Configure in job settings or run manually

### Compacting Repository
After pruning, run **Compact** to reclaim disk space from deleted archives.

---

## Configuration Reference

### Config File Location
- **Linux**: `~/.config/borg_manager/config/config.json`
- **Windows (compiled)**: `%USERPROFILE%/.config/borg_manager/config/config.json`
- **Development**: `./config/config.json`

### Key Configuration Options

| Setting | Description |
|---------|-------------|
| `borg_binary` | Path to borg executable |
| `current_repo` | Currently selected repository |
| `source_servers` | Dict of configured source servers |
| `jobs` | Dict of scheduled backup jobs |
| `log_settings.active_days` | Days to keep active logs (default: 7) |
| `log_settings.archive_days` | Days to keep archived logs (default: 90) |

### Environment Variables
- `USE_EMOJI=0` - Disable emoji icons (for terminal compatibility)
- `BORG_PASSPHRASE` - Set repository passphrase

---

## Troubleshooting

### App won't start
- Make sure `borg` is installed: `sudo apt install borgbackup`
- Check Python version: `python --version` (requires 3.8+)
- Check dependencies: Tools > Check Dependencies

### Connection failed
- Verify SSH key is set up correctly
- Test manually: `ssh user@hostname`
- Check for SSH host key issues
- Ensure borg is installed on remote server

### Backup is slow
- First backup is always slow (full copy)
- Subsequent backups are faster (deduplication)
- Check network speed for remote backups

### "Repository locked" error
- Another borg process may be running
- Use **Maintenance > Break Lock** (with caution)
- Check for stale lock files

### Connection timeout
- Increase SSH timeout in connection settings
- Check firewall rules
- Verify server is accessible

### Archive mounting fails
- Ensure FUSE is installed: `sudo apt install fuse`
- Check mount point permissions
- Try running with sudo for first mount

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| F5 | Refresh current view |
| Ctrl+S | Save current job/settings |
| Ctrl+Q | Quit application |

---

## Requirements

### Core Dependencies
- Python 3.8+
- borgbackup 1.2+
- tkinter (usually included with Python)

### Optional Dependencies
- `pystray`, `Pillow` - System tray support
- `paramiko` - Portable SSH (Windows)
- `matplotlib` - Dashboard charts
- `keyring` - Secure passphrase storage

### Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python borg_gui.py
```

---

## License

This application is open source software. See LICENSE file for details.
