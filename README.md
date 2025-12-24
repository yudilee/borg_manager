# Borg Backup Manager

A full-featured graphical interface for managing BorgBackup repositories, scheduled backups, and archive restoration.

## Features

- 📁 **Repository Management** - Add, configure, and switch between repositories
- 🔄 **Scheduled Backups** - Daily, weekly, or monthly automatic backups
- 📦 **Archive Browsing** - View, mount, and restore from backup archives
- 🔍 **Archive Search** - Filter archives by name or date
- ⇄ **Archive Diff** - Compare changes between two archives
- 🔔 **Desktop Notifications** - Get notified when backups complete
- 🔐 **Secure Storage** - Passphrase storage using system keyring
- 🖥️ **Remote Support** - SSH-based remote backups
- 📊 **Dashboard** - Overview of backup status and statistics

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/borg_manager.git
cd borg_manager

# Install dependencies
pip install -r requirements.txt

# Run the application
python3 borg_gui.py
```

## Requirements

- Python 3.8+
- BorgBackup 1.2+
- tkinter (usually included with Python)

### Optional Dependencies

- `pystray`, `Pillow` - System tray support
- `paramiko` - Portable SSH (recommended for Windows)
- `matplotlib` - Dashboard charts
- `keyring` - Secure passphrase storage

## Documentation

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for detailed usage instructions.

## License

MIT License - See LICENSE file for details.
