"""
Borg Manager - Constants and Configuration Values

Contains theme colors, icons, font settings, and other constants.
"""

import os
import sys
import platform


# ==========================================
# THEME COLORS
# ==========================================
THEME_COLORS = {
    "light": {
        "text_main": "#222", "text_sub": "#555", "text_meta": "#666",
        "bg_card": "#ffffff", "bg_window": "#f0f0f0",
        "card_status": "#e0f7fa", "card_archive": "#f3e5f5", "card_storage": "#e8f5e9", "card_sched": "#fff3e0",
        "card_server": "#e3f2fd", "card_repo": "#e0f2f1",
        "stat_orig": "#2196F3", "stat_comp": "#FF9800", "stat_dedup": "#9C27B0",
        "success": "#4CAF50", "error": "#F44336",
        "tree_inc": "#e6ffe6", "tree_exc": "#ffe6e6"
    },
    "dark": {
        "text_main": "#eeeeee", "text_sub": "#cccccc", "text_meta": "#aaaaaa",
        "bg_card": "#424242", "bg_window": "#303030",
        "card_status": "#004d40", "card_archive": "#4a148c", "card_storage": "#1b5e20", "card_sched": "#bf360c",
        "card_server": "#0d47a1", "card_repo": "#00695c",
        "stat_orig": "#64b5f6", "stat_comp": "#ffb74d", "stat_dedup": "#ba68c8",
        "success": "#81c784", "error": "#e57373",
        "tree_inc": "#1b5e20", "tree_exc": "#b71c1c"
    }
}


# ==========================================
# ICONS (emoji/text fallbacks)
# ==========================================
# Set USE_EMOJI=0 environment variable to disable emojis
USE_EMOJI = os.environ.get("USE_EMOJI", "1") == "1"

ICONS = {
    # Actions
    "add": ("➕", "[+]"),
    "remove": ("➖", "[-]"),
    "delete": ("🗑", "[-]"),
    "save": ("💾", "[*]"),
    "run": ("▶", "[>]"),
    "stop": ("⏹", "[x]"),
    "refresh": ("🔄", "[o]"),
    "open": ("📂", "[>]"),
    "close": ("✖", "[x]"),
    "confirm": ("✔", "[*]"),
    # Status
    "ok": ("✓", "[OK]"),
    "error": ("✗", "[ERR]"),
    "warning": ("⚠", "[!]"),
    "info": ("ℹ", "[i]"),
    # Objects
    "folder": ("📁", "[D]"),
    "file": ("📄", "[F]"),
    "archive": ("📦", "[A]"),
    "clock": ("🕐", "[T]"),
    "calendar": ("📅", "[C]"),
    "settings": ("⚙", "[S]"),
    "key": ("🔑", "[K]"),
    "lock": ("🔒", "[L]"),
    # Misc
    "backup": ("💾", "[B]"),
    "mount": ("💿", "[M]"),
    "prune": ("✂", "[~]"),
    "log": ("📋", "[L]"),
    # Dashboard cards
    "status": ("🟢", "[*]"),
    "storage": ("💽", "[S]"),
    "schedule": ("⏰", "[T]"),
    "server": ("🖥", "[H]"),
    "time": ("⏱", "[T]"),
    "memory": ("🧠", "[M]"),
    "disk": ("💿", "[D]"),
    "network": ("🌐", "[N]"),
}


def icon(name: str) -> str:
    """Get icon by name. Returns emoji if enabled, otherwise text fallback."""
    if name not in ICONS:
        return ""
    emoji, fallback = ICONS[name]
    return emoji if USE_EMOJI else fallback


# ==========================================
# PLATFORM-SPECIFIC FONTS
# ==========================================
def get_platform_fonts() -> dict:
    """Get optimal fonts for current platform with emoji support."""
    system = platform.system()
    
    if system == "Windows":
        return {
            "default": "Segoe UI",
            "mono": "Consolas",
            "emoji": "Segoe UI Emoji",
        }
    elif system == "Darwin":  # macOS
        return {
            "default": "SF Pro Text",
            "mono": "SF Mono",
            "emoji": "Apple Color Emoji",
        }
    else:  # Linux
        return {
            "default": "Noto Sans",
            "mono": "Noto Sans Mono",
            "emoji": "Noto Color Emoji",
        }


PLATFORM_FONTS = get_platform_fonts()
DEFAULT_FONT = PLATFORM_FONTS["default"]
MONO_FONT = PLATFORM_FONTS["mono"]


# ==========================================
# APPLICATION PATHS
# ==========================================
# Determine if running as compiled executable or script
if getattr(sys, 'frozen', False):
    # Running as compiled .exe
    APP_EXEC_DIR = os.path.dirname(sys.executable)
    USE_USER_HOME = True
else:
    # Running as .py script
    APP_EXEC_DIR = os.path.dirname(os.path.abspath(__file__))
    # Go up two directories to get to project root
    APP_EXEC_DIR = os.path.dirname(os.path.dirname(APP_EXEC_DIR))
    USE_USER_HOME = False

# Define folder paths
DATA_ROOT = APP_EXEC_DIR
if USE_USER_HOME:
    DATA_ROOT = os.path.join(os.path.expanduser("~"), ".config", "borg_manager")
    os.makedirs(DATA_ROOT, exist_ok=True)

CONFIG_SUBDIR = os.path.join(DATA_ROOT, "config")
SCRIPTS_DIR = os.path.join(DATA_ROOT, "scripts")
LOGS_DIR = os.path.join(DATA_ROOT, "logs")
LOGS_ARCHIVE_DIR = os.path.join(LOGS_DIR, "archive")

# Smart config file detection
ROOT_CONFIG = os.path.join(DATA_ROOT, "config.json")
SUB_CONFIG = os.path.join(CONFIG_SUBDIR, "config.json")

if os.path.exists(ROOT_CONFIG):
    CONFIG_FILE = ROOT_CONFIG
else:
    CONFIG_FILE = SUB_CONFIG

# Ensure directories exist
if CONFIG_FILE == SUB_CONFIG:
    os.makedirs(CONFIG_SUBDIR, exist_ok=True)

for d in [SCRIPTS_DIR, LOGS_DIR, LOGS_ARCHIVE_DIR]:
    os.makedirs(d, exist_ok=True)


# ==========================================
# KEYRING SETTINGS
# ==========================================
KEYRING_SERVICE = "BorgBackupManager"
