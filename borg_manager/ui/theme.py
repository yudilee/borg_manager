"""
Borg Manager - Theme Management

Handles theme colors and styling for the GUI.
"""

from tkinter import ttk
from typing import Optional

from ..utils.constants import THEME_COLORS


def get_theme_color(key: str, theme: str = "light") -> str:
    """Get a color from the current theme.
    
    Args:
        key: Color key (e.g., 'bg_card', 'text_main')
        theme: Theme name ('light' or 'dark')
        
    Returns:
        Hex color string
    """
    colors = THEME_COLORS.get(theme, THEME_COLORS["light"])
    return colors.get(key, "#ffffff")


def apply_theme(style: ttk.Style, theme: str = "light") -> None:
    """Apply theme colors to ttk style.
    
    Args:
        style: ttk.Style instance
        theme: Theme name ('light' or 'dark')
    """
    colors = THEME_COLORS.get(theme, THEME_COLORS["light"])
    
    # Configure base styles
    style.configure(".", 
                    background=colors["bg_window"],
                    foreground=colors["text_main"])
    
    style.configure("TFrame", background=colors["bg_window"])
    style.configure("TLabel", 
                    background=colors["bg_window"],
                    foreground=colors["text_main"])
    
    style.configure("TButton", padding=6)
    
    style.configure("Treeview",
                    background=colors["bg_card"],
                    foreground=colors["text_main"],
                    fieldbackground=colors["bg_card"])
    
    style.map("Treeview",
              background=[("selected", colors["stat_orig"])],
              foreground=[("selected", "#ffffff")])
