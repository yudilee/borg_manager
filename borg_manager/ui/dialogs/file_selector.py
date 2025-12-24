"""
Borg Manager - File Selector Dialog

Interactive file browser for selecting backup includes/excludes.
Supports both local and remote (SSH) browsing.
"""

import os
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Callable, Set

from ...utils.constants import icon


class FileSelectorDialog(tk.Toplevel):
    """Interactive file browser dialog for selecting files and folders."""
    
    def __init__(self, parent, on_confirm_callback: Callable, 
                 root_path: Optional[str] = None,
                 on_cancel_callback: Optional[Callable] = None,
                 ssh_helper=None):
        """Initialize file selector dialog.
        
        Args:
            parent: Parent window
            on_confirm_callback: Called with (includes, excludes) on confirm
            root_path: Optional starting directory
            on_cancel_callback: Optional callback on cancel
            ssh_helper: Optional SSHHelper for remote browsing
        """
        super().__init__(parent)
        self.title("Interactive File Selector")
        self.geometry("900x600")
        self.on_confirm = on_confirm_callback
        self.on_cancel = on_cancel_callback
        self.root_path = root_path
        self.ssh_helper = ssh_helper
        
        self.includes: Set[str] = set()
        self.excludes: Set[str] = set()

        self._init_ui()
        self._load_root()
        
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _init_ui(self):
        """Build the dialog UI."""
        # Instructions
        info_frame = ttk.Frame(self, padding=10)
        info_frame.pack(fill=tk.X)
        msg = "Browse and select folders."
        if self.root_path:
            msg += f" (Browsing: {self.root_path})"
        ttk.Label(info_frame, text=msg).pack(anchor=tk.W)
        ttk.Label(info_frame, text="Green = Included, Red = Excluded").pack(anchor=tk.W)
        
        # Tree view
        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10)
        
        self.tree = ttk.Treeview(tree_frame, selectmode='browse')
        self.tree.heading("#0", text="Path")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.bind("<<TreeviewOpen>>", self._on_expand)
        self.tree.bind("<Double-1>", self._on_double_click)
        
        # Action buttons
        btn_frame = ttk.Frame(self, padding=10)
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(btn_frame, text=f"{icon('add')} Include", 
                   command=lambda: self._toggle_selection("include")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=f"{icon('remove')} Exclude", 
                   command=lambda: self._toggle_selection("exclude")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear", 
                   command=self._clear_selection).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Cancel", 
                   command=self._on_close).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text=f"{icon('confirm')} Confirm", 
                   command=self._on_confirm).pack(side=tk.RIGHT, padx=5)
        
        # Selection summary
        summary_frame = ttk.Frame(self, padding=10)
        summary_frame.pack(fill=tk.X)
        
        self.lbl_includes = ttk.Label(summary_frame, text="Includes: 0")
        self.lbl_includes.pack(side=tk.LEFT, padx=10)
        self.lbl_excludes = ttk.Label(summary_frame, text="Excludes: 0")
        self.lbl_excludes.pack(side=tk.LEFT, padx=10)

    def _load_root(self):
        """Load the root directory into the tree."""
        if self.root_path:
            root = self.root_path
        elif self.ssh_helper:
            root = self.ssh_helper.get_home()
        else:
            root = os.path.expanduser("~")
        
        self.tree.insert("", "end", root, text=root, open=False)
        self._load_children(root)

    def _load_children(self, parent_path: str):
        """Load children of a directory."""
        # Remove placeholder if exists
        for child in self.tree.get_children(parent_path):
            if self.tree.item(child)["text"] == "Loading...":
                self.tree.delete(child)
        
        if self.ssh_helper:
            items = self.ssh_helper.list_dir(parent_path)
        else:
            try:
                items = []
                for name in os.listdir(parent_path):
                    full_path = os.path.join(parent_path, name)
                    is_dir = os.path.isdir(full_path)
                    items.append((name, is_dir))
                items.sort(key=lambda x: (not x[1], x[0].lower()))
            except PermissionError:
                return
        
        for name, is_dir in items:
            if name.startswith("."):
                continue
            
            full_path = os.path.join(parent_path, name)
            node_id = self.tree.insert(parent_path, "end", full_path, 
                                       text=name, open=False)
            
            if is_dir:
                # Add placeholder for lazy loading
                self.tree.insert(node_id, "end", text="Loading...")

    def _on_expand(self, event):
        """Handle tree node expansion."""
        node = self.tree.focus()
        if node:
            self._load_children(node)

    def _on_double_click(self, event):
        """Handle double-click to toggle include."""
        self._toggle_selection("include")

    def _toggle_selection(self, mode: str):
        """Toggle include/exclude for selected item."""
        selection = self.tree.focus()
        if not selection:
            return
        
        path = selection
        
        if mode == "include":
            self.excludes.discard(path)
            if path in self.includes:
                self.includes.remove(path)
            else:
                self.includes.add(path)
        else:
            self.includes.discard(path)
            if path in self.excludes:
                self.excludes.remove(path)
            else:
                self.excludes.add(path)
        
        self._update_item_color(path)
        self._update_summary()

    def _clear_selection(self):
        """Clear current selection."""
        selection = self.tree.focus()
        if selection:
            self.includes.discard(selection)
            self.excludes.discard(selection)
            self._update_item_color(selection)
            self._update_summary()

    def _update_item_color(self, path: str):
        """Update tree item color based on selection state."""
        if path in self.includes:
            self.tree.item(path, tags=("include",))
        elif path in self.excludes:
            self.tree.item(path, tags=("exclude",))
        else:
            self.tree.item(path, tags=())
        
        # Configure tag colors
        self.tree.tag_configure("include", background="#e6ffe6")
        self.tree.tag_configure("exclude", background="#ffe6e6")

    def _update_summary(self):
        """Update selection count labels."""
        self.lbl_includes.config(text=f"Includes: {len(self.includes)}")
        self.lbl_excludes.config(text=f"Excludes: {len(self.excludes)}")

    def _on_confirm(self):
        """Handle confirm button click."""
        if self.on_confirm:
            self.on_confirm(list(self.includes), list(self.excludes))
        self.destroy()

    def _on_close(self):
        """Handle dialog close."""
        if self.on_cancel:
            self.on_cancel()
        self.destroy()
