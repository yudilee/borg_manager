"""
Borg Manager - Progress Bar Widget

Custom progress bar widget for backup operations.
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional


class ProgressBar(ttk.Frame):
    """Custom progress bar widget with label and percentage display."""
    
    def __init__(self, parent, **kwargs):
        """Initialize progress bar.
        
        Args:
            parent: Parent widget
            **kwargs: Additional frame options
        """
        super().__init__(parent, **kwargs)
        
        self._value = 0
        self._max = 100
        self._text = ""
        
        self._init_ui()
    
    def _init_ui(self):
        """Build the progress bar UI."""
        # Label frame
        self.label_frame = ttk.Frame(self)
        self.label_frame.pack(fill=tk.X)
        
        self.lbl_text = ttk.Label(self.label_frame, text="")
        self.lbl_text.pack(side=tk.LEFT)
        
        self.lbl_percent = ttk.Label(self.label_frame, text="0%")
        self.lbl_percent.pack(side=tk.RIGHT)
        
        # Progress bar
        self.progress = ttk.Progressbar(self, mode='determinate', maximum=100)
        self.progress.pack(fill=tk.X, pady=(5, 0))
    
    def set_value(self, value: float, max_value: Optional[float] = None):
        """Set progress bar value.
        
        Args:
            value: Current value
            max_value: Optional maximum value (defaults to 100)
        """
        if max_value is not None:
            self._max = max_value
        
        self._value = min(value, self._max)
        
        if self._max > 0:
            percent = (self._value / self._max) * 100
        else:
            percent = 0
        
        self.progress['value'] = percent
        self.lbl_percent.config(text=f"{percent:.1f}%")
    
    def set_text(self, text: str):
        """Set progress bar label text.
        
        Args:
            text: Label text
        """
        self._text = text
        self.lbl_text.config(text=text)
    
    def set_indeterminate(self, active: bool = True):
        """Set indeterminate mode for unknown progress.
        
        Args:
            active: Whether indeterminate mode is active
        """
        if active:
            self.progress.config(mode='indeterminate')
            self.progress.start(10)
            self.lbl_percent.config(text="...")
        else:
            self.progress.stop()
            self.progress.config(mode='determinate')
    
    def reset(self):
        """Reset progress bar to initial state."""
        self._value = 0
        self.progress['value'] = 0
        self.lbl_text.config(text="")
        self.lbl_percent.config(text="0%")
        self.set_indeterminate(False)


class BackupProgressWidget(ttk.LabelFrame):
    """Comprehensive backup progress widget with file count and size info."""
    
    def __init__(self, parent, title: str = "Backup Progress", **kwargs):
        """Initialize backup progress widget.
        
        Args:
            parent: Parent widget
            title: Frame title
            **kwargs: Additional frame options
        """
        super().__init__(parent, text=title, **kwargs)
        
        self._init_ui()
    
    def _init_ui(self):
        """Build the progress widget UI."""
        padding = {'padx': 10, 'pady': 5}
        
        # Status row
        status_frame = ttk.Frame(self)
        status_frame.pack(fill=tk.X, **padding)
        
        ttk.Label(status_frame, text="Status:").pack(side=tk.LEFT)
        self.lbl_status = ttk.Label(status_frame, text="Idle")
        self.lbl_status.pack(side=tk.LEFT, padx=10)
        
        # Progress bar
        self.progress = ProgressBar(self)
        self.progress.pack(fill=tk.X, **padding)
        
        # Stats row
        stats_frame = ttk.Frame(self)
        stats_frame.pack(fill=tk.X, **padding)
        
        # Files processed
        ttk.Label(stats_frame, text="Files:").pack(side=tk.LEFT)
        self.lbl_files = ttk.Label(stats_frame, text="0")
        self.lbl_files.pack(side=tk.LEFT, padx=(5, 20))
        
        # Original size
        ttk.Label(stats_frame, text="Original:").pack(side=tk.LEFT)
        self.lbl_original = ttk.Label(stats_frame, text="0 B")
        self.lbl_original.pack(side=tk.LEFT, padx=(5, 20))
        
        # Compressed size
        ttk.Label(stats_frame, text="Compressed:").pack(side=tk.LEFT)
        self.lbl_compressed = ttk.Label(stats_frame, text="0 B")
        self.lbl_compressed.pack(side=tk.LEFT, padx=(5, 20))
        
        # Deduplicated size
        ttk.Label(stats_frame, text="Dedup:").pack(side=tk.LEFT)
        self.lbl_dedup = ttk.Label(stats_frame, text="0 B")
        self.lbl_dedup.pack(side=tk.LEFT, padx=5)
        
        # Current file row
        file_frame = ttk.Frame(self)
        file_frame.pack(fill=tk.X, **padding)
        
        ttk.Label(file_frame, text="Current:").pack(side=tk.LEFT)
        self.lbl_current_file = ttk.Label(file_frame, text="", width=60)
        self.lbl_current_file.pack(side=tk.LEFT, padx=5)
    
    def update_progress(self, files: int = 0, original: str = "0 B",
                        compressed: str = "0 B", dedup: str = "0 B",
                        current_file: str = "", percent: float = 0):
        """Update all progress information.
        
        Args:
            files: Number of files processed
            original: Original size string
            compressed: Compressed size string
            dedup: Deduplicated size string
            current_file: Currently processing file
            percent: Progress percentage
        """
        self.lbl_files.config(text=str(files))
        self.lbl_original.config(text=original)
        self.lbl_compressed.config(text=compressed)
        self.lbl_dedup.config(text=dedup)
        
        # Truncate long file paths
        if len(current_file) > 60:
            current_file = "..." + current_file[-57:]
        self.lbl_current_file.config(text=current_file)
        
        self.progress.set_value(percent)
    
    def set_status(self, status: str):
        """Set status text.
        
        Args:
            status: Status string
        """
        self.lbl_status.config(text=status)
    
    def start(self):
        """Start progress (indeterminate mode)."""
        self.lbl_status.config(text="Running...")
        self.progress.set_indeterminate(True)
    
    def stop(self, success: bool = True):
        """Stop progress.
        
        Args:
            success: Whether operation was successful
        """
        self.progress.set_indeterminate(False)
        if success:
            self.lbl_status.config(text="Complete")
            self.progress.set_value(100)
        else:
            self.lbl_status.config(text="Failed")
    
    def reset(self):
        """Reset widget to initial state."""
        self.lbl_status.config(text="Idle")
        self.lbl_files.config(text="0")
        self.lbl_original.config(text="0 B")
        self.lbl_compressed.config(text="0 B")
        self.lbl_dedup.config(text="0 B")
        self.lbl_current_file.config(text="")
        self.progress.reset()
