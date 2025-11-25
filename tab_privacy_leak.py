"""
Privacy Leak Tab Module
Handles credential and data monitoring
"""
import tkinter as tk
from tkinter import ttk


class PrivacyLeakTab:
    """Privacy Leak Detector - Credential & Data Monitoring"""
    
    def __init__(self, parent, security_manager):
        self.frame = ttk.Frame(parent)
        self.security_manager = security_manager
        self.setup_ui()
    
    def get_frame(self):
        """Return the main frame for this tab"""
        return self.frame
    
    def setup_ui(self):
        """Setup complete UI for privacy leak tab"""
        ttk.Label(self.frame, text="Privacy Leak Detector - Credential & Data Monitoring",
                  font=("Arial", 12, "bold")).pack(pady=10)
        
        # Statistics
        stats_frame = ttk.LabelFrame(self.frame, text=" Leak Statistics ", padding=10)
        stats_frame.pack(fill="x", padx=10, pady=5)
        
        self.total_leaks_var = tk.StringVar(value="Total Leaks: 0")
        self.high_severity_var = tk.StringVar(value="High Severity: 0")
        self.medium_severity_var = tk.StringVar(value="Medium Severity: 0")
        
        ttk.Label(stats_frame, textvariable=self.total_leaks_var,
                  font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.high_severity_var,
                  foreground="#d32f2f", font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.medium_severity_var,
                  foreground="#ff9800", font=("Arial", 10)).pack(side="left", padx=10)
        
        # Leak table
        table_frame = ttk.Frame(self.frame)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("Time", "Leak Type", "Source IP", "Dest IP", "Severity", "Status")
        self.leak_table = ttk.Treeview(table_frame, columns=columns,
                                      show="headings", height=20)
        
        column_widths = (80, 150, 150, 150, 100, 150)
        for col, width in zip(columns, column_widths):
            self.leak_table.heading(col, text=col, anchor="center")
            self.leak_table.column(col, width=width, anchor="center")
        
        self.leak_table.tag_configure("high", background="#ffe6e6",
                                     foreground="#d32f2f")
        self.leak_table.tag_configure("medium", background="#fff9e6",
                                     foreground="#ff9800")
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical",
                                 command=self.leak_table.yview)
        self.leak_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.leak_table.pack(side="left", fill="both", expand=True)
        
        note_label = ttk.Label(self.frame,
                               text="Monitors plain-text transmission of passwords, credentials, and sensitive data",
                               font=("Arial", 8), foreground="gray")
        note_label.pack(pady=5)
    
    def process_packet(self, packet_info):
        """Process packet and update leak display"""
        self.refresh_leaks()
    
    def refresh_leaks(self):
        """Refresh leak display"""
        self.leak_table.delete(*self.leak_table.get_children())
        
        leaks = self.security_manager.get_privacy_leaks()
        high_count = sum(1 for l in leaks if l["severity"] == "HIGH")
        medium_count = sum(1 for l in leaks if l["severity"] == "MEDIUM")
        
        self.total_leaks_var.set(f"Total Leaks: {len(leaks)}")
        self.high_severity_var.set(f"High Severity: {high_count}")
        self.medium_severity_var.set(f"Medium Severity: {medium_count}")
        
        for leak in leaks:
            tag = "high" if leak["severity"] == "HIGH" else "medium"
            status = "🚨 CRITICAL" if leak["severity"] == "HIGH" else "⚠️ WARNING"
            
            self.leak_table.insert("", 0, values=(
                leak["time"],
                leak["keyword"].upper(),
                leak["source_ip"],
                leak["dest_ip"],
                leak["severity"],
                status
            ), tags=(tag,))
