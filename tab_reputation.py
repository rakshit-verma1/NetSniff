"""
Reputation Tab Module
Handles network reputation system
"""
import tkinter as tk
from tkinter import ttk


class ReputationTab:
    """Network Reputation System"""
    
    def __init__(self, parent, security_manager):
        self.frame = ttk.Frame(parent)
        self.security_manager = security_manager
        self.setup_ui()
    
    def get_frame(self):
        """Return the main frame for this tab"""
        return self.frame
    
    def setup_ui(self):
        """Setup complete UI for reputation tab"""
        ttk.Label(self.frame, text="Network Reputation System",
                  font=("Arial", 12, "bold")).pack(pady=10)
        
        notebook = ttk.Notebook(self.frame)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # IP Reputation Tab
        ip_frame = ttk.Frame(notebook)
        notebook.add(ip_frame, text="IP Reputation")
        self.setup_ip_reputation(ip_frame)
        
        # Domain Reputation Tab
        domain_frame = ttk.Frame(notebook)
        notebook.add(domain_frame, text="Domain Reputation")
        self.setup_domain_reputation(domain_frame)
        
        ttk.Button(self.frame, text="Refresh Reputation Data",
                   command=self.refresh_reputation).pack(pady=5)
    
    def setup_ip_reputation(self, parent):
        """Setup IP reputation table"""
        table_frame = ttk.Frame(parent)
        table_frame.pack(fill="both", expand=True, pady=5)
        
        columns = ("IP Address", "Reputation Score", "Total Hits", "Blocked", "Status")
        self.ip_table = ttk.Treeview(table_frame, columns=columns,
                                    show="headings", height=18)
        
        column_widths = (150, 150, 100, 100, 150)
        for col, width in zip(columns, column_widths):
            self.ip_table.heading(col, text=col, anchor="center")
            self.ip_table.column(col, width=width, anchor="center")
        
        self.ip_table.tag_configure("trusted", background="#e8f5e8")
        self.ip_table.tag_configure("suspicious", background="#fff9e6")
        self.ip_table.tag_configure("blocked", background="#ffe6e6",
                                   foreground="#d32f2f")
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical",
                                 command=self.ip_table.yview)
        self.ip_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.ip_table.pack(side="left", fill="both", expand=True)
    
    def setup_domain_reputation(self, parent):
        """Setup domain reputation table"""
        table_frame = ttk.Frame(parent)
        table_frame.pack(fill="both", expand=True, pady=5)
        
        columns = ("Domain", "Reputation Score", "Total Hits", "Blocked", "Status")
        self.domain_table = ttk.Treeview(table_frame, columns=columns,
                                        show="headings", height=18)
        
        column_widths = (150, 150, 100, 100, 150)
        for col, width in zip(columns, column_widths):
            self.domain_table.heading(col, text=col, anchor="center")
            self.domain_table.column(col, width=width, anchor="center")
        
        self.domain_table.tag_configure("trusted", background="#e8f5e8")
        self.domain_table.tag_configure("suspicious", background="#fff9e6")
        self.domain_table.tag_configure("blocked", background="#ffe6e6",
                                       foreground="#d32f2f")
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical",
                                 command=self.domain_table.yview)
        self.domain_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.domain_table.pack(side="left", fill="both", expand=True)
    
    def process_packet(self, packet_info):
        """Process packet (reputation is updated in security manager)"""
        pass
    
    def refresh_reputation(self):
        """Refresh reputation data"""
        self.ip_table.delete(*self.ip_table.get_children())
        self.domain_table.delete(*self.domain_table.get_children())
        
        rep_stats = self.security_manager.get_reputation_stats()
        
        # Update IP reputation
        for ip, data in rep_stats["ips"].items():
            score = data["score"]
            status = "✓ Trusted" if score >= 70 else "⚠ Suspicious" if score >= 40 else "✗ Blocked"
            tag = "trusted" if score >= 70 else "suspicious" if score >= 40 else "blocked"
            
            self.ip_table.insert("", "end", values=(
                ip,
                f"{score:.1f}/100",
                data["hits"],
                data["blocked"],
                status
            ), tags=(tag,))
        
        # Update domain reputation
        for domain, data in rep_stats["domains"].items():
            score = data["score"]
            status = "✓ Trusted" if score >= 70 else "⚠ Suspicious" if score >= 40 else "✗ Blocked"
            tag = "trusted" if score >= 70 else "suspicious" if score >= 40 else "blocked"
            
            self.domain_table.insert("", "end", values=(
                domain,
                f"{score:.1f}/100",
                data["hits"],
                data["blocked"],
                status
            ), tags=(tag,))
