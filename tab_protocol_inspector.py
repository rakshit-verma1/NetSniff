"""
Protocol Inspector Tab Module
Handles HTTP/HTTPS analysis and deep packet inspection
"""
import tkinter as tk
from tkinter import ttk


class ProtocolInspectorTab:
    """Protocol Deep Inspection - HTTP/HTTPS Analysis"""
    
    def __init__(self, parent, security_manager):
        self.frame = ttk.Frame(parent)
        self.security_manager = security_manager
        self.setup_ui()
    
    def get_frame(self):
        """Return the main frame for this tab"""
        return self.frame
    
    def setup_ui(self):
        """Setup complete UI for protocol inspector tab"""
        ttk.Label(self.frame, text="Protocol Deep Inspection - HTTP/HTTPS Analysis",
                  font=("Arial", 12, "bold")).pack(pady=10)
        
        # Statistics
        stats_frame = ttk.LabelFrame(self.frame, text=" Protocol Statistics ", padding=10)
        stats_frame.pack(fill="x", padx=10, pady=5)
        
        self.http_count_var = tk.StringVar(value="HTTP Requests: 0")
        self.encryption_var = tk.StringVar(value="Encrypted Traffic: 0%")
        self.total_traffic_var = tk.StringVar(value="Total Traffic: 0")
        
        ttk.Label(stats_frame, textvariable=self.http_count_var,
                  font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.encryption_var,
                  font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.total_traffic_var,
                  font=("Arial", 10)).pack(side="left", padx=10)
        
        # Protocol table
        table_frame = ttk.Frame(self.frame)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("Time", "Type", "Method/Status", "URL/Info", "User Agent")
        self.protocol_table = ttk.Treeview(table_frame, columns=columns,
                                          show="headings", height=20)
        
        column_widths = (80, 100, 120, 400, 300)
        for col, width in zip(columns, column_widths):
            self.protocol_table.heading(col, text=col, anchor="center")
            self.protocol_table.column(col, width=width, anchor="center")
        
        self.protocol_table.tag_configure("request", background="#e3f2fd")
        self.protocol_table.tag_configure("response", background="#f3e5f5")
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical",
                                 command=self.protocol_table.yview)
        self.protocol_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.protocol_table.pack(side="left", fill="both", expand=True)
        
        ttk.Button(self.frame, text="Refresh Protocol Data",
                   command=self.refresh_protocols).pack(pady=5)
    
    def process_packet(self, packet_info):
        """Process packet and update protocol display"""
        self.refresh_protocols()
    
    def refresh_protocols(self):
        """Refresh protocol display"""
        self.protocol_table.delete(*self.protocol_table.get_children())
        
        traffic = self.security_manager.get_http_traffic()
        protocol_stats = self.security_manager.get_protocol_stats()
        
        self.http_count_var.set(f"HTTP Requests: {protocol_stats['http_requests']}")
        self.encryption_var.set(f"Encrypted Traffic: {protocol_stats['encrypted_ratio']}%")
        self.total_traffic_var.set(f"Total Traffic: {protocol_stats['total_traffic']}")
        
        for item in traffic[-100:]:
            if item["type"] == "request":
                method_status = item.get("method", "GET")
                url_info = item.get("url", "")
                user_agent = item.get("user_agent", "N/A")[:50]
                tag = "request"
            else:
                method_status = item.get("status", "200")
                url_info = "Response"
                user_agent = "N/A"
                tag = "response"
            
            self.protocol_table.insert("", 0, values=(
                item["time"],
                item["type"].upper(),
                method_status,
                url_info[:50] + "..." if len(url_info) > 50 else url_info,
                user_agent
            ), tags=(tag,))
