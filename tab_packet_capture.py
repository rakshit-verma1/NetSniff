"""
Packet Capture Tab Module
Handles packet display, filtering, and alerts
"""
import tkinter as tk
from tkinter import ttk
import datetime
from network_utils import SUSPICIOUS_PORTS


class PacketCaptureTab:
    """Main packet capture and display tab"""
    
    def __init__(self, parent, data_manager, filter_manager, public_ip):
        self.frame = ttk.Frame(parent)
        self.data_manager = data_manager
        self.filter_manager = filter_manager
        self.public_ip = public_ip
        self.setup_ui()
    
    def get_frame(self):
        """Return the main frame for this tab"""
        return self.frame
    
    def setup_ui(self):
        """Setup complete UI for packet capture tab"""
        # Filter section
        filter_section = ttk.LabelFrame(self.frame, text=" Filter Options ", padding=10)
        filter_section.pack(fill="x", pady=(0, 5))
        
        self.setup_filters(filter_section)
        
        # Content section
        content_section = ttk.Frame(self.frame)
        content_section.pack(fill="both", expand=True, pady=(0, 5))
        
        # Packet table
        table_section = ttk.LabelFrame(content_section, 
                                       text=" Live Packet Capture with DNS Resolution ", 
                                       padding=5)
        table_section.pack(fill="both", expand=True, pady=(0, 5))
        
        self.setup_packet_table(table_section)
        
        # Alert box
        alert_section = ttk.LabelFrame(content_section, text=" Security Alerts ", padding=5)
        alert_section.pack(fill="x", pady=(5, 0))
        
        self.setup_alert_box(alert_section)
    
    def setup_filters(self, parent):
        """Setup filter controls"""
        # Filter variables
        self.protocol_var = tk.StringVar()
        self.ip_var = tk.StringVar()
        self.port_var = tk.StringVar()
        self.dns_var = tk.StringVar()
        self.public_only = tk.BooleanVar()
        
        filter_title = ttk.Label(parent, text="Filters", font=("Arial", 10, "bold"))
        filter_title.grid(row=0, column=0, columnspan=10, sticky="w", pady=(0, 5))
        
        # Protocol filter
        ttk.Label(parent, text="Protocol:").grid(row=1, column=0, padx=(0, 5), sticky="w")
        protocol_box = ttk.Combobox(parent, textvariable=self.protocol_var, 
                                    width=8, state="readonly")
        protocol_box["values"] = ("", "TCP", "UDP", "ICMP")
        protocol_box.grid(row=1, column=1, padx=(0, 10))
        
        # IP filter
        ttk.Label(parent, text="IP:").grid(row=1, column=2, padx=(0, 5), sticky="w")
        ip_box = ttk.Entry(parent, textvariable=self.ip_var, width=12)
        ip_box.grid(row=1, column=3, padx=(0, 10))
        
        # Port filter
        ttk.Label(parent, text="Port:").grid(row=1, column=4, padx=(0, 5), sticky="w")
        port_box = ttk.Entry(parent, textvariable=self.port_var, width=6)
        port_box.grid(row=1, column=5, padx=(0, 10))
        
        # DNS filter
        ttk.Label(parent, text="DNS:").grid(row=1, column=6, padx=(0, 5), sticky="w")
        dns_box = ttk.Entry(parent, textvariable=self.dns_var, width=12)
        dns_box.grid(row=1, column=7, padx=(0, 10))
        
        # Public IP only checkbox
        public_check = ttk.Checkbutton(parent, text="Public IP Only", 
                                       variable=self.public_only)
        public_check.grid(row=1, column=8, padx=(0, 10))
        
        # Clear button
        clear_button = ttk.Button(parent, text="Clear", command=self.clear_filters, width=6)
        clear_button.grid(row=1, column=9)
    
    def setup_packet_table(self, parent):
        """Setup packet display table"""
        table_frame = ttk.Frame(parent)
        table_frame.pack(fill="both", expand=True)
        
        columns = ("Time", "Source IP", "Source DNS", "Dest IP", "Dest DNS", 
                  "Protocol", "Src Port", "Dst Port", "Info")
        self.packet_table = ttk.Treeview(table_frame, columns=columns, 
                                        show="headings", height=20)
        
        column_widths = (70, 100, 120, 100, 120, 70, 70, 70, 150)
        for col, width in zip(columns, column_widths):
            self.packet_table.heading(col, text=col, anchor="center")
            self.packet_table.column(col, width=width, anchor="center")
        
        # Configure tags for different protocols
        self.packet_table.tag_configure("TCP", background="#e8f5e8")
        self.packet_table.tag_configure("UDP", background="#f0f8ff")
        self.packet_table.tag_configure("ICMP", background="#fff5ee")
        self.packet_table.tag_configure("suspicious", background="#ffe6e6", 
                                       foreground="#d32f2f")
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", 
                                 command=self.packet_table.yview)
        self.packet_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.packet_table.pack(side="left", fill="both", expand=True)
    
    def setup_alert_box(self, parent):
        """Setup alert display box"""
        alert_frame = ttk.Frame(parent)
        alert_frame.pack(fill="both", expand=True)
        
        self.alert_box = tk.Text(
            alert_frame,
            height=5,
            font=("Consolas", 9),
            bg="#1a1a1a",
            fg="#ff6b6b",
            insertbackground="#ff6b6b",
            selectbackground="#333333",
            state="disabled",
            wrap="word"
        )
        
        scrollbar = ttk.Scrollbar(alert_frame, orient="vertical", 
                                 command=self.alert_box.yview)
        self.alert_box.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.alert_box.pack(side="left", fill="both", expand=True)
    
    def clear_filters(self):
        """Clear all filter values"""
        self.protocol_var.set("")
        self.ip_var.set("")
        self.port_var.set("")
        self.dns_var.set("")
        self.public_only.set(False)
    
    def should_display(self, packet_info):
        """Check if packet should be displayed based on filters"""
        time, source_ip, dest_ip, protocol, sport, dport, source_dns, dest_dns = packet_info[:8]
        
        # Protocol filter
        protocol_filter = self.protocol_var.get()
        if protocol_filter and protocol != protocol_filter:
            return False
        
        # IP filter
        ip_filter = self.ip_var.get()
        if ip_filter and ip_filter not in (source_ip, dest_ip):
            return False
        
        # Port filter
        port_filter = self.port_var.get()
        if port_filter:
            try:
                want_port = int(port_filter)
                if want_port not in (sport, dport):
                    return False
            except ValueError:
                pass
        
        # DNS filter
        dns_filter = self.dns_var.get().lower()
        if dns_filter:
            if dns_filter not in source_dns.lower() and dns_filter not in dest_dns.lower():
                return False
        
        # Public IP only filter
        public_only = self.public_only.get()
        if public_only and self.public_ip not in (source_ip, dest_ip):
            return False
        
        return True
    
    def process_packet(self, packet_info):
        """Process and display packet"""
        time, source_ip, dest_ip, protocol, sport, dport, source_dns, dest_dns = packet_info[:8]
        
        # Check if suspicious
        is_suspicious = (sport in SUSPICIOUS_PORTS or dport in SUSPICIOUS_PORTS) if sport and dport else False
        
        # Shorten DNS names
        source_dns_short = self.shorten_dns(source_dns)
        dest_dns_short = self.shorten_dns(dest_dns)
        
        # Create info string
        info = f"{source_ip} to {dest_ip}"
        if sport and dport:
            info = f"{source_ip}:{sport} to {dest_ip}:{dport}"
        
        display_data = (
            time,
            source_ip,
            source_dns_short,
            dest_ip,
            dest_dns_short,
            protocol,
            sport or "N/A",
            dport or "N/A",
            info
        )
        
        # Insert into table
        tag = "suspicious" if is_suspicious else protocol
        item = self.packet_table.insert("", 0, values=display_data, tags=(tag,))
        self.packet_table.see(item)
    
    def shorten_dns(self, dns_name):
        """Shorten DNS name for display"""
        if dns_name == "No DNS":
            return "No DNS"
        if len(dns_name) > 25:
            return dns_name[:22] + "..."
        return dns_name
    
    def add_alert(self, message):
        """Add alert message"""
        self.alert_box.config(state="normal")
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        alert_text = f"[{timestamp}] {message}\n"
        self.alert_box.insert("end", alert_text)
        self.alert_box.see("end")
        self.alert_box.config(state="disabled")
    
    def clear_all(self):
        """Clear all data in this tab"""
        self.packet_table.delete(*self.packet_table.get_children())
        self.alert_box.config(state="normal")
        self.alert_box.delete("1.0", "end")
        self.alert_box.config(state="disabled")
