import tkinter as tk
from tkinter import ttk
import datetime

# Basic UI Components

class FilterPanel(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.protocol_var = tk.StringVar()
        self.ip_var = tk.StringVar()
        self.port_var = tk.StringVar()
        self.dns_var = tk.StringVar()
        self.public_only = tk.BooleanVar()
        self.setup_filters()

    def setup_filters(self):
        filter_title = ttk.Label(self, text="Filters", font=("Arial", 10, "bold"))
        filter_title.grid(row=0, column=0, columnspan=10, sticky="w", pady=(0, 5))

        ttk.Label(self, text="Protocol:").grid(row=1, column=0, padx=(0, 5), sticky="w")
        protocol_box = ttk.Combobox(self, textvariable=self.protocol_var, width=8, state="readonly")
        protocol_box["values"] = ("", "TCP", "UDP", "ICMP")
        protocol_box.grid(row=1, column=1, padx=(0, 10))

        ttk.Label(self, text="IP:").grid(row=1, column=2, padx=(0, 5), sticky="w")
        ip_box = ttk.Entry(self, textvariable=self.ip_var, width=12)
        ip_box.grid(row=1, column=3, padx=(0, 10))

        ttk.Label(self, text="Port:").grid(row=1, column=4, padx=(0, 5), sticky="w")
        port_box = ttk.Entry(self, textvariable=self.port_var, width=6)
        port_box.grid(row=1, column=5, padx=(0, 10))

        ttk.Label(self, text="DNS:").grid(row=1, column=6, padx=(0, 5), sticky="w")
        dns_box = ttk.Entry(self, textvariable=self.dns_var, width=12)
        dns_box.grid(row=1, column=7, padx=(0, 10))

        public_check = ttk.Checkbutton(self, text="Public IP Only", variable=self.public_only)
        public_check.grid(row=1, column=8, padx=(0, 10))

        clear_button = ttk.Button(self, text="Clear", command=self.clear_all, width=6)
        clear_button.grid(row=1, column=9)

    def clear_all(self):
        self.protocol_var.set("")
        self.ip_var.set("")
        self.port_var.set("")
        self.dns_var.set("")
        self.public_only.set(False)

class PacketTable(ttk.Treeview):
    def __init__(self, master):
        columns = ("Time", "Source IP", "Source DNS", "Dest IP", "Dest DNS", "Protocol", "Src Port", "Dst Port", "Info")
        super().__init__(master, columns=columns, show="headings", height=20)

        column_widths = (70, 100, 120, 100, 120, 70, 70, 70, 150)
        for col, width in zip(columns, column_widths):
            self.heading(col, text=col, anchor="center")
            self.column(col, width=width, anchor="center")

        self.tag_configure("TCP", background="#e8f5e8")
        self.tag_configure("UDP", background="#f0f8ff") 
        self.tag_configure("ICMP", background="#fff5ee")
        self.tag_configure("suspicious", background="#ffe6e6", foreground="#d32f2f")

        scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.yview)
        self.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

    def add_packet_row(self, packet_data, is_suspicious=False):
        time, source_ip, dest_ip, protocol, sport, dport, source_dns, dest_dns = packet_data

        source_dns_short = self.shorten_dns(source_dns)
        dest_dns_short = self.shorten_dns(dest_dns)

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

        tag = "suspicious" if is_suspicious else protocol
        item = self.insert("", 0, values=display_data, tags=(tag,))
        self.see(item)

    def shorten_dns(self, dns_name):
        if dns_name == "No DNS":
            return "No DNS"
        if len(dns_name) > 25:
            return dns_name[:22] + "..."
        return dns_name

    def clear_table(self):
        self.delete(*self.get_children())

class AlertBox(tk.Text):
    def __init__(self, master):
        super().__init__(
            master, 
            height=5, 
            font=("Consolas", 9),
            bg="#1a1a1a", 
            fg="#ff6b6b",
            insertbackground="#ff6b6b",
            selectbackground="#333333",
            state="disabled",
            wrap="word"
        )

        scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.yview)
        self.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

    def add_alert(self, message):
        self.config(state="normal")
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        alert_text = f"[{timestamp}] {message}\n"
        self.insert("end", alert_text)
        self.see("end")
        self.config(state="disabled")

    def clear_alerts(self):
        self.config(state="normal")
        self.delete("1.0", "end")
        self.config(state="disabled")

class StatusBar(ttk.Frame):
    def __init__(self, master, ssid_var, ip_var, status_var):
        super().__init__(master, relief="sunken", borderwidth=1)

        left_section = ttk.Frame(self)
        left_section.pack(side="left", fill="x", expand=True, padx=5, pady=2)

        ttk.Label(left_section, text="Network:", font=("Arial", 9)).pack(side="left")
        ttk.Label(left_section, textvariable=ssid_var, font=("Arial", 9)).pack(side="left", padx=(5, 15))

        ttk.Label(left_section, text="Public IP:", font=("Arial", 9)).pack(side="left")
        ttk.Label(left_section, textvariable=ip_var, font=("Arial", 9)).pack(side="left", padx=5)

        right_section = ttk.Frame(self)
        right_section.pack(side="right", padx=5, pady=2)

        self.status_label = ttk.Label(right_section, textvariable=status_var, font=("Arial", 9, "bold"))
        self.status_label.pack(side="right")

        self.status_var = status_var
        self.status_var.trace_add("write", self.update_status_color)

    def update_status_color(self, *args):
        status = self.status_var.get()
        if "Running" in status:
            self.status_label.configure(foreground="#2e7d32")
        else:
            self.status_label.configure(foreground="#d32f2f")

# Security Feature Tabs

class DownloadManagerTab(ttk.Frame):
    def __init__(self, master, security_manager):
        super().__init__(master)
        self.security_manager = security_manager
        self.setup_ui()
        self.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_ui(self):
        ttk.Label(self, text="Secure Download Manager with Real-time Scanning", 
                  font=("Arial", 12, "bold")).pack(pady=10)
        
        info_frame = ttk.LabelFrame(self, text=" Download Statistics ", padding=10)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.total_downloads_var = tk.StringVar(value="Total Downloads: 0")
        self.blocked_downloads_var = tk.StringVar(value="Blocked: 0")
        self.safe_downloads_var = tk.StringVar(value="Safe: 0")
        
        ttk.Label(info_frame, textvariable=self.total_downloads_var, font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(info_frame, textvariable=self.blocked_downloads_var, foreground="#d32f2f", font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(info_frame, textvariable=self.safe_downloads_var, foreground="#2e7d32", font=("Arial", 10)).pack(side="left", padx=10)
        
        table_frame = ttk.Frame(self)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("Time", "Filename", "URL", "Status", "VT Score", "Safety")
        self.download_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)
        
        column_widths = (80, 150, 400, 100, 80, 100)
        for col, width in zip(columns, column_widths):
            self.download_table.heading(col, text=col, anchor="center")
            self.download_table.column(col, width=width, anchor="center")
        
        self.download_table.tag_configure("safe", background="#e8f5e8")
        self.download_table.tag_configure("blocked", background="#ffe6e6", foreground="#d32f2f")
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.download_table.yview)
        self.download_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.download_table.pack(side="left", fill="both", expand=True)
        
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="Refresh", command=self.refresh_downloads).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Clear List", command=self.clear_list).pack(side="left", padx=5)
        
        note_label = ttk.Label(self, text="Note: Configure VirusTotal API key in .env file for URL scanning",
                               font=("Arial", 8), foreground="gray")
        note_label.pack(pady=5)
    
    def process_packet(self, packet_info):
        self.refresh_downloads()
    
    def refresh_downloads(self):
        self.download_table.delete(*self.download_table.get_children())
        
        downloads = self.security_manager.get_downloads()
        safe_count = sum(1 for d in downloads if d.get("safe", True))
        blocked_count = len(downloads) - safe_count
        
        self.total_downloads_var.set(f"Total Downloads: {len(downloads)}")
        self.safe_downloads_var.set(f"Safe: {safe_count}")
        self.blocked_downloads_var.set(f"Blocked: {blocked_count}")
        
        for download in downloads:
            safety = "✓ SAFE" if download.get("safe", True) else "✗ BLOCKED"
            tag = "safe" if download.get("safe", True) else "blocked"
            vt_score = f"{download.get('vt_score', 0):.1f}%"
            
            self.download_table.insert("", 0, values=(
                download["time"],
                download["filename"][:30],
                download["url"][:50] + "..." if len(download["url"]) > 50 else download["url"],
                download["status"],
                vt_score,
                safety
            ), tags=(tag,))
    
    def clear_list(self):
        self.download_table.delete(*self.download_table.get_children())

class ThreatDetectionTab(ttk.Frame):
    def __init__(self, master, security_manager):
        super().__init__(master)
        self.security_manager = security_manager
        self.setup_ui()
        self.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_ui(self):
        ttk.Label(self, text="AI-Powered Threat Detection & Analysis", 
                  font=("Arial", 12, "bold")).pack(pady=10)
        
        stats_frame = ttk.LabelFrame(self, text=" Threat Statistics ", padding=10)
        stats_frame.pack(fill="x", padx=10, pady=5)
        
        self.threat_count_var = tk.StringVar(value="Total Threats: 0")
        self.high_severity_var = tk.StringVar(value="High Severity: 0")
        self.avg_score_var = tk.StringVar(value="Avg Score: 0")
        
        ttk.Label(stats_frame, textvariable=self.threat_count_var, font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.high_severity_var, foreground="#d32f2f", font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.avg_score_var, font=("Arial", 10)).pack(side="left", padx=10)
        
        table_frame = ttk.Frame(self)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("Time", "Source IP", "Dest IP", "Threat Score", "Reasons", "Severity")
        self.threat_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)
        
        column_widths = (80, 120, 120, 100, 350, 100)
        for col, width in zip(columns, column_widths):
            self.threat_table.heading(col, text=col, anchor="center")
            self.threat_table.column(col, width=width, anchor="center")
        
        self.threat_table.tag_configure("low", background="#fff9e6")
        self.threat_table.tag_configure("medium", background="#ffe6cc")
        self.threat_table.tag_configure("high", background="#ffe6e6", foreground="#d32f2f")
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.threat_table.yview)
        self.threat_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.threat_table.pack(side="left", fill="both", expand=True)
        
        note_label = ttk.Label(self, text="Behavioral analysis based on connection patterns, port usage, and domain reputation",
                               font=("Arial", 8), foreground="gray")
        note_label.pack(pady=5)
    
    def process_packet(self, packet_info):
        self.refresh_threats()
    
    def refresh_threats(self):
        self.threat_table.delete(*self.threat_table.get_children())
        
        threats = self.security_manager.get_threat_history()
        high_severity = sum(1 for t in threats if t["score"] >= 50)
        avg_score = sum(t["score"] for t in threats) / len(threats) if threats else 0
        
        self.threat_count_var.set(f"Total Threats: {len(threats)}")
        self.high_severity_var.set(f"High Severity: {high_severity}")
        self.avg_score_var.set(f"Avg Score: {avg_score:.1f}")
        
        for threat in threats[-50:]:
            score = threat["score"]
            severity = "HIGH" if score >= 50 else "MEDIUM" if score >= 30 else "LOW"
            tag = "high" if score >= 50 else "medium" if score >= 30 else "low"
            reasons = ", ".join(threat["reasons"][:2])
            
            self.threat_table.insert("", 0, values=(
                threat["time"],
                threat["source_ip"],
                threat["dest_ip"],
                f"{score}/100",
                reasons,
                severity
            ), tags=(tag,))

class ReputationTab(ttk.Frame):
    def __init__(self, master, security_manager):
        super().__init__(master)
        self.security_manager = security_manager
        self.setup_ui()
        self.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_ui(self):
        ttk.Label(self, text="Network Reputation System", 
                  font=("Arial", 12, "bold")).pack(pady=10)
        
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # IP Reputation Tab
        ip_frame = ttk.Frame(notebook)
        notebook.add(ip_frame, text="IP Reputation")
        
        ip_table_frame = ttk.Frame(ip_frame)
        ip_table_frame.pack(fill="both", expand=True, pady=5)
        
        columns = ("IP Address", "Reputation Score", "Total Hits", "Blocked", "Status")
        self.ip_table = ttk.Treeview(ip_table_frame, columns=columns, show="headings", height=18)
        
        column_widths = (150, 150, 100, 100, 150)
        for col, width in zip(columns, column_widths):
            self.ip_table.heading(col, text=col, anchor="center")
            self.ip_table.column(col, width=width, anchor="center")
        
        self.ip_table.tag_configure("trusted", background="#e8f5e8")
        self.ip_table.tag_configure("suspicious", background="#fff9e6")
        self.ip_table.tag_configure("blocked", background="#ffe6e6", foreground="#d32f2f")
        
        scrollbar = ttk.Scrollbar(ip_table_frame, orient="vertical", command=self.ip_table.yview)
        self.ip_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.ip_table.pack(side="left", fill="both", expand=True)
        
        # Domain Reputation Tab
        domain_frame = ttk.Frame(notebook)
        notebook.add(domain_frame, text="Domain Reputation")
        
        domain_table_frame = ttk.Frame(domain_frame)
        domain_table_frame.pack(fill="both", expand=True, pady=5)
        
        columns = ("Domain", "Reputation Score", "Total Hits", "Blocked", "Status")
        self.domain_table = ttk.Treeview(domain_table_frame, columns=columns, show="headings", height=18)
        
        for col, width in zip(columns, column_widths):
            self.domain_table.heading(col, text=col, anchor="center")
            self.domain_table.column(col, width=width, anchor="center")
        
        self.domain_table.tag_configure("trusted", background="#e8f5e8")
        self.domain_table.tag_configure("suspicious", background="#fff9e6")
        self.domain_table.tag_configure("blocked", background="#ffe6e6", foreground="#d32f2f")
        
        scrollbar2 = ttk.Scrollbar(domain_table_frame, orient="vertical", command=self.domain_table.yview)
        self.domain_table.configure(yscrollcommand=scrollbar2.set)
        scrollbar2.pack(side="right", fill="y")
        self.domain_table.pack(side="left", fill="both", expand=True)
        
        ttk.Button(self, text="Refresh Reputation Data", command=self.refresh_reputation).pack(pady=5)
    
    def process_packet(self, packet_info):
        pass
    
    def refresh_reputation(self):
        self.ip_table.delete(*self.ip_table.get_children())
        self.domain_table.delete(*self.domain_table.get_children())
        
        rep_stats = self.security_manager.get_reputation_stats()
        
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

class PrivacyLeakTab(ttk.Frame):
    def __init__(self, master, security_manager):
        super().__init__(master)
        self.security_manager = security_manager
        self.setup_ui()
        self.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_ui(self):
        ttk.Label(self, text="Privacy Leak Detector - Credential & Data Monitoring", 
                  font=("Arial", 12, "bold")).pack(pady=10)
        
        stats_frame = ttk.LabelFrame(self, text=" Leak Statistics ", padding=10)
        stats_frame.pack(fill="x", padx=10, pady=5)
        
        self.total_leaks_var = tk.StringVar(value="Total Leaks: 0")
        self.high_severity_var = tk.StringVar(value="High Severity: 0")
        self.medium_severity_var = tk.StringVar(value="Medium Severity: 0")
        
        ttk.Label(stats_frame, textvariable=self.total_leaks_var, font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.high_severity_var, foreground="#d32f2f", font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.medium_severity_var, foreground="#ff9800", font=("Arial", 10)).pack(side="left", padx=10)
        
        table_frame = ttk.Frame(self)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("Time", "Leak Type", "Source IP", "Dest IP", "Severity", "Status")
        self.leak_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)
        
        column_widths = (80, 150, 150, 150, 100, 150)
        for col, width in zip(columns, column_widths):
            self.leak_table.heading(col, text=col, anchor="center")
            self.leak_table.column(col, width=width, anchor="center")
        
        self.leak_table.tag_configure("high", background="#ffe6e6", foreground="#d32f2f")
        self.leak_table.tag_configure("medium", background="#fff9e6", foreground="#ff9800")
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.leak_table.yview)
        self.leak_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.leak_table.pack(side="left", fill="both", expand=True)
        
        note_label = ttk.Label(self, text="Monitors plain-text transmission of passwords, credentials, and sensitive data",
                               font=("Arial", 8), foreground="gray")
        note_label.pack(pady=5)
    
    def process_packet(self, packet_info):
        self.refresh_leaks()
    
    def refresh_leaks(self):
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

class ProtocolInspectorTab(ttk.Frame):
    def __init__(self, master, security_manager):
        super().__init__(master)
        self.security_manager = security_manager
        self.setup_ui()
        self.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_ui(self):
        ttk.Label(self, text="Protocol Deep Inspection - HTTP/HTTPS Analysis", 
                  font=("Arial", 12, "bold")).pack(pady=10)
        
        stats_frame = ttk.LabelFrame(self, text=" Protocol Statistics ", padding=10)
        stats_frame.pack(fill="x", padx=10, pady=5)
        
        self.http_count_var = tk.StringVar(value="HTTP Requests: 0")
        self.encryption_var = tk.StringVar(value="Encrypted Traffic: 0%")
        self.total_traffic_var = tk.StringVar(value="Total Traffic: 0")
        
        ttk.Label(stats_frame, textvariable=self.http_count_var, font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.encryption_var, font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.total_traffic_var, font=("Arial", 10)).pack(side="left", padx=10)
        
        table_frame = ttk.Frame(self)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("Time", "Type", "Method/Status", "URL/Info", "User Agent")
        self.protocol_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)
        
        column_widths = (80, 100, 120, 400, 300)
        for col, width in zip(columns, column_widths):
            self.protocol_table.heading(col, text=col, anchor="center")
            self.protocol_table.column(col, width=width, anchor="center")
        
        self.protocol_table.tag_configure("request", background="#e3f2fd")
        self.protocol_table.tag_configure("response", background="#f3e5f5")
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.protocol_table.yview)
        self.protocol_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.protocol_table.pack(side="left", fill="both", expand=True)
        
        ttk.Button(self, text="Refresh Protocol Data", command=self.refresh_protocols).pack(pady=5)
    
    def process_packet(self, packet_info):
        self.refresh_protocols()
    
    def refresh_protocols(self):
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