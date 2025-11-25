
import tkinter as tk
from tkinter import ttk


class ThreatDetectionTab:
    
    def __init__(self, parent, security_manager):
        self.frame = ttk.Frame(parent)
        self.security_manager = security_manager
        self.setup_ui()
    
    def get_frame(self):
        return self.frame
    
    def setup_ui(self):
        ttk.Label(self.frame, text="Threat Detection & Analysis",
                  font=("Arial", 12, "bold")).pack(pady=10)
        
        stats_frame = ttk.LabelFrame(self.frame, text=" Threat Statistics ", padding=10)
        stats_frame.pack(fill="x", padx=10, pady=5)
        
        self.threat_count_var = tk.StringVar(value="Total Threats: 0")
        self.high_severity_var = tk.StringVar(value="High Severity: 0")
        self.avg_score_var = tk.StringVar(value="Avg Score: 0")
        
        ttk.Label(stats_frame, textvariable=self.threat_count_var,
                  font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.high_severity_var,
                  foreground="#d32f2f", font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.avg_score_var,
                  font=("Arial", 10)).pack(side="left", padx=10)
        
        table_frame = ttk.Frame(self.frame)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("Time", "Source IP", "Dest IP", "Threat Score", "Reasons", "Severity")
        self.threat_table = ttk.Treeview(table_frame, columns=columns,
                                        show="headings", height=20)
        
        column_widths = (80, 120, 120, 100, 350, 100)
        for col, width in zip(columns, column_widths):
            self.threat_table.heading(col, text=col, anchor="center")
            self.threat_table.column(col, width=width, anchor="center")
        
        self.threat_table.tag_configure("low", background="#fff9e6")
        self.threat_table.tag_configure("medium", background="#ffe6cc")
        self.threat_table.tag_configure("high", background="#ffe6e6",
                                       foreground="#d32f2f")
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical",
                                 command=self.threat_table.yview)
        self.threat_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.threat_table.pack(side="left", fill="both", expand=True)
        
        note_label = ttk.Label(self.frame,
                               text="Behavioral analysis based on connection patterns, port usage, and domain reputation",
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
