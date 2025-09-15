
import tkinter as tk
from tkinter import ttk
import datetime

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

        # Shorten DNS names if too long
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
        """Shorten DNS names for better display"""
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
