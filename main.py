
import tkinter as tk
from tkinter import ttk
from network_utils import PacketCapture, get_wifi_name, get_public_ip, SUSPICIOUS_PORTS
from ui_components import FilterPanel, PacketTable, AlertBox, StatusBar
from data_manager import PacketDataManager, FilterManager

class NetworkSnifferApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("NetSniff")
        self.geometry("1400x700")
        self.minsize(1200, 600)

        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.public_ip = get_public_ip()

        self.ssid_var = tk.StringVar(value=f"SSID: {get_wifi_name()}")
        self.public_ip_var = tk.StringVar(value=f"Public IP: {self.public_ip}")
        self.status_var = tk.StringVar(value="Status: Stopped")

        self.packet_count_var = tk.StringVar(value="Packets: 0")
        self.alert_count_var = tk.StringVar(value="Alerts: 0")

        self.data_manager = PacketDataManager()
        self.filter_manager = FilterManager(self.public_ip)

        self.setup_interface()

        self.packet_capture = PacketCapture(self.handle_packet, self.handle_alert)

        self.protocol("WM_DELETE_WINDOW", self.close_app)

    def setup_interface(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=8, pady=8)

        title_section = ttk.Frame(main_frame)
        title_section.pack(fill="x", pady=(0, 10))

        title = ttk.Label(title_section, text="Network Packet Sniffer with DNS", font=("Arial", 16, "bold"))
        title.pack(side="left")

        stats_section = ttk.Frame(title_section)
        stats_section.pack(side="right")

        ttk.Label(stats_section, textvariable=self.packet_count_var, font=("Arial", 9)).pack(side="left", padx=5)
        ttk.Label(stats_section, textvariable=self.alert_count_var, font=("Arial", 9)).pack(side="left", padx=5)

        filter_section = ttk.LabelFrame(main_frame, text=" Filter Options ", padding=10)
        filter_section.pack(fill="x", pady=(0, 5))

        self.filters = FilterPanel(filter_section)
        self.filters.pack(fill="x")

        content_section = ttk.Frame(main_frame)
        content_section.pack(fill="both", expand=True, pady=(0, 5))

        table_section = ttk.LabelFrame(content_section, text=" Live Packet Capture with DNS Resolution ", padding=5)
        table_section.pack(fill="both", expand=True, pady=(0, 5))

        table_frame = ttk.Frame(table_section)
        table_frame.pack(fill="both", expand=True)

        self.packet_table = PacketTable(table_frame)
        self.packet_table.pack(side="left", fill="both", expand=True)

        alert_section = ttk.LabelFrame(content_section, text=" Security Alerts ", padding=5)
        alert_section.pack(fill="x", pady=(5, 0))

        alert_frame = ttk.Frame(alert_section)
        alert_frame.pack(fill="both", expand=True)

        self.alert_box = AlertBox(alert_frame)
        self.alert_box.pack(side="left", fill="both", expand=True)

        control_section = ttk.Frame(main_frame)
        control_section.pack(fill="x", pady=(5, 0))

        left_controls = ttk.Frame(control_section)
        left_controls.pack(side="left")

        self.start_button = ttk.Button(left_controls, text="Start Capture", command=self.start_capturing)
        self.start_button.pack(side="left", padx=(0, 5))

        self.stop_button = ttk.Button(left_controls, text="Stop Capture", command=self.stop_capturing, state="disabled")
        self.stop_button.pack(side="left", padx=(0, 10))

        ttk.Button(left_controls, text="Clear", command=self.clear_all_data).pack(side="left")

        right_controls = ttk.Frame(control_section)
        right_controls.pack(side="right")

        ttk.Button(right_controls, text="Export CSV", command=self.data_manager.export_to_csv).pack(side="right")

        self.status_bar = StatusBar(main_frame, self.ssid_var, self.public_ip_var, self.status_var)
        self.status_bar.pack(fill="x", pady=(5, 0))

    def start_capturing(self):
        self.clear_all_data()
        self.status_var.set("Status: Running")
        self.start_button["state"] = "disabled"
        self.stop_button["state"] = "normal"
        self.packet_capture.start_capture()
        self.alert_box.add_alert("Packet capture started - DNS resolution enabled")

    def stop_capturing(self):
        self.packet_capture.stop_capture()
        self.status_var.set("Status: Stopped")
        self.start_button["state"] = "normal"
        self.stop_button["state"] = "disabled"
        self.alert_box.add_alert("Packet capture stopped")

    def clear_all_data(self):
        self.data_manager.clear_data()
        self.packet_table.clear_table()
        self.alert_box.clear_alerts()
        self.update_statistics()

    def update_statistics(self):
        self.packet_count_var.set(f"Packets: {self.data_manager.get_packet_count()}")
        self.alert_count_var.set(f"Alerts: {self.data_manager.get_alert_count()}")

    def handle_packet(self, packet_info):
        if not self.filter_manager.should_display_packet(packet_info, self.filters):
            return

        self.data_manager.add_packet(packet_info)

        time, source_ip, dest_ip, protocol, sport, dport, source_dns, dest_dns = packet_info
        is_suspicious = (sport in SUSPICIOUS_PORTS or dport in SUSPICIOUS_PORTS) if sport and dport else False

        self.packet_table.add_packet_row(packet_info, is_suspicious)
        self.update_statistics()

    def handle_alert(self, alert_message):
        self.alert_box.add_alert(alert_message)
        self.data_manager.increment_alerts()
        self.update_statistics()

    def close_app(self):
        if hasattr(self, 'packet_capture'):
            self.packet_capture.stop_capture()
        self.destroy()

if __name__ == "__main__":
    try:
        app = NetworkSnifferApp()
        app.mainloop()
    except KeyboardInterrupt:
        print("Application stopped by user")
    except Exception as error:
        print(f"Error: {error}")
