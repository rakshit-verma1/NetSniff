import tkinter as tk
from tkinter import ttk

from network_utils import PacketCapture, get_wifi_name, get_public_ip
from data_manager import PacketDataManager, FilterManager
from security_manager import SecurityManager

from tab_packet_capture import PacketCaptureTab
from tab_download_manager import DownloadManagerTab
from tab_threat_detection import ThreatDetectionTab
from tab_reputation import ReputationTab
from tab_privacy_leak import PrivacyLeakTab
from tab_protocol_inspector import ProtocolInspectorTab


class NetworkSnifferApp(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("NetSniff Pro - Advanced Security Suite")
        self.geometry("1800x900")
        self.minsize(1400, 700)
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.public_ip = get_public_ip()
        self.data_manager = PacketDataManager()
        self.filter_manager = FilterManager(self.public_ip)
        self.security_manager = SecurityManager()
        
        self.setup_interface()
        
        self.packet_capture = PacketCapture(
            self.handle_packet,
            self.handle_alert,
            self.security_manager
        )
        
        self.protocol("WM_DELETE_WINDOW", self.close_app)
    
    def setup_interface(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=8, pady=8)
        
        self.setup_title_section(main_frame)
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill="both", expand=True, pady=(0, 5))
        
        self.init_tabs()
        
        self.setup_control_section(main_frame)
        
        self.setup_status_bar(main_frame)
    
    def setup_title_section(self, parent):
        title_section = ttk.Frame(parent)
        title_section.pack(fill="x", pady=(0, 10))
        
        title = ttk.Label(title_section, text="NetSniff Pro - Advanced Security Suite", 
                         font=("Arial", 16, "bold"))
        title.pack(side="left")
        
        stats_section = ttk.Frame(title_section)
        stats_section.pack(side="right")
        
        self.packet_count_var = tk.StringVar(value="Packets: 0")
        self.alert_count_var = tk.StringVar(value="Alerts: 0")
        self.threat_score_var = tk.StringVar(value="Threat Score: 0")
        
        ttk.Label(stats_section, textvariable=self.packet_count_var, 
                 font=("Arial", 9)).pack(side="left", padx=5)
        ttk.Label(stats_section, textvariable=self.alert_count_var, 
                 font=("Arial", 9)).pack(side="left", padx=5)
        ttk.Label(stats_section, textvariable=self.threat_score_var, 
                 font=("Arial", 9, "bold"), foreground="#d32f2f").pack(side="left", padx=5)
    
    def init_tabs(self):

        self.packet_capture_tab = PacketCaptureTab(
            self.notebook,
            self.data_manager,
            self.filter_manager,
            self.public_ip
        )
        self.notebook.add(self.packet_capture_tab.get_frame(), text="📡 Packet Capture")
        
        self.download_manager_tab = DownloadManagerTab(
            self.notebook,
            self.security_manager
        )
        self.notebook.add(self.download_manager_tab.get_frame(), text="⬇️ Download Manager")
        
        self.threat_detection_tab = ThreatDetectionTab(
            self.notebook,
            self.security_manager
        )
        self.notebook.add(self.threat_detection_tab.get_frame(), text="🛡️ Threat Detection")
        
        # Tab 4: Reputation
        self.reputation_tab = ReputationTab(
            self.notebook,
            self.security_manager
        )
        self.notebook.add(self.reputation_tab.get_frame(), text="⭐ Reputation")
        
        # Tab 5: Privacy Leak Detector
        self.privacy_leak_tab = PrivacyLeakTab(
            self.notebook,
            self.security_manager
        )
        self.notebook.add(self.privacy_leak_tab.get_frame(), text="🔒 Privacy Leaks")
        
        # Tab 6: Protocol Inspector
        self.protocol_inspector_tab = ProtocolInspectorTab(
            self.notebook,
            self.security_manager
        )
        self.notebook.add(self.protocol_inspector_tab.get_frame(), text="🔍 Protocol Inspector")
    
    def setup_control_section(self, parent):
        control_section = ttk.Frame(parent)
        control_section.pack(fill="x", pady=(5, 0))
        
        left_controls = ttk.Frame(control_section)
        left_controls.pack(side="left", fill="x", expand=False)
        
        self.start_button = ttk.Button(left_controls, text="▶ Start Capture", 
                                       command=self.start_capturing, width=15)
        self.start_button.pack(side="left", padx=(0, 5))
        
        self.stop_button = ttk.Button(left_controls, text="⏸ Stop Capture", 
                                      command=self.stop_capturing, state="disabled", width=15)
        self.stop_button.pack(side="left", padx=(0, 10))
        
        ttk.Button(left_controls, text="🗑 Clear", 
                  command=self.clear_all_data, width=10).pack(side="left")
        
        right_controls = ttk.Frame(control_section)
        right_controls.pack(side="right", fill="x", expand=False)
        
        ttk.Button(right_controls, text="📥 Export CSV", 
                  command=self.data_manager.export_to_csv, width=15).pack(side="right")
    
    def setup_status_bar(self, parent):
        status_frame = ttk.Frame(parent, relief="sunken", borderwidth=1)
        status_frame.pack(fill="x", pady=(5, 0))
        
        left_section = ttk.Frame(status_frame)
        left_section.pack(side="left", fill="x", expand=True, padx=5, pady=2)
        
        self.ssid_var = tk.StringVar(value=f"SSID: {get_wifi_name()}")
        self.public_ip_var = tk.StringVar(value=f"Public IP: {self.public_ip}")
        self.status_var = tk.StringVar(value="Status: Stopped")
        
        ttk.Label(left_section, text="Network:", font=("Arial", 9)).pack(side="left")
        ttk.Label(left_section, textvariable=self.ssid_var, 
                 font=("Arial", 9)).pack(side="left", padx=(5, 15))
        
        ttk.Label(left_section, text="Public IP:", font=("Arial", 9)).pack(side="left")
        ttk.Label(left_section, textvariable=self.public_ip_var, 
                 font=("Arial", 9)).pack(side="left", padx=5)
        
        right_section = ttk.Frame(status_frame)
        right_section.pack(side="right", padx=5, pady=2)
        
        self.status_label = ttk.Label(right_section, textvariable=self.status_var, 
                                      font=("Arial", 9, "bold"))
        self.status_label.pack(side="right")
        
        self.status_var.trace_add("write", self.update_status_color)
    
    def update_status_color(self, *args):
        status = self.status_var.get()
        if "Running" in status:
            self.status_label.configure(foreground="#2e7d32")
        else:
            self.status_label.configure(foreground="#d32f2f")
    
    def start_capturing(self):
        self.clear_all_data()
        self.status_var.set("Status: Running")
        self.start_button["state"] = "disabled"
        self.stop_button["state"] = "normal"
        self.packet_capture.start_capture()
        self.packet_capture_tab.add_alert("Packet capture started - All security features enabled")
    
    def stop_capturing(self):
        self.packet_capture.stop_capture()
        self.status_var.set("Status: Stopped")
        self.start_button["state"] = "normal"
        self.stop_button["state"] = "disabled"
        self.packet_capture_tab.add_alert("Packet capture stopped")
    
    def clear_all_data(self):
        self.data_manager.clear_data()
        self.security_manager.clear_data()
        self.packet_capture_tab.clear_all()
        self.update_statistics()
    
    def update_statistics(self):
        self.packet_count_var.set(f"Packets: {self.data_manager.get_packet_count()}")
        self.alert_count_var.set(f"Alerts: {self.data_manager.get_alert_count()}")
        threat_score = self.security_manager.get_current_threat_score()
        self.threat_score_var.set(f"Threat Score: {threat_score}/100")
    
    def handle_packet(self, packet_info):

        if not self.packet_capture_tab.should_display(packet_info):
            return
        
        self.data_manager.add_packet(packet_info)
        
        self.packet_capture_tab.process_packet(packet_info)
        self.download_manager_tab.process_packet(packet_info)
        self.threat_detection_tab.process_packet(packet_info)
        self.reputation_tab.process_packet(packet_info)
        self.privacy_leak_tab.process_packet(packet_info)
        self.protocol_inspector_tab.process_packet(packet_info)
        
        self.update_statistics()
    
    def handle_alert(self, alert_message):
        self.packet_capture_tab.add_alert(alert_message)
        self.data_manager.increment_alerts()
        self.update_statistics()
    
    def close_app(self):
        if hasattr(self, 'packet_capture'):
            self.packet_capture.stop_capture()
        self.quit()
        self.destroy()


if __name__ == "__main__":
    try:
        app = NetworkSnifferApp()
        app.mainloop()
    except KeyboardInterrupt:
        print("Application stopped by user")
    except Exception as error:
        print(f"Error: {error}")
        import traceback
        traceback.print_exc()
