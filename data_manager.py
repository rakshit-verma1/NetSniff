
import csv
from tkinter import filedialog, messagebox

class PacketDataManager:
    def __init__(self):
        self.packet_data = []
        self.packet_count = 0
        self.alert_count = 0

    def add_packet(self, packet_info):
        self.packet_data.append(packet_info)
        self.packet_count += 1

    def clear_data(self):
        self.packet_data.clear()
        self.packet_count = 0
        self.alert_count = 0

    def get_packet_count(self):
        return self.packet_count

    def get_alert_count(self):
        return self.alert_count

    def increment_alerts(self):
        self.alert_count += 1

    def export_to_csv(self):
        if not self.packet_data:
            messagebox.showwarning("Export Warning", "No packets to export")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Packet Data"
        )

        if not filename:
            return

        try:
            with open(filename, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow([
                    "Time", "Source IP", "Destination IP", "Protocol", 
                    "Src Port", "Dst Port", "Source DNS", "Destination DNS"
                ])
                writer.writerows(self.packet_data)
            messagebox.showinfo("Export Success", f"Data exported to: {filename}")
        except Exception as error:
            messagebox.showerror("Export Error", f"Failed to export data: {str(error)}")

class FilterManager:
    def __init__(self, public_ip):
        self.public_ip = public_ip

    def should_display_packet(self, packet_info, filters):
        time, source_ip, dest_ip, protocol, sport, dport, source_dns, dest_dns = packet_info

        protocol_filter = filters.protocol_var.get()
        if protocol_filter and protocol != protocol_filter:
            return False

        ip_filter = filters.ip_var.get()
        if ip_filter and ip_filter not in (source_ip, dest_ip):
            return False

        port_filter = filters.port_var.get()
        if port_filter:
            try:
                want_port = int(port_filter)
                if want_port not in (sport, dport):
                    return False
            except ValueError:
                pass

        dns_filter = filters.dns_var.get().lower()
        if dns_filter:
            if dns_filter not in source_dns.lower() and dns_filter not in dest_dns.lower():
                return False

        public_only = filters.public_only.get()
        if public_only and self.public_ip not in (source_ip, dest_ip):
            return False

        return True
