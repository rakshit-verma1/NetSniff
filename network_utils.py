
import subprocess
import urllib.request
import datetime
import threading
import time
import socket
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

SUSPICIOUS_PORTS = {4444, 5555, 6666, 12345}

def get_wifi_name():
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in output.splitlines():
            if "SSID" in line and "BSSID" not in line:
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "Not connected"

def get_public_ip():
    try:
        response = urllib.request.urlopen("https://api.ipify.org", timeout=4)
        return response.read().decode()
    except Exception:
        return "Unavailable"

def get_dns_name(ip_address):
    """Get domain name from IP address using reverse DNS lookup"""
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        return "No DNS"

def is_suspicious_packet(packet):
    if TCP in packet:
        tcp_layer = packet[TCP]
        return tcp_layer.sport in SUSPICIOUS_PORTS or tcp_layer.dport in SUSPICIOUS_PORTS
    return False

class PacketCapture:
    def __init__(self, packet_handler, alert_handler):
        self.packet_handler = packet_handler
        self.alert_handler = alert_handler
        self.running = False
        self.thread = None
        self.packet_count = 0
        self.delay = 0.5
        self.dns_cache = {}

    def start_capture(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self.capture_loop, daemon=True)
        self.thread.start()

    def stop_capture(self):
        self.running = False

    def capture_loop(self):
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.running)

    def get_cached_dns(self, ip_address):
        """Get DNS name with caching to improve performance"""
        if ip_address in self.dns_cache:
            return self.dns_cache[ip_address]

        dns_name = get_dns_name(ip_address)
        self.dns_cache[ip_address] = dns_name
        return dns_name

    def process_packet(self, packet):
        if IP not in packet:
            return

        time.sleep(self.delay)

        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(packet[IP].proto, str(packet[IP].proto))
        source_port = dest_port = ""

        # Get DNS names for source and destination IPs
        source_dns = self.get_cached_dns(source_ip)
        dest_dns = self.get_cached_dns(dest_ip)

        if TCP in packet or UDP in packet:
            layer = packet[TCP] if TCP in packet else packet[UDP]
            source_port = layer.sport
            dest_port = layer.dport

        packet_data = (current_time, source_ip, dest_ip, protocol, source_port, dest_port, source_dns, dest_dns)
        self.packet_handler(packet_data)

        if is_suspicious_packet(packet):
            alert_msg = f"Suspicious port detected: {source_ip} ({source_dns}) to {dest_ip} ({dest_dns})"
            self.alert_handler(alert_msg)
