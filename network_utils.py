import subprocess
import urllib.request
import datetime
import threading
from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR

SUSPICIOUS_PORTS = {4444, 5555, 6666, 12345, 31337, 1337, 8888, 9999}

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

def is_suspicious_packet(packet):
    if TCP in packet:
        tcp_layer = packet[TCP]
        return tcp_layer.sport in SUSPICIOUS_PORTS or tcp_layer.dport in SUSPICIOUS_PORTS
    return False

class PacketCapture:
    def __init__(self, packet_handler, alert_handler, security_manager):
        self.packet_handler = packet_handler
        self.alert_handler = alert_handler
        self.security_manager = security_manager
        self.running = False
        self.thread = None
        self.packet_count = 0
        self.dns_map = {}

    def start_capture(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self.capture_loop, daemon=True)
        self.thread.start()
    
    def stop_capture(self):
        self.running = False
    
    def capture_loop(self):
        sniff(prn=self.process_packet, store=False, stop_filter=lambda x: not self.running)
    
    def process_dns_packet(self, packet):
        try:
            dns_layer = packet[DNS]
            if dns_layer.qr == 1 and dns_layer.ancount > 0:
                query_name = packet[DNSQR].qname
                if isinstance(query_name, bytes):
                    query_name = query_name.decode('utf-8', errors='ignore')
                query_name = query_name.rstrip('.')
                
                for i in range(dns_layer.ancount):
                    answer = dns_layer.an[i]
                    if answer.type == 1:
                        ip = answer.rdata
                        self.dns_map[ip] = query_name
                        self.security_manager.add_dns_mapping(ip, query_name)
        except Exception:
            pass
    
    def extract_http_data(self, packet):
        try:
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                if isinstance(payload, bytes):
                    payload_str = payload.decode('utf-8', errors='ignore')
                    
                    if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                        lines = payload_str.split('\r\n')
                        if len(lines) > 0:
                            method = lines[0].split(' ')[0]
                            path = lines[0].split(' ')[1] if len(lines[0].split(' ')) > 1 else '/'
                            
                            host = ""
                            user_agent = ""
                            for line in lines[1:]:
                                if line.lower().startswith('host:'):
                                    host = line.split(':', 1)[1].strip()
                                elif line.lower().startswith('user-agent:'):
                                    user_agent = line.split(':', 1)[1].strip()
                            
                            if host:
                                url = f"http://{host}{path}"
                                self.security_manager.process_http_request(url, method, user_agent, packet)
                    
                    # Check for HTTP responses
                    elif payload_str.startswith('HTTP/'):
                        lines = payload_str.split('\r\n')
                        if len(lines) > 0:
                            status_code = lines[0].split(' ')[1] if len(lines[0].split(' ')) > 1 else '200'
                            self.security_manager.process_http_response(status_code, packet)
                            
        except Exception:
            pass
    
    def check_privacy_leaks(self, packet):
        """Check for potential privacy leaks in packet payload"""
        try:
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                if isinstance(payload, bytes):
                    payload_str = payload.decode('utf-8', errors='ignore').lower()
                    
                    # Check for credentials
                    keywords = ['password', 'passwd', 'pwd', 'user', 'username', 'email', 'token', 'api_key', 'secret']
                    for keyword in keywords:
                        if keyword in payload_str:
                            source_ip = packet[IP].src if IP in packet else "Unknown"
                            dest_ip = packet[IP].dst if IP in packet else "Unknown"
                            self.security_manager.detect_privacy_leak(keyword, source_ip, dest_ip, packet)
                            self.alert_handler(f"⚠️ Privacy Leak: '{keyword}' detected in plain text from {source_ip}")
                            break
        except Exception:
            pass
    
    def process_packet(self, packet):
        # Check for DNS packets
        if packet.haslayer(DNS):
            self.process_dns_packet(packet)
        
        # Extract HTTP data
        self.extract_http_data(packet)
        
        # Check for privacy leaks
        self.check_privacy_leaks(packet)
        
        if IP not in packet:
            return
        
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(packet[IP].proto, str(packet[IP].proto))
        source_port = dest_port = ""
        
        source_dns = self.dns_map.get(source_ip, "No DNS")
        dest_dns = self.dns_map.get(dest_ip, "No DNS")
        
        if TCP in packet or UDP in packet:
            layer = packet[TCP] if TCP in packet else packet[UDP]
            source_port = layer.sport
            dest_port = layer.dport
        
        # Store packet object for deep inspection
        packet_data = (current_time, source_ip, dest_ip, protocol, source_port, dest_port, source_dns, dest_dns, packet)
        self.packet_handler(packet_data)
        
        # Threat detection
        threat_level = self.security_manager.analyze_threat(packet_data)
        if threat_level > 50:
            self.alert_handler(f"🚨 High threat detected: {source_ip} → {dest_ip} (Score: {threat_level})")
        
        if is_suspicious_packet(packet):
            alert_msg = f"Suspicious port detected: {source_ip} ({source_dns}) to {dest_ip} ({dest_dns})"
            self.alert_handler(alert_msg)