
import os
import ssl
import socket
import hashlib
import urllib.request
import urllib.parse
import json
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()


class SecurityManager:
    
    def __init__(self):
        self.dns_cache = {}
        
        self.ip_reputation = defaultdict(lambda: {
            "score": 80,
            "hits": 0,
            "blocked": 0,
            "history": []
        })
        self.domain_reputation = defaultdict(lambda: {
            "score": 50,
            "hits": 0,
            "blocked": 0
        })
        
        self.threat_history = []
        self.privacy_leaks = []
        self.http_traffic = []
        self.downloads = []
        self.manual_downloads = []  
        
        self.connection_frequency = defaultdict(int)
        self.port_usage = Counter()
        self.protocol_stats = Counter()
        
        self.geo_cache = {}
        
        self.blocklist_domains = [
            'doubleclick.net', 'google-analytics.com', 'facebook.com/tr',
            'googleadservices.com', 'googlesyndication.com',
            'ads.', 'tracker.', 'analytics.', 'telemetry.',
            'ad.', 'adservice.', 'metrics.'
        ]
        
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        if self.vt_api_key:
            print(f"✓ VirusTotal API key loaded successfully")
        else:
            print("⚠ Warning: VirusTotal API key not found in .env file")
            print("  Create a .env file with: VIRUSTOTAL_API_KEY=your_key_here")
        
        self.stats = {
            "total_threats": 0,
            "total_leaks": 0,
            "total_downloads": 0,
            "session_start": datetime.now()
        }
    
    def clear_data(self):
        self.threat_history.clear()
        self.privacy_leaks.clear()
        self.http_traffic.clear()
        self.downloads.clear()
        self.manual_downloads.clear()
        self.connection_frequency.clear()
        self.port_usage.clear()
        self.protocol_stats.clear()
        
        self.stats = {
            "total_threats": 0,
            "total_leaks": 0,
            "total_downloads": 0,
            "session_start": datetime.now()
        }
        
        print("Security data cleared")
    
    def add_dns_mapping(self, ip, domain):
        self.dns_cache[ip] = domain
    
    def get_domain_for_ip(self, ip):
        return self.dns_cache.get(ip, "Unknown")
    
    def add_manual_download(self, download_info):
        self.manual_downloads.append(download_info)
        self.stats["total_downloads"] += 1
        print(f"Manual download added: {download_info['filename']}")
    
    def get_manual_downloads(self):
        return self.manual_downloads
    
    def update_manual_download(self, download_id, updates):
        for download in self.manual_downloads:
            if download.get("id") == download_id:
                download.update(updates)
                return True
        return False
    
    def get_downloads(self):
        return self.downloads
    
    def analyze_threat(self, packet_info):
        time, source_ip, dest_ip, protocol, sport, dport, source_dns, dest_dns, packet = packet_info
        
        threat_score = 0
        reasons = []
        
        self.protocol_stats[protocol] += 1
        
        suspicious_ports = {4444, 5555, 6666, 12345, 31337, 1337, 8888, 9999}
        if sport in suspicious_ports or dport in suspicious_ports:
            threat_score += 30
            reasons.append(f"Suspicious port usage: {sport or dport}")
        
        conn_key = f"{source_ip}:{dest_ip}"
        self.connection_frequency[conn_key] += 1
        if self.connection_frequency[conn_key] > 100:
            threat_score += 20
            reasons.append("High frequency connections")
        
        for domain in [source_dns, dest_dns]:
            if domain != "No DNS":
                for blocked in self.blocklist_domains:
                    if blocked in domain.lower():
                        threat_score += 40
                        reasons.append(f"Blocked domain: {domain}")
                        self.domain_reputation[domain]["blocked"] += 1
                        break
                
                self.domain_reputation[domain]["hits"] += 1
        
        if dport:
            self.port_usage[dport] += 1
        
        unique_ports = len(self.port_usage)
        if unique_ports > 50:
            threat_score += 15
            reasons.append("Potential port scanning")
        
        self.ip_reputation[source_ip]["hits"] += 1
        
        if threat_score > 0:
            # Decrease reputation score
            self.ip_reputation[source_ip]["score"] = max(
                0,
                self.ip_reputation[source_ip]["score"] - threat_score / 10
            )
            self.ip_reputation[source_ip]["history"].append({
                "time": time,
                "threat": threat_score,
                "reasons": reasons
            })
            
            # Track blocked IPs
            if threat_score >= 50:
                self.ip_reputation[source_ip]["blocked"] += 1
        
        # Store threat history
        if threat_score > 30:
            self.threat_history.append({
                "time": time,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "score": threat_score,
                "reasons": reasons,
                "protocol": protocol
            })
            self.stats["total_threats"] += 1
        
        return min(threat_score, 100)
    
    def get_current_threat_score(self):
        """Calculate current overall threat score"""
        if not self.threat_history:
            return 0
        
        # Average of recent threats (last 10)
        recent = self.threat_history[-10:]
        return int(sum(t["score"] for t in recent) / len(recent))
    
    def get_threat_history(self):
        return self.threat_history
    
    # Reputation Management
    def get_ip_reputation(self, ip):
        return self.ip_reputation[ip]
    
    def get_domain_reputation(self, domain):
        """Get reputation data for domain"""
        return self.domain_reputation[domain]
    
    def get_reputation_stats(self):
        """Get reputation statistics"""
        return {
            "ips": dict(self.ip_reputation),
            "domains": dict(self.domain_reputation)
        }
    
    # SSL Certificate Verification
    def check_ssl_certificate(self, hostname):
        """Verify SSL certificate for hostname"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "valid": True,
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "subject": dict(x[0] for x in cert['subject']),
                        "version": cert['version'],
                        "notAfter": cert['notAfter']
                    }
        except Exception as e:
            return {"valid": False, "error": str(e)}
    
    # VirusTotal Integration
    def scan_url_virustotal(self, url):
        """Scan URL with VirusTotal API"""
        if not self.vt_api_key:
            return {
                "error": "VirusTotal API key not configured",
                "safe": True,
                "score": 0
            }
        
        try:
            # First, submit the URL for scanning
            api_url = "https://www.virustotal.com/api/v3/urls"
            
            data = urllib.parse.urlencode({'url': url}).encode()
            req = urllib.request.Request(api_url, data=data, method='POST')
            req.add_header("x-apikey", self.vt_api_key)
            req.add_header("Accept", "application/json")
            
            response = urllib.request.urlopen(req, timeout=10)
            result = json.loads(response.read().decode())
            
            # Get the analysis ID
            analysis_id = result.get('data', {}).get('id', '')
            
            if not analysis_id:
                return {
                    "error": "Failed to get analysis ID",
                    "safe": True,
                    "score": 0
                }
            
            # Wait a moment for analysis to complete
            import time
            time.sleep(2)
            
            # Get the analysis results
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            req = urllib.request.Request(analysis_url)
            req.add_header("x-apikey", self.vt_api_key)
            req.add_header("Accept", "application/json")
            
            response = urllib.request.urlopen(req, timeout=10)
            data = json.loads(response.read().decode())
            
            stats = data.get("data", {}).get("attributes", {}).get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            
            total = malicious + suspicious + harmless + undetected
            threat_count = malicious + suspicious
            
            return {
                "safe": threat_count == 0,
                "score": (threat_count / total * 100) if total > 0 else 0,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "total": total
            }
        
        except urllib.error.HTTPError as e:
            error_msg = f"HTTP Error {e.code}"
            if e.code == 401:
                error_msg = "Invalid API key"
            elif e.code == 429:
                error_msg = "Rate limit exceeded"
            
            print(f"VirusTotal API error: {error_msg}")
            return {"error": error_msg, "safe": True, "score": 0}
        
        except Exception as e:
            print(f"VirusTotal API error: {e}")
            return {"error": str(e), "safe": True, "score": 0}
    
    def scan_file_hash_virustotal(self, file_hash):
        """Scan file hash with VirusTotal API"""
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not configured", "safe": True}
        
        try:
            api_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            
            req = urllib.request.Request(api_url)
            req.add_header("x-apikey", self.vt_api_key)
            
            response = urllib.request.urlopen(req, timeout=10)
            data = json.loads(response.read().decode())
            
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            
            return {
                "safe": malicious == 0,
                "score": (malicious / total * 100) if total > 0 else 0,
                "malicious": malicious,
                "suspicious": suspicious,
                "total": total
            }
        except Exception as e:
            return {"error": str(e), "safe": True}
    
    # HTTP Traffic Processing
    def process_http_request(self, url, method, user_agent, packet):
        """Process HTTP request"""
        self.http_traffic.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": "request",
            "method": method,
            "url": url,
            "user_agent": user_agent
        })
        
        # Check if it's a download
        download_extensions = [
            '.exe', '.zip', '.rar', '.msi', '.dmg', '.apk',
            '.deb', '.rpm', '.bin', '.sh', '.bat', '.dll',
            '.iso', '.img', '.tar', '.gz', '.7z'
        ]
        
        if any(ext in url.lower() for ext in download_extensions):
            self.detect_download(url, packet)
    
    def process_http_response(self, status_code, packet):
        """Process HTTP response"""
        self.http_traffic.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": "response",
            "status": status_code
        })
    
    def get_http_traffic(self):
        """Get HTTP traffic"""
        return self.http_traffic
    
    # Download Detection
    def detect_download(self, url, packet):
        """Detect and analyze download"""
        filename = url.split('/')[-1].split('?')[0]  # Remove query parameters
        
        if not filename:
            filename = "download"
        
        download_info = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "url": url,
            "filename": filename,
            "status": "Detected",
            "threat_score": 0
        }
        
        # Check URL reputation (async in real implementation)
        # For now, we'll just mark it as detected
        download_info["vt_score"] = 0
        download_info["safe"] = True
        
        self.downloads.append(download_info)
        self.stats["total_downloads"] += 1
        
        print(f"Download detected: {filename}")
    
    # Privacy Leak Detection
    def detect_privacy_leak(self, keyword, source_ip, dest_ip, packet):
        """Detect privacy leak"""
        leak_info = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "keyword": keyword,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "severity": self._classify_leak_severity(keyword)
        }
        
        self.privacy_leaks.append(leak_info)
        self.stats["total_leaks"] += 1
        
        print(f"Privacy leak detected: {keyword} from {source_ip}")
    
    def _classify_leak_severity(self, keyword):
        """Classify privacy leak severity"""
        high_severity_keywords = [
            'password', 'passwd', 'secret', 'private_key',
            'privatekey', 'api_key', 'apikey'
        ]
        
        if keyword.lower() in high_severity_keywords:
            return "HIGH"
        return "MEDIUM"
    
    def get_privacy_leaks(self):
        """Get privacy leaks"""
        return self.privacy_leaks
    
    # Protocol Statistics
    def get_protocol_stats(self):
        """Get protocol statistics"""
        http_count = len([t for t in self.http_traffic if t["type"] == "request"])
        
        # Calculate HTTPS ratio (would need TLS detection for accurate count)
        total_http = len(self.http_traffic)
        https_ratio = 0  # Placeholder
        
        return {
            "http_requests": http_count,
            "encrypted_ratio": https_ratio,
            "total_traffic": total_http,
            "protocols": dict(self.protocol_stats)
        }
    
    # Statistics
    def get_statistics(self):
        """Get comprehensive statistics"""
        session_duration = datetime.now() - self.stats["session_start"]
        
        return {
            "total_threats": self.stats["total_threats"],
            "total_leaks": self.stats["total_leaks"],
            "total_downloads": self.stats["total_downloads"],
            "session_duration": str(session_duration).split('.')[0],
            "unique_ips": len(self.ip_reputation),
            "unique_domains": len(self.domain_reputation),
            "http_requests": len([t for t in self.http_traffic if t["type"] == "request"]),
            "protocols": dict(self.protocol_stats)
        }
    
    # Utility Methods
    def is_suspicious_domain(self, domain):
        """Check if domain is suspicious"""
        for blocked in self.blocklist_domains:
            if blocked in domain.lower():
                return True
        return False
    
    def get_ip_location(self, ip):
        """Get IP geolocation (placeholder)"""
        # Would use geolocation API in production
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        
        return {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown"
        }
    
    def calculate_risk_score(self):
        """Calculate overall network risk score"""
        if not self.threat_history:
            return 0
        
        # Recent threats (last hour)
        one_hour_ago = datetime.now() - timedelta(hours=1)
        
        recent_threats = [
            t for t in self.threat_history
            if datetime.strptime(t["time"], "%H:%M:%S").time() >= one_hour_ago.time()
        ]
        
        if not recent_threats:
            return 0
        
        avg_threat = sum(t["score"] for t in recent_threats) / len(recent_threats)
        
        # Adjust for number of threats
        frequency_multiplier = min(len(recent_threats) / 10, 2.0)
        
        risk_score = min(avg_threat * frequency_multiplier, 100)
        
        return int(risk_score)