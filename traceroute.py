#!/usr/bin/env python3
"""
Traceroute OSINT Tool
Network path analysis and OSINT gathering tool for NexusHub
"""

import socket
import subprocess
import json
import re
import requests
import whois
import dns.resolver
from datetime import datetime
import ipaddress
import geoip2.database
import geoip2.errors
import os

class TracerouteOSINT:
    def __init__(self):
        self.results: dict = {}
        self.geoip_reader = None
        self.setup_geoip()
    
    def setup_geoip(self):
        """Setup GeoIP database reader"""
        try:
            # You would need to download the GeoLite2 database
            # self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            pass
        except Exception as e:
            print(f"GeoIP setup failed: {e}")
    
    def traceroute(self, target, max_hops=30, timeout=1):
        """Perform traceroute to target"""
        try:
            # Resolve target to IP if it's a hostname
            ip = socket.gethostbyname(target)
            
            # Use system traceroute command
            if os.name == 'nt':  # Windows
                cmd = ['tracert', '-h', str(max_hops), '-w', str(timeout * 1000), target]
            else:  # Unix/Linux
                cmd = ['traceroute', '-m', str(max_hops), '-w', str(timeout), target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return self.parse_traceroute_output(result.stdout, target, ip)
            else:
                return {"error": f"Traceroute failed: {result.stderr}"}
                
        except Exception as e:
            return {"error": f"Traceroute error: {str(e)}"}
    
    def parse_traceroute_output(self, output, target, target_ip):
        """Parse traceroute command output"""
        hops = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if re.match(r'^\s*\d+', line):  # Line starts with number (hop number)
                hop_data = self.parse_hop_line(line)
                if hop_data:
                    hops.append(hop_data)
        
        return {
            "target": target,
            "target_ip": target_ip,
            "timestamp": datetime.now().isoformat(),
            "hops": hops,
            "total_hops": len(hops)
        }
    
    def parse_hop_line(self, line):
        """Parse individual hop line from traceroute output"""
        # This is a simplified parser - would need enhancement for different OS formats
        parts = line.strip().split()
        if len(parts) >= 2:
            try:
                hop_num = int(parts[0])
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                ip = ip_match.group(1) if ip_match else None
                
                return {
                    "hop": hop_num,
                    "ip": ip,
                    "hostname": self.get_hostname(ip) if ip else None,
                    "rtt": self.extract_rtt(line),
                    "osint_data": self.gather_osint(ip) if ip else {}
                }
            except:
                return None
        return None
    
    def get_hostname(self, ip):
        """Get hostname for IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    def extract_rtt(self, line):
        """Extract RTT values from traceroute line"""
        rtt_matches = re.findall(r'(\d+\.?\d*)\s*ms', line)
        if rtt_matches:
            return [float(rtt) for rtt in rtt_matches]
        return []
    
    def gather_osint(self, ip):
        """Gather OSINT information for IP address"""
        osint_data = {
            "ip": ip,
            "reverse_dns": None,
            "whois": {},
            "dns_records": {},
            "geolocation": {},
            "asn": {},
            "ports": []
        }
        
        try:
            # Reverse DNS
            osint_data["reverse_dns"] = self.get_hostname(ip)
            
            # WHOIS information
            osint_data["whois"] = self.get_whois_info(ip)
            
            # DNS records
            osint_data["dns_records"] = self.get_dns_records(ip)
            
            # Geolocation
            osint_data["geolocation"] = self.get_geolocation(ip)
            
            # Port scanning (basic)
            osint_data["ports"] = self.scan_common_ports(ip)
            
        except Exception as e:
            osint_data["error"] = str(e)
        
        return osint_data
    
    def get_whois_info(self, ip):
        """Get WHOIS information for IP"""
        try:
            w = whois.whois(ip)
            return {
                "organization": w.org,
                "country": w.country,
                "description": w.description,
                "asn": w.asn
            }
        except:
            return {}
    
    def get_dns_records(self, ip):
        """Get DNS records for IP"""
        records = {}
        try:
            # Reverse DNS
            records["PTR"] = socket.gethostbyaddr(ip)[0]
        except:
            records["PTR"] = None
        
        return records
    
    def get_geolocation(self, ip):
        """Get geolocation information for IP"""
        if not self.geoip_reader:
            return {"error": "GeoIP database not available"}
        
        try:
            response = self.geoip_reader.city(ip)
            return {
                "country": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone
            }
        except geoip2.errors.AddressNotFoundError:
            return {"error": "IP not found in database"}
        except Exception as e:
            return {"error": str(e)}
    
    def scan_common_ports(self, ip, ports=None):
        """Scan common ports on IP"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080]
        
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return open_ports
    
    def analyze_network_path(self, traceroute_data):
        """Analyze the network path for security insights"""
        analysis = {
            "summary": {},
            "security_concerns": [],
            "recommendations": []
        }
        
        hops = traceroute_data.get("hops", [])
        if not hops:
            return analysis
        
        # Basic analysis
        analysis["summary"] = {
            "total_hops": len(hops),
            "countries": [],
            "organizations": [],
            "private_ips": 0,
            "public_ips": 0
        }
        
        for hop in hops:
            ip = hop.get("ip")
            if not ip:
                continue
            
            # Count private vs public IPs
            if ipaddress.ip_address(ip).is_private:
                analysis["summary"]["private_ips"] += 1
            else:
                analysis["summary"]["public_ips"] += 1
            
            # Collect organizations
            org = hop.get("osint_data", {}).get("whois", {}).get("organization")
            if org and org not in analysis["summary"]["organizations"]:
                analysis["summary"]["organizations"].append(org)
            
            # Collect countries
            country = hop.get("osint_data", {}).get("geolocation", {}).get("country")
            if country and country not in analysis["summary"]["countries"]:
                analysis["summary"]["countries"].append(country)
        
        # Security analysis
        for hop in hops:
            ip = hop.get("ip")
            if not ip:
                continue
            
            # Check for suspicious ports
            open_ports = hop.get("osint_data", {}).get("ports", [])
            suspicious_ports = [22, 23, 3389, 3306, 5432]  # SSH, Telnet, RDP, MySQL, PostgreSQL
            for port in open_ports:
                if port in suspicious_ports:
                    analysis["security_concerns"].append(f"Open {port} port on {ip}")
            
            # Check for private IPs in public routes
            if ipaddress.ip_address(ip).is_private and analysis["summary"]["public_ips"] > 0:
                analysis["security_concerns"].append(f"Private IP {ip} in public route")
        
        return analysis
    
    def export_results(self, format="json"):
        """Export results in specified format"""
        if format == "json":
            return json.dumps(self.results, indent=2)
        elif format == "csv":
            # Implement CSV export
            pass
        elif format == "txt":
            # Implement text export
            pass
        return ""

def main():
    """Main function for command line usage"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python traceroute.py <target> [max_hops]")
        sys.exit(1)
    
    target = sys.argv[1]
    max_hops = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    
    tracer = TracerouteOSINT()
    results = tracer.traceroute(target, max_hops)
    
    if "error" in results:
        print(f"Error: {results['error']}")
        sys.exit(1)
    
    # Add analysis
    analysis_result = tracer.analyze_network_path(results)
    results["analysis"] = analysis_result
    
    # Export results
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 