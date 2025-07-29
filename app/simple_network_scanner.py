#!/usr/bin/env python3
"""
Simple Network Scanner
A basic network scanner to discover devices on the local network.
"""

import asyncio
import socket
import subprocess
import json
import sys
from typing import List, Dict, Optional
from datetime import datetime
import concurrent.futures


class SimpleNetworkScanner:
    """A simple network scanner that discovers devices on the local network."""
    
    def __init__(self):
        self.discovered_devices = []
    
    def get_local_ip(self) -> str:
        """Get the local IP address of this machine."""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # Use Google's DNS server
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    def get_network_range(self) -> str:
        """Get the network range based on local IP."""
        local_ip = self.get_local_ip()
        # Simple approach - assume /24 network
        parts = local_ip.split('.')
        network_base = '.'.join(parts[:3])
        return f"{network_base}.1-254"
    
    def ping_host(self, ip: str) -> bool:
        """Ping a host to check if it's reachable."""
        try:
            # Use ping command
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                capture_output=True,
                text=True,
                timeout=3
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_hostname(self, ip: str) -> Optional[str]:
        """Get hostname for an IP address."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None
    
    def get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address from ARP table."""
        try:
            result = subprocess.run(
                ['arp', '-n', ip],
                capture_output=True,
                text=True,
                timeout=3
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if ip in line and 'incomplete' not in line:
                        parts = line.split()
                        for part in parts:
                            # Look for MAC address pattern
                            if ':' in part and len(part) == 17:
                                return part
        except Exception:
            pass
        return None
    
    def classify_device(self, ip: str, hostname: str, mac: str) -> str:
        """Classify the device type based on available information."""
        if ip.endswith('.1'):
            return "Gateway/Router"
        
        if hostname:
            hostname_lower = hostname.lower()
            if any(keyword in hostname_lower for keyword in ['router', 'gateway', 'modem']):
                return "Router"
            elif any(keyword in hostname_lower for keyword in ['phone', 'mobile', 'iphone', 'android']):
                return "Mobile Device"
            elif any(keyword in hostname_lower for keyword in ['printer', 'print']):
                return "Printer"
            elif any(keyword in hostname_lower for keyword in ['pi', 'raspberry']):
                return "Raspberry Pi"
            elif any(keyword in hostname_lower for keyword in ['tv', 'roku', 'chromecast', 'apple-tv']):
                return "Smart TV/Streaming"
            elif any(keyword in hostname_lower for keyword in ['mac', 'macbook', 'imac']):
                return "Mac Computer"
            elif any(keyword in hostname_lower for keyword in ['windows', 'pc', 'desktop']):
                return "Windows Computer"
            else:
                return "Computer"
        
        if mac:
            # Basic MAC address OUI classification
            mac_upper = mac.upper()
            if mac_upper.startswith('00:50:56') or mac_upper.startswith('00:0C:29'):
                return "Virtual Machine"
            elif mac_upper.startswith('B8:27:EB') or mac_upper.startswith('DC:A6:32'):
                return "Raspberry Pi"
            elif mac_upper.startswith('00:1B:63'):
                return "Apple Device"
        
        return "Unknown Device"
    
    def scan_host(self, ip: str) -> Optional[Dict]:
        """Scan a single host."""
        try:
            # Check if host is alive
            if not self.ping_host(ip):
                return None
            
            # Get additional info
            hostname = self.get_hostname(ip)
            mac_address = self.get_mac_address(ip)
            device_type = self.classify_device(ip, hostname, mac_address)
            
            return {
                "ip_address": ip,
                "hostname": hostname or "Unknown",
                "mac_address": mac_address or "Unknown",
                "device_type": device_type,
                "status": "online",
                "response_time": "< 1s"
            }
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
            return None
    
    def scan_network_range(self, max_workers: int = 20) -> List[Dict]:
        """Scan the network range for active devices."""
        print("Starting network scan...")
        print(f"Local IP: {self.get_local_ip()}")
        print(f"Network range: {self.get_network_range()}")
        print()
        
        # Generate IP range
        local_ip = self.get_local_ip()
        parts = local_ip.split('.')
        network_base = '.'.join(parts[:3])
        ip_range = [f"{network_base}.{i}" for i in range(1, 255)]
        
        devices = []
        
        # Use thread pool for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all ping tasks
            future_to_ip = {executor.submit(self.scan_host, ip): ip for ip in ip_range}
            
            # Process completed tasks
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result:
                        devices.append(result)
                        print(f"✓ Found device: {result['ip_address']} ({result['hostname']}) - {result['device_type']}")
                except Exception as e:
                    print(f"✗ Error scanning {ip}: {e}")
        
        return devices
    
    def scan_and_display(self):
        """Scan the network and display results."""
        print("=" * 60)
        print("SIMPLE NETWORK SCANNER")
        print("=" * 60)
        
        start_time = datetime.now()
        devices = self.scan_network_range()
        end_time = datetime.now()
        
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        
        if not devices:
            print("No devices found on the network.")
            return
        
        print(f"Found {len(devices)} active devices:")
        print()
        
        # Sort devices by IP address
        devices.sort(key=lambda x: [int(i) for i in x['ip_address'].split('.')])
        
        for i, device in enumerate(devices, 1):
            print(f"{i}. {device['ip_address']}")
            print(f"   Hostname: {device['hostname']}")
            print(f"   MAC Address: {device['mac_address']}")
            print(f"   Device Type: {device['device_type']}")
            print(f"   Status: {device['status']}")
            print()
        
        scan_duration = (end_time - start_time).total_seconds()
        print(f"Scan completed in {scan_duration:.2f} seconds")
        
        # Save to JSON file
        output_file = f"network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        scan_data = {
            "scan_time": start_time.isoformat(),
            "scan_duration": scan_duration,
            "devices_found": len(devices),
            "network_range": self.get_network_range(),
            "local_ip": self.get_local_ip(),
            "devices": devices
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(scan_data, f, indent=2)
            print(f"Results saved to: {output_file}")
        except Exception as e:
            print(f"Error saving results: {e}")


def main():
    """Main function."""
    scanner = SimpleNetworkScanner()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help" or sys.argv[1] == "-h":
            print("Simple Network Scanner")
            print("Usage: python3 simple_network_scanner.py")
            print()
            print("This script will:")
            print("- Discover your local network range")
            print("- Scan for active devices")
            print("- Display device information")
            print("- Save results to JSON file")
            return
        elif sys.argv[1] == "--version":
            print("Simple Network Scanner v1.0")
            return
    
    try:
        scanner.scan_and_display()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
