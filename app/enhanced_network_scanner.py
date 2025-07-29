#!/usr/bin/env python3
"""
Enhanced Network Scanner with Change Detection
Monitors network changes and provides comparison between scans.
"""

import socket
import subprocess
import concurrent.futures
import time
import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
import threading


@dataclass
class Device:
    """Represents a network device."""
    ip_address: str
    hostname: Optional[str]
    mac_address: Optional[str]
    device_type: str
    status: str
    first_seen: str
    last_seen: str


class EnhancedNetworkScanner:
    """Enhanced network scanner with change detection capabilities."""
    
    def __init__(self, max_workers: int = 20):
        self.max_workers = max_workers
        self.known_devices: Dict[str, Device] = {}
        self.scan_history: List[Dict] = []
        self.lock = threading.Lock()
        
        # Load previous scan data if available
        self.load_scan_history()
    
    def load_scan_history(self):
        """Load previous scan history from files."""
        try:
            # Find the most recent scan file
            scan_files = [f for f in os.listdir('.') if f.startswith('network_scan_') and f.endswith('.json')]
            if scan_files:
                latest_file = max(scan_files, key=os.path.getctime)
                with open(latest_file, 'r') as f:
                    data = json.load(f)
                    
                # Load known devices from the latest scan
                for device_data in data.get('devices', []):
                    device = Device(
                        ip_address=device_data['ip_address'],
                        hostname=device_data.get('hostname'),
                        mac_address=device_data.get('mac_address'),
                        device_type=device_data['device_type'],
                        status=device_data['status'],
                        first_seen=device_data.get('first_seen', data['scan_time']),
                        last_seen=device_data.get('last_seen', data['scan_time'])
                    )
                    self.known_devices[device.ip_address] = device
                    
                print(f"Loaded {len(self.known_devices)} known devices from previous scan")
        except Exception as e:
            print(f"Could not load scan history: {e}")
    
    def save_scan_history(self, scan_data: Dict):
        """Save scan history to file."""
        try:
            # Add to scan history
            self.scan_history.append(scan_data)
            
            # Keep only last 10 scans
            if len(self.scan_history) > 10:
                self.scan_history = self.scan_history[-10:]
            
            # Save to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(scan_data, f, indent=2)
            
            print(f"Scan results saved to: {filename}")
        except Exception as e:
            print(f"Could not save scan history: {e}")
    
    def get_local_ip(self) -> str:
        """Get the local IP address of this machine."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    def get_network_range(self, local_ip: str) -> List[str]:
        """Generate IP range for the local network."""
        try:
            # Extract network portion (assuming /24)
            parts = local_ip.split('.')
            network_base = '.'.join(parts[:3])
            
            # Generate all possible IPs in the range
            return [f"{network_base}.{i}" for i in range(1, 255)]
        except Exception:
            return ["192.168.1.1"]
    
    def ping_host(self, ip: str) -> bool:
        """Check if a host is reachable via ping."""
        try:
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
            return socket.gethostbyaddr(ip)[0]
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
                for line in result.stdout.split('\n'):
                    if ip in line and 'incomplete' not in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:
                                return part
        except Exception:
            pass
        return None
    
    def classify_device(self, ip: str, hostname: str, mac: str) -> str:
        """Classify device type based on available information."""
        # Gateway/Router detection
        if ip.endswith('.1'):
            return "Gateway/Router"
        
        # Hostname-based classification
        if hostname:
            hostname_lower = hostname.lower()
            if any(keyword in hostname_lower for keyword in ['router', 'gateway']):
                return "Router"
            elif any(keyword in hostname_lower for keyword in ['phone', 'mobile', 'iphone', 'android']):
                return "Mobile Device"
            elif any(keyword in hostname_lower for keyword in ['printer', 'hp', 'canon', 'epson']):
                return "Printer"
            elif any(keyword in hostname_lower for keyword in ['pi', 'raspberry']):
                return "Raspberry Pi"
            elif any(keyword in hostname_lower for keyword in ['tv', 'roku', 'chromecast', 'firetv']):
                return "Smart TV/Streaming"
            elif any(keyword in hostname_lower for keyword in ['vm', 'virtual']):
                return "Virtual Machine"
            elif any(keyword in hostname_lower for keyword in ['mac', 'imac', 'macbook']):
                return "Mac Computer"
            elif any(keyword in hostname_lower for keyword in ['windows', 'desktop', 'laptop']):
                return "Computer"
            else:
                return "Computer"
        
        # MAC address-based classification (OUI lookup)
        if mac:
            mac_upper = mac.upper()
            # Apple devices
            if mac_upper.startswith(('00:1B:63', '00:1F:F3', '00:23:DF', '00:25:00')):
                return "Apple Device"
            # Raspberry Pi Foundation
            elif mac_upper.startswith(('B8:27:EB', 'DC:A6:32', 'E4:5F:01')):
                return "Raspberry Pi"
        
        return "Unknown Device"
    
    def scan_host(self, ip: str) -> Optional[Dict]:
        """Scan a single host and return device information."""
        try:
            if not self.ping_host(ip):
                return None
            
            hostname = self.get_hostname(ip)
            mac_address = self.get_mac_address(ip)
            device_type = self.classify_device(ip, hostname, mac_address)
            
            current_time = datetime.now().isoformat()
            
            # Check if this is a known device
            with self.lock:
                if ip in self.known_devices:
                    # Update existing device
                    self.known_devices[ip].last_seen = current_time
                    self.known_devices[ip].status = "online"
                    # Update other fields if they've changed
                    if hostname and not self.known_devices[ip].hostname:
                        self.known_devices[ip].hostname = hostname
                    if mac_address and not self.known_devices[ip].mac_address:
                        self.known_devices[ip].mac_address = mac_address
                else:
                    # New device
                    self.known_devices[ip] = Device(
                        ip_address=ip,
                        hostname=hostname,
                        mac_address=mac_address,
                        device_type=device_type,
                        status="online",
                        first_seen=current_time,
                        last_seen=current_time
                    )
            
            return {
                "ip_address": ip,
                "hostname": hostname,
                "mac_address": mac_address,
                "device_type": device_type,
                "status": "online",
                "first_seen": self.known_devices[ip].first_seen,
                "last_seen": current_time
            }
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
            return None
    
    def scan_network(self) -> Dict:
        """Scan the entire network and return results."""
        start_time = time.time()
        local_ip = self.get_local_ip()
        network_range = self.get_network_range(local_ip)
        
        print(f"Starting enhanced network scan...")
        print(f"Local IP: {local_ip}")
        print(f"Network range: {network_range[0]}-{network_range[-1]}")
        
        # Mark all known devices as potentially offline
        with self.lock:
            for device in self.known_devices.values():
                device.status = "offline"
        
        # Scan all IPs concurrently
        devices = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {executor.submit(self.scan_host, ip): ip for ip in network_range}
            
            for i, future in enumerate(concurrent.futures.as_completed(future_to_ip)):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result:
                        devices.append(result)
                        print(f"✓ Found device: {result['ip_address']} ({result['hostname']}) - {result['device_type']}")
                except Exception as e:
                    print(f"Error with {ip}: {e}")
                
                # Progress indicator
                if (i + 1) % 50 == 0:
                    print(f"Scanned {i + 1}/{len(network_range)} addresses...")
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        
        # Sort devices by IP address
        devices.sort(key=lambda x: tuple(map(int, x['ip_address'].split('.'))))
        
        # Analyze changes
        changes = self.analyze_changes(devices)
        
        # Prepare results
        result = {
            "scan_time": datetime.now().isoformat(),
            "scan_duration": scan_duration,
            "local_ip": local_ip,
            "network_range": f"{network_range[0]}-{network_range[-1]}",
            "devices_found": len(devices),
            "devices": devices,
            "changes": changes,
            "total_known_devices": len(self.known_devices)
        }
        
        # Save results
        self.save_scan_history(result)
        
        return result
    
    def analyze_changes(self, current_devices: List[Dict]) -> Dict:
        """Analyze changes between current and previous scans."""
        changes = {
            "new_devices": [],
            "returning_devices": [],
            "offline_devices": [],
            "updated_devices": []
        }
        
        current_ips = set(device['ip_address'] for device in current_devices)
        
        with self.lock:
            for ip, device in self.known_devices.items():
                if ip in current_ips:
                    # Device is online
                    if device.status == "offline":
                        changes["returning_devices"].append(ip)
                else:
                    # Device is offline
                    if device.status == "online":
                        changes["offline_devices"].append(ip)
            
            # Check for new devices
            for device in current_devices:
                ip = device['ip_address']
                if ip not in self.known_devices:
                    changes["new_devices"].append(ip)
        
        return changes
    
    def print_results(self, results: Dict):
        """Print scan results in a formatted way."""
        print("\n" + "=" * 60)
        print("ENHANCED NETWORK SCANNER RESULTS")
        print("=" * 60)
        
        print(f"Scan completed in {results['scan_duration']:.2f} seconds")
        print(f"Found {results['devices_found']} active devices")
        
        # Print changes
        changes = results['changes']
        if changes['new_devices']:
            print(f"\n🆕 New devices found: {len(changes['new_devices'])}")
            for ip in changes['new_devices']:
                print(f"  - {ip}")
        
        if changes['returning_devices']:
            print(f"\n🔄 Devices back online: {len(changes['returning_devices'])}")
            for ip in changes['returning_devices']:
                print(f"  - {ip}")
        
        if changes['offline_devices']:
            print(f"\n📴 Devices gone offline: {len(changes['offline_devices'])}")
            for ip in changes['offline_devices']:
                print(f"  - {ip}")
        
        if not any(changes.values()):
            print("\n✅ No changes detected since last scan")
        
        print(f"\n📊 Device Details:")
        for i, device in enumerate(results['devices'], 1):
            print(f"\n{i}. {device['ip_address']}")
            print(f"   Hostname: {device['hostname']}")
            print(f"   MAC Address: {device['mac_address']}")
            print(f"   Device Type: {device['device_type']}")
            print(f"   Status: {device['status']}")
            print(f"   First Seen: {device.get('first_seen', 'Unknown')}")
            print(f"   Last Seen: {device.get('last_seen', 'Unknown')}")


def main():
    """Main function to run the enhanced network scanner."""
    scanner = EnhancedNetworkScanner()
    
    try:
        results = scanner.scan_network()
        scanner.print_results(results)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"Error during scan: {e}")


if __name__ == "__main__":
    main()
