#!/usr/bin/env python3
"""
Simple Network Scanner
Scans the local network for connected devices
"""

import asyncio
import subprocess
import socket
import netifaces
from datetime import datetime
from typing import List, Dict, Optional
import json
import sys


class SimpleNetworkScanner:
    """Simple network scanner without requiring root privileges"""
    
    def __init__(self):
        self.devices = []
    
    def get_default_gateway(self) -> Optional[str]:
        """Get the default gateway IP address"""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
            if default_gateway:
                return default_gateway[0]
        except Exception as e:
            print(f"Error getting default gateway: {e}")
        return None
    
    def get_local_network_range(self) -> str:
        """Get the local network range"""
        try:
            # Get all interfaces and find the one with a private IP
            for interface_name in netifaces.interfaces():
                interface_info = netifaces.ifaddresses(interface_name)
                if netifaces.AF_INET in interface_info:
                    ipv4_info = interface_info[netifaces.AF_INET][0]
                    ip = ipv4_info.get('addr', '')
                    netmask = ipv4_info.get('netmask', '')
                    
                    # Skip loopback
                    if ip.startswith('127.'):
                        continue
                    
                    # Check for private IP ranges
                    if (ip.startswith('192.168.') or 
                        ip.startswith('10.') or 
                        ip.startswith('172.')):
                        
                        network = self.calculate_network_address(ip, netmask)
                        return f"{network}/24"
            
            # Fallback
            return "192.168.1.0/24"
        except Exception as e:
            print(f"Error getting network range: {e}")
            return "192.168.1.0/24"
    
    def calculate_network_address(self, ip: str, netmask: str) -> str:
        """Calculate network address from IP and netmask"""
        try:
            ip_parts = [int(x) for x in ip.split('.')]
            netmask_parts = [int(x) for x in netmask.split('.')]
            
            network_parts = []
            for i in range(4):
                network_parts.append(ip_parts[i] & netmask_parts[i])
            
            return '.'.join(map(str, network_parts))
        except:
            return "192.168.1.0"
    
    async def ping_host(self, ip: str) -> bool:
        """Ping a host to check if it's alive"""
        try:
            # Use ping command
            process = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '1', ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()
            return process.returncode == 0
        except:
            return False
    
    def get_hostname(self, ip: str) -> Optional[str]:
        """Get hostname for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def get_mac_address_from_arp(self, ip: str) -> Optional[str]:
        """Get MAC address from ARP table"""
        try:
            # Try to get MAC from ARP table
            result = subprocess.run(['arp', '-n', ip], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if ip in line and 'incomplete' not in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            # Look for MAC address pattern
                            for part in parts:
                                if ':' in part and len(part) == 17:
                                    return part
        except:
            pass
        return None
    
    async def scan_host(self, ip: str) -> Optional[Dict]:
        """Scan a single host"""
        try:
            # Check if host is alive
            is_alive = await self.ping_host(ip)
            if not is_alive:
                return None
            
            # Get hostname
            hostname = self.get_hostname(ip)
            
            # Get MAC address
            mac_address = self.get_mac_address_from_arp(ip)
            
            # Determine device type based on IP
            device_type = "Unknown"
            if ip.endswith('.1'):
                device_type = "Gateway/Router"
            elif hostname:
                hostname_lower = hostname.lower()
                if 'router' in hostname_lower or 'gateway' in hostname_lower:
                    device_type = "Router"
                elif 'switch' in hostname_lower:
                    device_type = "Switch"
                elif 'printer' in hostname_lower:
                    device_type = "Printer"
                elif 'phone' in hostname_lower or 'mobile' in hostname_lower:
                    device_type = "Mobile Device"
                else:
                    device_type = "Computer"
            
            return {
                "ip_address": ip,
                "hostname": hostname,
                "mac_address": mac_address,
                "device_type": device_type,
                "status": "online"
            }
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
            return None
    
    async def scan_network(self, network_range: str = None) -> List[Dict]:
        """Scan the network for devices"""
        if network_range is None:
            network_range = self.get_local_network_range()
        
        print(f"Scanning network: {network_range}")
        
        # Parse network range
        try:
            network_part, cidr = network_range.split('/')
            network_parts = network_part.split('.')
            base_ip = '.'.join(network_parts[:3])
            
            # Create IP range (assuming /24)
            ip_range = [f"{base_ip}.{i}" for i in range(1, 255)]
            
        except Exception as e:
            print(f"Error parsing network range: {e}")
            return []
        
        # Scan hosts in parallel
        tasks = []
        for ip in ip_range:
            task = self.scan_host(ip)
            tasks.append(task)
        
        # Execute tasks with a reasonable chunk size
        chunk_size = 50
        results = []
        
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i + chunk_size]
            chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
            results.extend(chunk_results)
        
        # Filter out None results and exceptions
        devices = [device for device in results if isinstance(device, dict)]
        
        return devices
    
    def get_network_interfaces(self) -> List[Dict]:
        """Get network interfaces"""
        interfaces = []
        
        try:
            for interface_name in netifaces.interfaces():
                interface_info = netifaces.ifaddresses(interface_name)
                
                if netifaces.AF_INET in interface_info:
                    ipv4_info = interface_info[netifaces.AF_INET][0]
                    
                    interface = {
                        "name": interface_name,
                        "ip_address": ipv4_info.get('addr', ''),
                        "netmask": ipv4_info.get('netmask', ''),
                        "broadcast": ipv4_info.get('broadcast'),
                        "is_up": True
                    }
                    interfaces.append(interface)
        except Exception as e:
            print(f"Error getting interfaces: {e}")
        
        return interfaces


async def main():
    """Main function"""
    scanner = SimpleNetworkScanner()
    
    print("=== Network Scanner ===")
    print(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Get network interfaces
    print("Network Interfaces:")
    interfaces = scanner.get_network_interfaces()
    for iface in interfaces:
        print(f"  {iface['name']}: {iface['ip_address']}/{iface['netmask']}")
    print()
    
    # Get gateway
    gateway = scanner.get_default_gateway()
    print(f"Default Gateway: {gateway}")
    print()
    
    # Scan network
    print("Scanning for devices...")
    devices = await scanner.scan_network()
    
    print(f"\nFound {len(devices)} devices:")
    print("-" * 80)
    print(f"{'IP Address':<15} {'Hostname':<20} {'MAC Address':<18} {'Device Type':<15}")
    print("-" * 80)
    
    for device in devices:
        hostname = device.get('hostname') or 'N/A'
        hostname = hostname[:19] if len(hostname) > 19 else hostname
        mac = device.get('mac_address') or 'N/A'
        device_type = device.get('device_type') or 'Unknown'
        
        print(f"{device['ip_address']:<15} {hostname:<20} {mac:<18} {device_type:<15}")
    
    # Save results to JSON
    results = {
        "scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "network_range": scanner.get_local_network_range(),
        "gateway": gateway,
        "interfaces": interfaces,
        "devices_found": len(devices),
        "devices": devices
    }
    
    with open('network_scan_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: network_scan_results.json")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
