import asyncio
import socket
import subprocess
import netifaces
from datetime import datetime
from typing import List, Optional, Dict, Any
from scapy.all import ARP, Ether, srp, conf
import nmap
from concurrent.futures import ThreadPoolExecutor
import logging

from app.models import NetworkDevice, NetworkInterface, NetworkScanResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkScanner:
    """Service for scanning network devices and interfaces"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.executor = ThreadPoolExecutor(max_workers=20)
        
    async def get_network_interfaces(self) -> List[NetworkInterface]:
        """Get all network interfaces with their details"""
        interfaces = []
        
        try:
            for interface_name in netifaces.interfaces():
                interface_info = netifaces.ifaddresses(interface_name)
                
                # Get IPv4 information
                if netifaces.AF_INET in interface_info:
                    ipv4_info = interface_info[netifaces.AF_INET][0]
                    
                    interface = NetworkInterface(
                        name=interface_name,
                        ip_address=ipv4_info.get('addr', ''),
                        netmask=ipv4_info.get('netmask', ''),
                        broadcast=ipv4_info.get('broadcast'),
                        is_up=True  # If we can get the info, it's likely up
                    )
                    interfaces.append(interface)
                    
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            
        return interfaces
    
    def _get_default_gateway(self) -> Optional[str]:
        """Get the default gateway IP address"""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
            if default_gateway:
                return default_gateway[0]
        except Exception as e:
            logger.error(f"Error getting default gateway: {e}")
        return None
    
    def _get_local_network_range(self) -> str:
        """Get the local network range (e.g., 192.168.1.0/24)"""
        try:
            # Get default interface
            gateway = self._get_default_gateway()
            if gateway:
                # Find the interface that can reach the gateway
                for interface_name in netifaces.interfaces():
                    interface_info = netifaces.ifaddresses(interface_name)
                    if netifaces.AF_INET in interface_info:
                        ipv4_info = interface_info[netifaces.AF_INET][0]
                        ip = ipv4_info.get('addr', '')
                        netmask = ipv4_info.get('netmask', '')
                        
                        # Check if this interface is on the same network as gateway
                        if self._is_same_network(ip, gateway, netmask):
                            # Calculate network address
                            network = self._calculate_network_address(ip, netmask)
                            cidr = self._netmask_to_cidr(netmask)
                            return f"{network}/{cidr}"
                            
            # Fallback to common ranges
            return "192.168.1.0/24"
            
        except Exception as e:
            logger.error(f"Error getting network range: {e}")
            return "192.168.1.0/24"
    
    def _is_same_network(self, ip1: str, ip2: str, netmask: str) -> bool:
        """Check if two IPs are on the same network"""
        try:
            import ipaddress
            network1 = ipaddress.IPv4Network(f"{ip1}/{netmask}", strict=False)
            ip2_addr = ipaddress.IPv4Address(ip2)
            return ip2_addr in network1
        except:
            return False
    
    def _calculate_network_address(self, ip: str, netmask: str) -> str:
        """Calculate network address from IP and netmask"""
        try:
            import ipaddress
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network.network_address)
        except:
            return "192.168.1.0"
    
    def _netmask_to_cidr(self, netmask: str) -> int:
        """Convert netmask to CIDR notation"""
        try:
            import ipaddress
            return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
        except:
            return 24
    
    async def _ping_host(self, ip: str) -> bool:
        """Ping a host to check if it's alive"""
        try:
            # Use ping command
            result = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '1000', ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.wait()
            return result.returncode == 0
        except:
            return False
    
    def _get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address for an IP using ARP"""
        try:
            # Disable scapy verbose output
            conf.verb = 0
            
            # Create ARP request
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send request and receive response
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
                
        except Exception as e:
            logger.debug(f"Error getting MAC for {ip}: {e}")
            
        return None
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """Get hostname for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def _scan_ports(self, ip: str, common_ports: List[int] = None) -> List[int]:
        """Scan common ports on a host"""
        if common_ports is None:
            common_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        open_ports = []
        
        try:
            # Use nmap for port scanning
            self.nm.scan(ip, arguments='-sS -O --host-timeout 10s')
            
            if ip in self.nm.all_hosts():
                for protocol in self.nm[ip].all_protocols():
                    ports = self.nm[ip][protocol].keys()
                    for port in ports:
                        if self.nm[ip][protocol][port]['state'] == 'open':
                            open_ports.append(port)
                            
        except Exception as e:
            logger.debug(f"Error scanning ports for {ip}: {e}")
            
        return open_ports
    
    def _detect_device_type(self, mac: str, ports: List[int], hostname: str) -> str:
        """Detect device type based on MAC, ports, and hostname"""
        if not mac:
            return "unknown"
        
        # Common device type indicators
        mac_vendors = {
            "00:50:56": "VMware",
            "00:0c:29": "VMware",
            "00:1c:42": "VMware",
            "08:00:27": "VirtualBox",
            "52:54:00": "QEMU",
            "00:16:3e": "Xen",
            "00:23:20": "Apple",
            "00:1b:63": "Apple",
            "28:cf:e9": "Apple",
            "b8:27:eb": "Raspberry Pi",
            "dc:a6:32": "Raspberry Pi",
        }
        
        # Check MAC vendor
        mac_prefix = mac[:8].upper()
        if mac_prefix in mac_vendors:
            return mac_vendors[mac_prefix]
        
        # Check based on open ports
        if 80 in ports or 443 in ports:
            return "Web Server"
        elif 22 in ports:
            return "SSH Server"
        elif 25 in ports:
            return "Mail Server"
        elif 53 in ports:
            return "DNS Server"
        
        # Check hostname patterns
        if hostname:
            hostname_lower = hostname.lower()
            if 'router' in hostname_lower or 'gateway' in hostname_lower:
                return "Router"
            elif 'switch' in hostname_lower:
                return "Switch"
            elif 'printer' in hostname_lower:
                return "Printer"
            elif 'camera' in hostname_lower:
                return "Camera"
        
        return "Computer"
    
    async def scan_network(self, network_range: str = None) -> NetworkScanResult:
        """Scan the network for devices"""
        if network_range is None:
            network_range = self._get_local_network_range()
        
        logger.info(f"Scanning network range: {network_range}")
        
        start_time = datetime.now()
        devices = []
        
        try:
            # Get network interfaces
            interfaces = await self.get_network_interfaces()
            
            # Calculate IP range
            import ipaddress
            network = ipaddress.IPv4Network(network_range, strict=False)
            
            # Create tasks for parallel scanning
            tasks = []
            for ip in network.hosts():
                task = self._scan_single_host(str(ip))
                tasks.append(task)
            
            # Execute scanning tasks
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out None results and exceptions
            devices = [device for device in results if isinstance(device, NetworkDevice)]
            
        except Exception as e:
            logger.error(f"Error during network scan: {e}")
            interfaces = []
        
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return NetworkScanResult(
            network_range=network_range,
            scan_time=scan_time,
            devices_found=len(devices),
            devices=devices,
            interfaces=interfaces
        )
    
    async def _scan_single_host(self, ip: str) -> Optional[NetworkDevice]:
        """Scan a single host for device information"""
        try:
            # First, check if host is alive
            is_alive = await self._ping_host(ip)
            if not is_alive:
                return None
            
            # Get device information
            mac_address = self._get_mac_address(ip)
            hostname = self._get_hostname(ip)
            
            # Scan ports (run in thread pool to avoid blocking)
            loop = asyncio.get_event_loop()
            open_ports = await loop.run_in_executor(
                self.executor, self._scan_ports, ip
            )
            
            # Detect device type
            device_type = self._detect_device_type(mac_address or "", open_ports, hostname or "")
            
            return NetworkDevice(
                ip_address=ip,
                mac_address=mac_address,
                hostname=hostname,
                device_type=device_type,
                vendor=None,  # Could be enhanced with MAC vendor lookup
                status="online",
                open_ports=open_ports,
                response_time=None  # Could be enhanced with ping timing
            )
            
        except Exception as e:
            logger.debug(f"Error scanning host {ip}: {e}")
            return None
    
    async def scan_specific_hosts(self, ip_addresses: List[str]) -> List[NetworkDevice]:
        """Scan specific IP addresses"""
        tasks = []
        for ip in ip_addresses:
            task = self._scan_single_host(ip)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [device for device in results if isinstance(device, NetworkDevice)]
    
    async def quick_scan(self) -> NetworkScanResult:
        """Perform a quick network scan (ping only)"""
        network_range = self._get_local_network_range()
        logger.info(f"Quick scanning network range: {network_range}")
        
        start_time = datetime.now()
        devices = []
        
        try:
            # Get network interfaces
            interfaces = await self.get_network_interfaces()
            
            # Calculate IP range
            import ipaddress
            network = ipaddress.IPv4Network(network_range, strict=False)
            
            # Create tasks for parallel ping scanning
            tasks = []
            for ip in network.hosts():
                task = self._quick_scan_host(str(ip))
                tasks.append(task)
            
            # Execute scanning tasks
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out None results and exceptions
            devices = [device for device in results if isinstance(device, NetworkDevice)]
            
        except Exception as e:
            logger.error(f"Error during quick scan: {e}")
            interfaces = []
        
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return NetworkScanResult(
            network_range=network_range,
            scan_time=scan_time,
            devices_found=len(devices),
            devices=devices,
            interfaces=interfaces
        )
    
    async def _quick_scan_host(self, ip: str) -> Optional[NetworkDevice]:
        """Quick scan of a single host (ping only)"""
        try:
            is_alive = await self._ping_host(ip)
            if not is_alive:
                return None
            
            # Get basic information
            hostname = self._get_hostname(ip)
            
            return NetworkDevice(
                ip_address=ip,
                mac_address=None,
                hostname=hostname,
                device_type="unknown",
                vendor=None,
                status="online",
                open_ports=[],
                response_time=None
            )
            
        except Exception as e:
            logger.debug(f"Error quick scanning host {ip}: {e}")
            return None


# Global network scanner instance
network_scanner = NetworkScanner()
