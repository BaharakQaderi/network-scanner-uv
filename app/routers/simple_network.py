from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Optional
import asyncio
import subprocess
import socket
import netifaces
from datetime import datetime
import json
import time

router = APIRouter()

class ScanRequest(BaseModel):
    network_range: Optional[str] = None
    max_concurrent: Optional[int] = 100
    timeout: Optional[float] = 1.0

class ScanResult(BaseModel):
    network_range: str
    scan_time: str
    scan_duration: float
    devices_found: int
    devices: List[Dict]
    gateway: Optional[str]


class SimpleNetworkScanner:
    """Simple network scanner for basic functionality"""
    
    def get_default_gateway(self) -> Optional[str]:
        """Get the default gateway IP address"""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
            if default_gateway:
                return default_gateway[0]
        except Exception:
            pass
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
                    
                    # Skip loopback
                    if ip.startswith('127.'):
                        continue
                    
                    # Check for private IP ranges
                    if (ip.startswith('192.168.') or 
                        ip.startswith('10.') or 
                        ip.startswith('172.')):
                        
                        # Calculate network address (simple approach)
                        parts = ip.split('.')
                        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0"
                        return f"{network}/24"
            
            # Fallback
            return "192.168.1.0/24"
        except Exception:
            return "192.168.1.0/24"
    
    async def ping_host(self, ip: str) -> bool:
        """Ping a host to check if it's alive"""
        try:
            process = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '1', ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
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
            result = subprocess.run(['arp', '-n', ip], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if ip in line and 'incomplete' not in line:
                        parts = line.split()
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
            
            # Determine device type
            device_type = "Unknown"
            if ip.endswith('.1'):
                device_type = "Gateway/Router"
            elif hostname:
                hostname_lower = hostname.lower()
                if 'router' in hostname_lower or 'gateway' in hostname_lower:
                    device_type = "Router"
                elif 'phone' in hostname_lower or 'mobile' in hostname_lower or 'iphone' in hostname_lower:
                    device_type = "Mobile Device"
                elif 'printer' in hostname_lower:
                    device_type = "Printer"
                elif 'pi' in hostname_lower or 'raspberry' in hostname_lower:
                    device_type = "Raspberry Pi"
                else:
                    device_type = "Computer"
            
            return {
                "ip_address": ip,
                "hostname": hostname,
                "mac_address": mac_address,
                "device_type": device_type,
                "status": "online"
            }
        except Exception:
            return None
    
    async def scan_network(self, network_range: str = None, max_concurrent: int = 100, timeout: float = 1.0) -> Dict:
        """Scan the network for devices with improved performance"""
        start_time = time.time()
        
        if network_range is None:
            network_range = self.get_local_network_range()
        
        # Parse network range
        try:
            network_part, cidr = network_range.split('/')
            network_parts = network_part.split('.')
            base_ip = '.'.join(network_parts[:3])
            
            # Create IP range (assuming /24)
            ip_range = [f"{base_ip}.{i}" for i in range(1, 255)]
            
        except Exception:
            return {
                "network_range": network_range,
                "scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "scan_duration": 0.0,
                "devices_found": 0,
                "devices": [],
                "gateway": None
            }
        
        # Use semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(ip):
            async with semaphore:
                return await self.scan_host(ip)
        
        # Scan hosts in parallel with controlled concurrency
        tasks = [scan_with_semaphore(ip) for ip in ip_range]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out None results and exceptions
        devices = [device for device in results if isinstance(device, dict)]
        
        scan_duration = time.time() - start_time
        
        return {
            "network_range": network_range,
            "scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "scan_duration": round(scan_duration, 2),
            "devices_found": len(devices),
            "devices": devices,
            "gateway": self.get_default_gateway()
        }
    
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
        except Exception:
            pass
        
        return interfaces


# Global scanner instance
scanner = SimpleNetworkScanner()


@router.get("/interfaces")
async def get_network_interfaces():
    """Get all network interfaces on this system"""
    try:
        interfaces = scanner.get_network_interfaces()
        return {"interfaces": interfaces}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan")
async def scan_network_post(scan_request: ScanRequest):
    """Scan the network for connected devices with custom parameters"""
    try:
        result = await scanner.scan_network(
            network_range=scan_request.network_range,
            max_concurrent=scan_request.max_concurrent,
            timeout=scan_request.timeout
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan")
async def scan_network_get(
    network_range: Optional[str] = None,
    max_concurrent: int = 100,
    quick: bool = False
):
    """Scan the network for connected devices"""
    try:
        # Adjust parameters for quick scan
        if quick:
            max_concurrent = 200
            timeout = 0.5
        else:
            timeout = 1.0
            
        result = await scanner.scan_network(
            network_range=network_range,
            max_concurrent=max_concurrent,
            timeout=timeout
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/gateway")
async def get_gateway_info():
    """Get information about the network gateway"""
    try:
        gateway_ip = scanner.get_default_gateway()
        if not gateway_ip:
            raise HTTPException(status_code=404, detail="Gateway not found")
        
        return {
            "gateway_ip": gateway_ip,
            "network_range": scanner.get_local_network_range()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_network_stats():
    """Get basic network statistics"""
    try:
        interfaces = scanner.get_network_interfaces()
        gateway = scanner.get_default_gateway()
        network_range = scanner.get_local_network_range()
        
        return {
            "interfaces_count": len(interfaces),
            "gateway": gateway,
            "network_range": network_range,
            "active_interfaces": [
                {
                    "name": iface["name"],
                    "ip": iface["ip_address"],
                    "netmask": iface["netmask"]
                }
                for iface in interfaces if iface["is_up"]
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
