from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from app.models import NetworkDevice, NetworkScanResult, NetworkInterface
from app.network_scanner import network_scanner

router = APIRouter()


@router.get("/interfaces", response_model=List[NetworkInterface])
async def get_network_interfaces():
    """Get all network interfaces on this system"""
    try:
        interfaces = await network_scanner.get_network_interfaces()
        return interfaces
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan", response_model=NetworkScanResult)
async def scan_network(
    network_range: Optional[str] = Query(None, description="Network range to scan (e.g., 192.168.1.0/24)"),
    quick: bool = Query(False, description="Perform quick scan (ping only)")
):
    """Scan the network for connected devices"""
    try:
        if quick:
            result = await network_scanner.quick_scan()
        else:
            result = await network_scanner.scan_network(network_range)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan/quick", response_model=NetworkScanResult)
async def quick_scan_network():
    """Perform a quick network scan (ping only) - faster but less detailed"""
    try:
        result = await network_scanner.quick_scan()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/hosts", response_model=List[NetworkDevice])
async def scan_specific_hosts(ip_addresses: List[str]):
    """Scan specific IP addresses for device information"""
    try:
        if not ip_addresses:
            raise HTTPException(status_code=400, detail="No IP addresses provided")
        
        devices = await network_scanner.scan_specific_hosts(ip_addresses)
        return devices
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/device/{ip_address}", response_model=NetworkDevice)
async def get_device_info(ip_address: str):
    """Get detailed information about a specific device"""
    try:
        devices = await network_scanner.scan_specific_hosts([ip_address])
        
        if not devices:
            raise HTTPException(
                status_code=404, 
                detail=f"Device at {ip_address} not found or not responding"
            )
        
        return devices[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/gateway")
async def get_gateway_info():
    """Get information about the network gateway"""
    try:
        gateway_ip = network_scanner._get_default_gateway()
        if not gateway_ip:
            raise HTTPException(status_code=404, detail="Gateway not found")
        
        devices = await network_scanner.scan_specific_hosts([gateway_ip])
        
        if not devices:
            # Return basic gateway info even if detailed scan fails
            return {
                "ip_address": gateway_ip,
                "device_type": "Gateway/Router",
                "status": "online",
                "hostname": None,
                "mac_address": None
            }
        
        return devices[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_network_stats():
    """Get basic network statistics"""
    try:
        # Get interfaces
        interfaces = await network_scanner.get_network_interfaces()
        
        # Get gateway
        gateway = network_scanner._get_default_gateway()
        
        # Get network range
        network_range = network_scanner._get_local_network_range()
        
        return {
            "interfaces_count": len(interfaces),
            "gateway": gateway,
            "network_range": network_range,
            "active_interfaces": [
                {
                    "name": iface.name,
                    "ip": iface.ip_address,
                    "netmask": iface.netmask
                }
                for iface in interfaces if iface.is_up
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
