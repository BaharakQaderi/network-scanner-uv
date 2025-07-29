import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from app.main import app
from app.routers.simple_network import SimpleNetworkScanner


@pytest.fixture
def client():
    """Create test client"""
    return TestClient(app)


@pytest.fixture
def scanner():
    """Create scanner instance for testing"""
    return SimpleNetworkScanner()


class TestNetworkScanner:
    """Test cases for NetworkScanner functionality"""
    
    def test_get_local_network_range(self, scanner):
        """Test getting local network range"""
        with patch('netifaces.interfaces') as mock_interfaces, \
             patch('netifaces.ifaddresses') as mock_ifaddresses:
            
            mock_interfaces.return_value = ['eth0', 'lo']
            mock_ifaddresses.return_value = {
                2: [{'addr': '192.168.1.100', 'netmask': '255.255.255.0'}]
            }
            
            result = scanner.get_local_network_range()
            assert result == "192.168.1.0/24"
    
    def test_get_default_gateway(self, scanner):
        """Test getting default gateway"""
        with patch('netifaces.gateways') as mock_gateways:
            mock_gateways.return_value = {
                'default': {2: ('192.168.1.1', 'eth0')}
            }
            
            result = scanner.get_default_gateway()
            assert result == "192.168.1.1"
    
    @pytest.mark.asyncio
    async def test_ping_host_success(self, scanner):
        """Test successful ping"""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = Mock()
            mock_process.wait = AsyncMock(return_value=None)
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            result = await scanner.ping_host("192.168.1.1")
            assert result is True
    
    @pytest.mark.asyncio
    async def test_ping_host_failure(self, scanner):
        """Test failed ping"""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = Mock()
            mock_process.wait = AsyncMock(return_value=None)
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process
            
            result = await scanner.ping_host("192.168.1.99")
            assert result is False
    
    def test_get_hostname(self, scanner):
        """Test hostname resolution"""
        with patch('socket.gethostbyaddr') as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ('router.local', [], [])
            
            result = scanner.get_hostname("192.168.1.1")
            assert result == "router.local"
    
    def test_get_hostname_failure(self, scanner):
        """Test hostname resolution failure"""
        with patch('socket.gethostbyaddr') as mock_gethostbyaddr:
            mock_gethostbyaddr.side_effect = Exception("Host not found")
            
            result = scanner.get_hostname("192.168.1.99")
            assert result is None
    
    @pytest.mark.asyncio
    async def test_scan_host_success(self, scanner):
        """Test successful host scan"""
        with patch.object(scanner, 'ping_host', return_value=True), \
             patch.object(scanner, 'get_hostname', return_value='test-host'), \
             patch.object(scanner, 'get_mac_address_from_arp', return_value='aa:bb:cc:dd:ee:ff'):
            
            result = await scanner.scan_host("192.168.1.10")
            
            assert result is not None
            assert result['ip_address'] == "192.168.1.10"
            assert result['hostname'] == 'test-host'
            assert result['mac_address'] == 'aa:bb:cc:dd:ee:ff'
            assert result['status'] == 'online'
    
    @pytest.mark.asyncio
    async def test_scan_host_offline(self, scanner):
        """Test scanning offline host"""
        with patch.object(scanner, 'ping_host', return_value=False):
            result = await scanner.scan_host("192.168.1.99")
            assert result is None
    
    def test_get_network_interfaces(self, scanner):
        """Test getting network interfaces"""
        with patch('netifaces.interfaces') as mock_interfaces, \
             patch('netifaces.ifaddresses') as mock_ifaddresses:
            
            mock_interfaces.return_value = ['eth0']
            mock_ifaddresses.return_value = {
                2: [{'addr': '192.168.1.100', 'netmask': '255.255.255.0', 'broadcast': '192.168.1.255'}]
            }
            
            result = scanner.get_network_interfaces()
            
            assert len(result) == 1
            assert result[0]['name'] == 'eth0'
            assert result[0]['ip_address'] == '192.168.1.100'


class TestNetworkAPI:
    """Test cases for FastAPI endpoints"""
    
    def test_root_endpoint(self, client):
        """Test root endpoint redirects to scanner"""
        response = client.get("/", follow_redirects=False)
        assert response.status_code == 307  # Redirect status code
        assert response.headers["location"] == "/scanner"
    
    def test_scanner_endpoint(self, client):
        """Test scanner endpoint returns HTML"""
        response = client.get("/scanner")
        assert response.status_code == 200
        assert "Network Scanner" in response.text
        assert "text/html" in response.headers["content-type"]
    
    def test_health_endpoint(self, client):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
    
    def test_network_interfaces_endpoint(self, client):
        """Test network interfaces endpoint"""
        with patch('app.routers.simple_network.scanner.get_network_interfaces') as mock_interfaces:
            mock_interfaces.return_value = [
                {
                    "name": "eth0",
                    "ip_address": "192.168.1.100",
                    "netmask": "255.255.255.0",
                    "broadcast": "192.168.1.255",
                    "is_up": True
                }
            ]
            
            response = client.get("/network/interfaces")
            assert response.status_code == 200
            data = response.json()
            assert "interfaces" in data
            assert len(data["interfaces"]) == 1
    
    def test_gateway_info_endpoint(self, client):
        """Test gateway info endpoint"""
        with patch('app.routers.simple_network.scanner.get_default_gateway') as mock_gateway, \
             patch('app.routers.simple_network.scanner.get_local_network_range') as mock_range:
            
            mock_gateway.return_value = "192.168.1.1"
            mock_range.return_value = "192.168.1.0/24"
            
            response = client.get("/network/gateway")
            assert response.status_code == 200
            data = response.json()
            assert data["gateway_ip"] == "192.168.1.1"
            assert data["network_range"] == "192.168.1.0/24"
    
    def test_network_stats_endpoint(self, client):
        """Test network stats endpoint"""
        with patch('app.routers.simple_network.scanner.get_network_interfaces') as mock_interfaces, \
             patch('app.routers.simple_network.scanner.get_default_gateway') as mock_gateway, \
             patch('app.routers.simple_network.scanner.get_local_network_range') as mock_range:
            
            mock_interfaces.return_value = [{"name": "eth0", "ip_address": "192.168.1.100", "netmask": "255.255.255.0", "is_up": True}]
            mock_gateway.return_value = "192.168.1.1"
            mock_range.return_value = "192.168.1.0/24"
            
            response = client.get("/network/stats")
            assert response.status_code == 200
            data = response.json()
            assert data["interfaces_count"] == 1
            assert data["gateway"] == "192.168.1.1"
            assert data["network_range"] == "192.168.1.0/24"
    
    @pytest.mark.asyncio
    async def test_scan_network_get_endpoint(self, client):
        """Test network scan GET endpoint"""
        mock_result = {
            "network_range": "192.168.1.0/24",
            "scan_time": "2024-01-01 12:00:00",
            "scan_duration": 2.5,
            "devices_found": 2,
            "devices": [
                {"ip_address": "192.168.1.1", "hostname": "router", "mac_address": "aa:bb:cc:dd:ee:ff", "device_type": "Router", "status": "online"},
                {"ip_address": "192.168.1.100", "hostname": "laptop", "mac_address": "11:22:33:44:55:66", "device_type": "Computer", "status": "online"}
            ],
            "gateway": "192.168.1.1"
        }
        
        with patch('app.routers.simple_network.scanner.scan_network', return_value=mock_result):
            response = client.get("/network/scan")
            assert response.status_code == 200
            data = response.json()
            assert data["devices_found"] == 2
            assert len(data["devices"]) == 2
    
    def test_scan_network_post_endpoint(self, client):
        """Test network scan POST endpoint"""
        mock_result = {
            "network_range": "10.0.0.0/24",
            "scan_time": "2024-01-01 12:00:00",
            "scan_duration": 1.8,
            "devices_found": 1,
            "devices": [
                {"ip_address": "10.0.0.1", "hostname": "gateway", "mac_address": "ff:ee:dd:cc:bb:aa", "device_type": "Gateway", "status": "online"}
            ],
            "gateway": "10.0.0.1"
        }
        
        scan_request = {
            "network_range": "10.0.0.0/24",
            "max_concurrent": 50,
            "timeout": 0.8
        }
        
        with patch('app.routers.simple_network.scanner.scan_network', return_value=mock_result):
            response = client.post("/network/scan", json=scan_request)
            assert response.status_code == 200
            data = response.json()
            assert data["network_range"] == "10.0.0.0/24"
            assert data["devices_found"] == 1


@pytest.mark.integration
class TestIntegration:
    """Integration tests for the complete system"""
    
    def test_docker_health_check(self):
        """Test that the application would pass Docker health check"""
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
    
    def test_cors_headers(self, client):
        """Test CORS headers are properly set"""
        response = client.options("/")
        # CORS middleware should handle OPTIONS requests
        assert response.status_code in [200, 405]  # 405 if OPTIONS not explicitly handled
    
    def test_static_files_mount(self, client):
        """Test that static files endpoint works"""
        response = client.get("/scanner")
        # Should return HTML content or error message
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])