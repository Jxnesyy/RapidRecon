import pytest
import nmap
import logging
from unittest.mock import MagicMock, patch
from rapidrecon.scanner import scan_host, scan_assets

class FakePortScanner:
    def __init__(self):
        # structure to hold fake scan results
        self._data = {
            '192.0.2.1': {
                'tcp': {
                    80: {'state': 'open', 'name': 'http', 'product': 'nginx', 'version': '1.18'},
                    22: {'state': 'closed', 'name': 'ssh', 'product': '', 'version': ''}
                }
            }
        }

    def scan(self, hosts, ports, arguments):
        # pretend we scanned and filled internal state
        self._last_hosts = hosts

    def all_hosts(self):
        return list(self._data.keys())

    def __getitem__(self, host):
        # Return structured data matching nmap.PortScanner API
        return { 'all_protocols': lambda: list(self._data[host].keys()),
                 host: self._data[host],
                 '__getitem__': lambda key: self._data[host] }

@pytest.fixture(autouse=True)
def patch_port_scanner(monkeypatch):
    # Patch nmap.PortScanner to return our fake scanner
    monkeypatch.setattr(nmap, 'PortScanner', lambda: FakePortScanner())


def test_scan_host():
    # Test direct scan_host output
    result = scan_host('192.0.2.1', ports='1-1024', args='-sS -Pn', timeout=5)
    assert result['host'] == '192.0.2.1'
    assert isinstance(result['ports'], list)
    # Should find port 80 open only
    ports = {p['port']: p for p in result['ports']}
    assert ports[80]['state'] == 'open'
    assert 'product' in ports[80]
    # Closed ports may or may not appear depending on lib; at least open.


def test_scan_assets(monkeypatch):
    assets = {'subdomains': ['example.com'], 'ips': ['192.0.2.1']}
    scan_cfg = {'nmap': {'ports': '80', 'args': '-sS -Pn'}, 'timeout': 5, 'max_concurrency': 2}

    # Patch scan_host to track calls
    called = []
    def fake_scan_host(host, ports, args, timeout):
        called.append(host)
        return {'host': host, 'ports': []}

    monkeypatch.setattr('rapidrecon.scanner.scan_host', fake_scan_host)

    results = scan_assets(assets, scan_cfg)
    # scan_host should be invoked for both example.com and 192.0.2.1
    assert set(called) == set(['example.com', '192.0.2.1'])
    assert isinstance(results, list)
    assert all('host' in entry for entry in results)
