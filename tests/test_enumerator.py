import pytest
import responses
import socket
from rapidrecon.enumerator import fetch_crtsh_subdomains, resolve_to_ips, enumerate_assets

# Sample JSON response from crt.sh
CRT_JSON = [
    {"name_value": "test.example.com"},
    {"name_value": "sub.test.example.com\nother.example.com"}
]

@responses.activate
def test_fetch_crtsh_subdomains(monkeypatch):
    domain = "example.com"
    # Mock the requests.get call
    responses.add(
        responses.GET,
        "https://crt.sh/",
        json=CRT_JSON,
        status=200
    )
    subs = fetch_crtsh_subdomains(domain)
    # Should include both 'test.example.com' and 'sub.test.example.com' and 'other.example.com'
    assert "test.example.com" in subs
    assert "sub.test.example.com" in subs
    assert "other.example.com" in subs
    # No duplicates
    assert len(subs) == len(set(subs))

def test_resolve_to_ips(monkeypatch):
    # Monkeypatch socket.getaddrinfo
    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "good.example.com":
            return [ (None, None, None, None, ("192.0.2.5", 0)) ]
        raise socket.gaierror
    monkeypatch.setattr(socket, 'getaddrinfo', fake_getaddrinfo)

    ips = resolve_to_ips(["good.example.com", "bad.example.com"])
    assert "192.0.2.5" in ips
    # bad.example.com should be skipped without exception
    assert isinstance(ips, list)

@responses.activate
def test_enumerate_assets_domain(monkeypatch, tmp_path):
    # Prepare config enabling crtsh, disabling others
    enum_cfg = {
        "sources": {"crtsh": True, "virustotal": False, "securitytrails": False},
        "api_keys": {},
        "whois": False
    }
    # Mock crt.sh response
    responses.add(
        responses.GET,
        "https://crt.sh/",
        json=CRT_JSON,
        status=200
    )
    # Patch resolve_to_ips to return fixed IPs
    monkeypatch.setattr(
        'rapidrecon.enumerator.resolve_to_ips',
        lambda hosts: ["198.51.100.1"]
    )
    result = enumerate_assets("example.com", enum_cfg)
    assert "subdomains" in result and "ips" in result
    # IP list should contain our fake IP
    assert result["ips"] == ["198.51.100.1"]

def test_enumerate_assets_ip_range():
    # If target is IP, should bypass enumeration
    enum_cfg = {"sources": {}, "api_keys": {}, "whois": False}
    result = enumerate_assets("192.0.2.0/24", enum_cfg)
    assert result["ips"] == ["192.0.2.0/24"]
    assert result["subdomains"] == []
