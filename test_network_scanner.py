# python
#!/usr/bin/env python3
import socket
import json
import pytest

# Absolute import of functions and module under test
from network_scanner import (
    get_mac_details,
    add_vendor_to_cache,
    check_vendor_cache,
    get_vendor_from_cache,
    get_hostname,
    get_default_network_range,
    print_results,
    vendor_cache,
)
import network_scanner as ns


class DummyResp:
    def __init__(self, status_code, content=b""):
        self.status_code = status_code
        self.content = content


def setup_function(function):
    # Ensure global vendor_cache is cleared between tests
    vendor_cache.clear()


def test_get_mac_details_200_response(monkeypatch):
    mac = "AA:BB:CC:DD:EE:FF"

    def fake_get(url):
        assert url.endswith(mac)
        return DummyResp(200, b"TestVendor")

    monkeypatch.setattr(ns.requests, "get", fake_get)
    result = get_mac_details(mac)
    assert result == "TestVendor"
    assert check_vendor_cache(mac)
    assert get_vendor_from_cache(mac) == "TestVendor (cached)"


def test_get_mac_details_404_response(monkeypatch):
    mac = "00:11:22:33:44:55"

    monkeypatch.setattr(ns.requests, "get", lambda url: DummyResp(404, b""))
    result = get_mac_details(mac)
    assert result == f"Unknown Vendor {mac}"


def test_get_mac_details_other_status(monkeypatch):
    mac = "11:22:33:44:55:66"

    monkeypatch.setattr(ns.requests, "get", lambda url: DummyResp(500, b""))
    result = get_mac_details(mac)
    assert "Invalid MAC" in result and "500" in result


def test_get_mac_details_uses_cache_and_does_not_call_requests(monkeypatch):
    mac = "DE:AD:BE:EF:00:01"
    add_vendor_to_cache(mac, "CachedVendor")

    def bad_get(url):
        raise AssertionError(
            "requests.get should not be called when cache has the vendor")

    monkeypatch.setattr(ns.requests, "get", bad_get)
    result = get_mac_details(mac)
    assert result == "CachedVendor (cached)"


def test_get_hostname_success_and_failure(monkeypatch):
    ip = "192.0.2.1"

    # success
    monkeypatch.setattr(ns.socket, "gethostbyaddr",
                        lambda ipaddr: ("host.example.com", [], []))
    assert get_hostname(ip) == "host.example.com"

    # failure -> socket.herror
    def raise_herror(ipaddr):
        raise ns.socket.herror

    monkeypatch.setattr(ns.socket, "gethostbyaddr", raise_herror)
    assert get_hostname(ip) == "N/A"


def test_get_default_network_range_handles_socket_failure(monkeypatch):
    # Stub socket.socket to produce an object whose connect raises
    class BadSocket:
        def __init__(self, *args, **kwargs):
            pass

        def connect(self, target):
            raise Exception("network unreachable")

        def getsockname(self):
            return ("0.0.0.0", 0)

        def close(self):
            pass

    monkeypatch.setattr(ns.socket, "socket", BadSocket)
    assert get_default_network_range() is None


def test_print_results_outputs_table_and_counts(capsys):
    # No devices
    print_results([])
    out = capsys.readouterr().out
    assert "No devices found" in out

    # One device -> table + total count
    devices = [
        {
            "mac": "AA:BB:CC:DD:EE:FF",
            "ip": "192.168.1.10",
            "hostname": "host.local",
            "vendor": "TestVendor"
        }
    ]
    print_results(devices)
    out = capsys.readouterr().out
    assert "MAC Address" in out
    assert "IPv4 Address" in out
    assert "Vendor" in out
    assert "Total devices found: 1" in out
