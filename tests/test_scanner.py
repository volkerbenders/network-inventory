"""Specifications/tests for the NetworkScanner class."""

import pytest
from network_inventory.scanner import NetworkScanner


class TestNetworkScanner:
    """Specifications for the NetworkScanner class."""

    def test_scanner_can_be_instantiated(self):
        """A NetworkScanner object can be created."""
        scanner = NetworkScanner()
        assert scanner is not None

    def test_scanner_accepts_network_range(self):
        """A NetworkScanner can be initialized with a network range."""
        network_range = "192.168.1.0/24"
        scanner = NetworkScanner(network_range=network_range)
        assert scanner.network_range == network_range

    def test_scan_returns_list(self):
        """The scan method returns a list."""
        scanner = NetworkScanner()
        result = scanner.scan()
        assert isinstance(result, list)

    def test_scan_returns_empty_list_initially(self):
        """The scan method returns an empty list when no devices are found."""
        scanner = NetworkScanner()
        result = scanner.scan()
        assert result == []
