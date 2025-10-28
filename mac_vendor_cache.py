#!/usr/bin/env python3
"""
MAC vendor cache utilities (object-oriented)
"""

import json
import logging
from typing import Optional

logger = logging.getLogger("mac_vendor_cache")

CACHE_PATH = "mac_vendor_cache.json"


class VendorCache:
    """
    VendorCache replaces the previous MacVendorCache class name.
    Holds MAC->vendor mappings and provides helper methods.
    """
    def __init__(self):
        self._cache = {}

    def add(self, mac, vendor):
        self._cache[mac] = vendor

    def get(self, mac):
        return self._cache.get(mac)

    def contains(self, mac):
        return mac in self._cache

    def to_dict(self):
        return dict(self._cache)

    def load_from_dict(self, d):
        self._cache = dict(d)


# Backwards compatibility alias for code still referencing the old class name
MacVendorCache = VendorCache

# Module-level instance for backwards compatibility with existing imports
cache = MacVendorCache()

# Backwards-compatible function wrappers (so existing imports keep working)
def add_vendor_to_cache(mac_address: str, vendor_name: str) -> None:
    return cache.add_vendor_to_cache(mac_address, vendor_name)


def get_vendor_from_cache(mac_address: str) -> Optional[str]:
    return cache.get_vendor_from_cache(mac_address)


def check_vendor_cache(mac_address: str) -> bool:
    return cache.check_vendor_cache(mac_address)


def initialize_mac_vendor_cache() -> None:
    return cache.initialize_mac_vendor_cache()


def write_vendor_cache_to_file() -> None:
    return cache.write_vendor_cache_to_file()