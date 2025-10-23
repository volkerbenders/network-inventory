#!/usr/bin/env python3
"""
MAC vendor cache utilities (object-oriented)
"""

import json
import logging
from typing import Optional

logger = logging.getLogger("mac_vendor_cache")

CACHE_PATH = "mac_vendor_cache.json"


class MacVendorCache:
    """In-memory MAC vendor cache with persistence."""

    def __init__(self, path: str = CACHE_PATH):
        self._path = path
        self._cache: dict[str, str] = {}
        self.initialize()

    def initialize(self) -> None:
        """Load persisted cache from disk into memory."""
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self._cache.clear()
                    # ensure keys and values are strings
                    self._cache.update({str(k): str(v) for k, v in data.items()})
                    logger.debug(f"Loaded {len(self._cache)} cached vendors from {self._path}")
                else:
                    logger.debug(f"Cache file {self._path} does not contain a mapping; starting empty")
        except FileNotFoundError:
            logger.debug(f"MAC vendor cache file not found at {self._path}; starting with empty cache")
        except Exception as e:
            logger.error(f"Could not load MAC vendor cache from file {self._path}: {e}")

    def write_to_file(self) -> None:
        """Persist the in-memory cache to disk."""
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2, ensure_ascii=False)
                logger.debug(f"Wrote {len(self._cache)} cached vendors to {self._path}")
        except Exception as e:
            logger.error(f"Failed to write MAC vendor cache to file {self._path}: {e}")

    def add(self, mac_address: str, vendor_name: str) -> None:
        """Add or update a vendor for a given MAC address."""
        logger.debug(f"+ + + Caching vendor for {mac_address}: {vendor_name}")
        self._cache[str(mac_address)] = str(vendor_name)

    def get(self, mac_address: str) -> Optional[str]:
        """Retrieve a vendor from cache. Returns '<vendor> (cached)' or None."""
        logger.debug(f"- - - Retrieving vendor from cache for {mac_address}")
        vendor = self._cache.get(str(mac_address))
        return f"{vendor} (cached)" if vendor else None

    def has(self, mac_address: str) -> bool:
        """Check whether a MAC address exists in cache."""
        logger.debug(f". . . Checking vendor cache for {mac_address}")
        return str(mac_address) in self._cache

    # Convenience names matching previous procedural API
    def add_vendor_to_cache(self, mac_address: str, vendor_name: str) -> None:
        return self.add(mac_address, vendor_name)

    def get_vendor_from_cache(self, mac_address: str) -> Optional[str]:
        return self.get(mac_address)

    def check_vendor_cache(self, mac_address: str) -> bool:
        return self.has(mac_address)

    def initialize_mac_vendor_cache(self) -> None:
        return self.initialize()

    def write_vendor_cache_to_file(self) -> None:
        return self.write_to_file()


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