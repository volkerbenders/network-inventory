#!/usr/bin/env python3
import json
import os

import pytest

from vendor_cache import VendorCache
import mac_vendor_cache as mvc


def test_initialize_loads_file(tmp_path):
    p = tmp_path / "cache.json"
    data = {"AA:BB:CC:DD:EE:FF": "TestVendor"}
    p.write_text(json.dumps(data), encoding="utf-8")

    cache = VendorCache()
    cache.initialize_mac_vendor_cache()
    assert cache.check_vendor_cache("AA:BB:CC:DD:EE:FF")
    assert cache.get_vendor_from_cache("AA:BB:CC:DD:EE:FF") == "TestVendor (cached)"


def test_add_get_has(tmp_path):
    p = tmp_path / "cache2.json"
    cache = VendorCache()
    cache.initialize_mac_vendor_cache()

    mac = "00:11:22:33:44:55"
    assert not cache.has(mac)

    cache.add(mac, "VendorX")
    assert cache.has(mac)
    assert cache.get(mac) == "VendorX (cached)"


def test_write_and_reload(tmp_path):
    p = tmp_path / "cache3.json"
    cache = VendorCache()
    cache.initialize_mac_vendor_cache()

    mac = "11:22:33:44:55:66"
    cache.add(mac, "VendorY")
    cache.write_to_file()

    # New instance should load persisted data
    cache2 = VendorCache()
    cache2.initialize_mac_vendor_cache()
    assert cache2.check_vendor_cache(mac)
    assert cache2.get_vendor_from_cache(mac) == "VendorY (cached)"


def test_module_wrappers_use_isolated_instance(tmp_path, monkeypatch):
    # Replace the module-level cache with an isolated one that uses a temp file
    isolated_path = str(tmp_path / "wrapper.json")
    isolated_cache = MacVendorCache(isolated_path)
    monkeypatch.setattr(mvc, "cache", isolated_cache)

    mvc.add_vendor_to_cache("aa:bb:cc", "WrapperVendor")
    assert mvc.check_vendor_cache("aa:bb:cc")
    assert mvc.get_vendor_from_cache("aa:bb:cc") == "WrapperVendor (cached)"

    mvc.write_vendor_cache_to_file()
    # Reinitialize (loads from disk)
    mvc.initialize_mac_vendor_cache()
    assert mvc.check_vendor_cache("aa:bb:cc")