"""Tests for SKULL-NetRecon network utilities."""

import pytest
from skull_netrecon.utils.network import (
    expand_ip_range,
    validate_ip,
    validate_cidr,
    mac_to_vendor,
    get_local_ip,
    resolve_hostname,
)


class TestValidateIP:
    def test_valid_ipv4(self):
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("10.0.0.1") is True
        assert validate_ip("127.0.0.1") is True

    def test_invalid_ipv4(self):
        assert validate_ip("256.256.256.256") is False
        assert validate_ip("not-an-ip") is False
        assert validate_ip("") is False

    def test_cidr_not_valid_ip(self):
        assert validate_ip("192.168.1.0/24") is False


class TestValidateCIDR:
    def test_valid_cidr(self):
        assert validate_cidr("192.168.1.0/24") is True
        assert validate_cidr("10.0.0.0/8") is True
        assert validate_cidr("192.168.1.1/32") is True

    def test_invalid_cidr(self):
        assert validate_cidr("not-a-cidr") is False
        assert validate_cidr("192.168.1.0/33") is False


class TestExpandIPRange:
    def test_single_ip(self):
        assert expand_ip_range("192.168.1.1") == ["192.168.1.1"]

    def test_cidr_small(self):
        result = expand_ip_range("192.168.1.0/30")
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_range_notation(self):
        result = expand_ip_range("192.168.1.1-5")
        assert len(result) == 5
        assert result[0] == "192.168.1.1"
        assert result[-1] == "192.168.1.5"

    def test_range_full_notation(self):
        result = expand_ip_range("192.168.1.1-192.168.1.3")
        assert len(result) == 3
        assert result == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

    def test_invalid_input(self):
        assert expand_ip_range("invalid") == []


class TestMacToVendor:
    def test_known_mac(self):
        oui_db = {
            "00:0C:29": "VMware",
            "00:50:56": "VMware",
        }
        assert mac_to_vendor("00:0C:29:AB:CD:EF", oui_db) == "VMware"

    def test_unknown_mac(self):
        oui_db = {"00:0C:29": "VMware"}
        assert mac_to_vendor("FF:FF:FF:AA:BB:CC", oui_db) == "Unknown"

    def test_empty_mac(self):
        assert mac_to_vendor("", {}) is None

    def test_none_mac(self):
        assert mac_to_vendor(None, {}) is None

    def test_empty_db(self):
        assert mac_to_vendor("00:0C:29:AB:CD:EF", {}) == "Unknown"

    def test_dash_format(self):
        oui_db = {"00:0C:29": "VMware"}
        assert mac_to_vendor("00-0C-29-AB-CD-EF", oui_db) == "VMware"


class TestGetLocalIP:
    def test_returns_string(self):
        ip = get_local_ip()
        assert isinstance(ip, str)
        assert len(ip) > 0


class TestResolveHostname:
    def test_localhost(self):
        result = resolve_hostname("127.0.0.1")
        assert result is not None

    def test_invalid_ip(self):
        result = resolve_hostname("192.0.2.1")
        assert result is None
