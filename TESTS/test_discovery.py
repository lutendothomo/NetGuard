import pytest
from unittest.mock import patch, MagicMock
from netguard.core.discovery import (
    _normalize_mac,
    _vendor,
    _arp_table,
    _is_alive,
    discover_hosts,
    PROBE_PORTS,
    OUI_VENDORS,
)


def test_mac_normalization():
    assert _normalize_mac("00-0c-29-11-22-33") == "00:0C:29:11:22:33"
    assert _normalize_mac("b8:27:eb:01:02:03") == "B8:27:EB:01:02:03"
    assert _normalize_mac("000c.2911.2233") == "00:0C:29:11:22:33"
    assert _normalize_mac("000c29112233") == "00:0C:29:11:22:33"
    assert _normalize_mac("invalid_mac") is None
    assert _normalize_mac("") is None
    assert _normalize_mac(None) is None


def test_vendor_resolution():
    assert _vendor("00:0C:29:11:22:33") == "VMware"
    assert _vendor("00-0c-29-11-22-33") == "VMware"
    assert _vendor("b8-27-eb-aa-bb-cc") == "Raspberry Pi"
    assert _vendor("00:15:5d:00:11:22") == "Microsoft Hyper-V"
    assert _vendor("11:22:33:44:55:66") == "Unknown"
    assert _vendor(None) is None


def test_arp_table_parsing_proc_net_arp():
    from unittest.mock import mock_open
    sample_proc = (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.1      0x1         0x2         00:50:56:c0:00:08     *        eth0\n"
        "192.168.1.5      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
    )
    with patch("builtins.open", mock_open(read_data=sample_proc)):
        table = _arp_table()
        assert table.get("192.168.1.1") == "00:50:56:C0:00:08"
        assert "192.168.1.5" not in table




def test_arp_table_fallback_command(monkeypatch):
    # Simulate non-Linux where /proc/net/arp fails
    def mock_open(*args, **kwargs):
        raise OSError("File not found")

    mock_run = MagicMock()
    mock_run.return_value.stdout = (
        "Interface: 192.168.1.100 --- 0x2\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.1.1           00-0c-29-33-44-55     dynamic\n"
        "  224.0.0.22            01-00-5e-00-00-16     static\n"
        "  255.255.255.255       ff-ff-ff-ff-ff-ff     static\n"
    )

    with patch("builtins.open", mock_open), patch("subprocess.run", mock_run):
        table = _arp_table()
        assert table.get("192.168.1.1") == "00:0C:29:33:44:55"
        assert "224.0.0.22" not in table
        assert "255.255.255.255" not in table


def test_discover_hosts_loopback():
    hosts = discover_hosts("127.0.0.0/30")
    ips = [h["ip"] for h in hosts]
    assert "127.0.0.1" in ips


def test_discover_hosts_single_ip_and_31():
    # /32 single host
    single = discover_hosts("127.0.0.1/32")
    assert len(single) >= 1
    assert single[0]["ip"] == "127.0.0.1"

    # /31 point-to-point network
    ptp = discover_hosts("127.0.0.0/31")
    assert len(ptp) >= 1
