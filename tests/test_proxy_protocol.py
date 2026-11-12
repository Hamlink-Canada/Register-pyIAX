import pytest

from rpt_iax.config import load_settings
from rpt_iax.proxy_protocol import unwrap_datagram

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def test_unwrap_v2_udp_ipv4_datagram():
    header = bytes.fromhex("c6336414 c000020a 303912e9")
    payload = b"IAX payload"
    datagram = SIGNATURE + b"\x21\x12\x00\x0c" + header + payload

    assert unwrap_datagram(datagram) == (payload, ("198.51.100.20", 12345))


@pytest.mark.parametrize(
    "datagram",
    [
        b"not a proxy header",
        SIGNATURE + b"\x11\x12\x00\x0c" + bytes(12) + b"IAX",
        SIGNATURE + b"\x21\x11\x00\x0c" + bytes(12) + b"IAX",
        SIGNATURE + b"\x21\x12\x00\x0b" + bytes(12) + b"IAX",
        SIGNATURE + b"\x21\x12\x00\x0c" + bytes(11),
    ],
)
def test_unwrap_rejects_missing_or_unsupported_header(datagram):
    with pytest.raises(ValueError):
        unwrap_datagram(datagram)


def test_proxy_mode_is_disabled_by_default():
    settings = load_settings()

    assert settings.PROXY_PROTOCOL.ENABLED is False
    assert settings.PROXY_PROTOCOL.TRUSTED_PROXIES == []


def test_proxy_mode_requires_trusted_ipv4_networks():
    with pytest.raises(ValueError, match="trusted_proxies is required"):
        load_settings(proxy_protocol={"enabled": True})

    with pytest.raises(ValueError, match="must contain IPv4 CIDRs"):
        load_settings(proxy_protocol={"trusted_proxies": ["2001:db8::/32"]})
