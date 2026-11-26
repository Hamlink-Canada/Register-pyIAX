"""Parser for PROXY protocol v2 datagrams carrying IAX over UDP/IPv4."""

from ipaddress import IPv4Address
from struct import unpack

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
V2_PROXY_UDP4 = (0x21, 0x12)  # PROXY command, INET address family, datagram transport.
ADDRESS_LENGTH = 12  # IPv4 source + destination addresses and UDP source + destination ports.


def unwrap_datagram(data):
    """Return (IAX payload, original IPv4 peer) or raise ValueError for invalid headers."""
    if len(data) < 16 + ADDRESS_LENGTH or data[:12] != SIGNATURE:
        raise ValueError("missing or truncated PROXY protocol header")
    version_command, family_protocol = data[12:14]
    if (version_command, family_protocol) != V2_PROXY_UDP4:
        raise ValueError("unsupported PROXY protocol command or address family")
    address_length = unpack("!H", data[14:16])[0]
    header_length = 16 + address_length
    if address_length < ADDRESS_LENGTH or header_length > len(data):
        raise ValueError("invalid PROXY protocol address length")

    source_ip = str(IPv4Address(data[16:20]))
    source_port = unpack("!H", data[24:26])[0]
    return data[header_length:], (source_ip, source_port)
