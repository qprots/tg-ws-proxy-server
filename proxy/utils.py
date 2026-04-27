"""Shared constants and utility functions."""
from __future__ import annotations

import socket as _socket
import struct
from typing import Dict, Optional, Tuple


# --- MTProto protocol constants ---

ZERO_64 = b'\x00' * 64
HANDSHAKE_LEN = 64
SKIP_LEN = 8
PREKEY_LEN = 32
KEY_LEN = 32
IV_LEN = 16
PROTO_TAG_POS = 56
DC_IDX_POS = 60

PROTO_ABRIDGED = 0xEFEFEFEF
PROTO_INTERMEDIATE = 0xEEEEEEEE
PROTO_PADDED_INTERMEDIATE = 0xDDDDDDDD
VALID_PROTOS = frozenset((PROTO_ABRIDGED, PROTO_INTERMEDIATE, PROTO_PADDED_INTERMEDIATE))

# --- Pre-compiled struct formats ---

st_BB = struct.Struct('>BB')
st_BBH = struct.Struct('>BBH')
st_BBQ = struct.Struct('>BBQ')
st_BB4s = struct.Struct('>BB4s')
st_BBH4s = struct.Struct('>BBH4s')
st_BBQ4s = struct.Struct('>BBQ4s')
st_H = struct.Struct('>H')
st_Q = struct.Struct('>Q')
st_I_net = struct.Struct('!I')
st_Ih = struct.Struct('<Ih')
st_I_le = struct.Struct('<I')

# --- Telegram IP ranges for SOCKS5 routing ---

_TG_RANGES = [
    # 185.76.151.0/24
    (struct.unpack('!I', _socket.inet_aton('185.76.151.0'))[0],
     struct.unpack('!I', _socket.inet_aton('185.76.151.255'))[0]),
    # 149.154.160.0/20
    (struct.unpack('!I', _socket.inet_aton('149.154.160.0'))[0],
     struct.unpack('!I', _socket.inet_aton('149.154.175.255'))[0]),
    # 91.105.192.0/23
    (struct.unpack('!I', _socket.inet_aton('91.105.192.0'))[0],
     struct.unpack('!I', _socket.inet_aton('91.105.193.255'))[0]),
    # 91.108.0.0/16
    (struct.unpack('!I', _socket.inet_aton('91.108.0.0'))[0],
     struct.unpack('!I', _socket.inet_aton('91.108.255.255'))[0]),
]

# IP -> (dc_id, is_media)
IP_TO_DC: Dict[str, Tuple[int, bool]] = {
    # DC1
    '149.154.175.50': (1, False), '149.154.175.51': (1, False),
    '149.154.175.53': (1, False), '149.154.175.54': (1, False),
    '149.154.175.52': (1, True),
    # DC2
    '149.154.167.41': (2, False), '149.154.167.50': (2, False),
    '149.154.167.51': (2, False), '149.154.167.220': (2, False),
    '149.154.167.99': (2, False),
    '95.161.76.100':  (2, False),
    '91.105.192.100': (2, False),
    '91.105.192.101': (2, False),
    '149.154.167.151': (2, True), '149.154.167.222': (2, True),
    '149.154.167.223': (2, True), '149.154.162.123': (2, True),
    '149.154.167.35':  (2, True),
    # DC3
    '149.154.175.100': (3, False), '149.154.175.101': (3, False),
    '149.154.175.102': (3, True),
    # DC4
    '149.154.167.91': (4, False), '149.154.167.92': (4, False),
    '149.154.164.250': (4, True), '149.154.166.120': (4, True),
    '149.154.166.121': (4, True), '149.154.167.118': (4, True),
    '149.154.165.111': (4, True),
    # DC5
    '91.108.56.100': (5, False), '91.108.56.101': (5, False),
    '91.108.56.116': (5, False), '91.108.56.126': (5, False),
    '91.108.56.134': (5, False),
    '149.154.171.5':  (5, False),
    '91.108.56.102': (5, True), '91.108.56.128': (5, True),
    '91.108.56.151': (5, True),
}

# Default IPs for DC fallback (from upstream)
DC_DEFAULT_IPS: Dict[int, str] = {
    1: '149.154.175.50',
    2: '149.154.167.51',
    3: '149.154.175.100',
    4: '149.154.167.91',
    5: '149.154.171.5',
    203: '91.105.192.100',
}

# Telegram IP subnets for iptables / routing reference
TG_SUBNETS = [
    '91.108.56.0/22',
    '91.108.4.0/22',
    '91.108.8.0/22',
    '91.108.16.0/22',
    '91.108.12.0/22',
    '149.154.160.0/20',
    '91.105.192.0/23',
    '91.108.20.0/22',
    '185.76.151.0/24',
]


def human_bytes(n: int) -> str:
    """Format byte count in human-readable form."""
    for unit in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024  # type: ignore
    return f"{n:.1f}TB"


def is_telegram_ip(ip: str) -> bool:
    """Check if an IP belongs to a known Telegram range."""
    try:
        n = st_I_net.unpack(_socket.inet_aton(ip))[0]
        return any(lo <= n <= hi for lo, hi in _TG_RANGES)
    except OSError:
        return False


def is_http_transport(data: bytes) -> bool:
    """Detect HTTP transport (POST/GET/HEAD/OPTIONS)."""
    return (data[:5] == b'POST ' or data[:4] == b'GET ' or
            data[:5] == b'HEAD ' or data[:8] == b'OPTIONS ')


def get_link_host(host: str) -> Optional[str]:
    """Resolve display host for links."""
    if host == '0.0.0.0':
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as _s:
                _s.connect(('8.8.8.8', 80))
                link_host = _s.getsockname()[0]
        except OSError:
            link_host = '127.0.0.1'
        return link_host
    else:
        return host
