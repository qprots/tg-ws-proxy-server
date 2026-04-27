"""Proxy configuration management."""
from __future__ import annotations

import logging
import os
import random
import socket as _socket
import string
import threading
from dataclasses import dataclass, field
from typing import Dict, List
from urllib.request import Request, urlopen

from .balancer import balancer

log = logging.getLogger('tg-ws-proxy')

CFPROXY_DOMAINS_URL = (
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main"
    "/.github/cfproxy-domains.txt"
)

# Encoded default CF proxy domains (from upstream)
_CFPROXY_ENC: List[str] = ['virkgj.com', 'vmmzovy.com', 'mkuosckvso.com',
                            'zaewayzmplad.com', 'twdmbzcm.com']
_S = ''.join(chr(c) for c in (46, 99, 111, 46, 117, 107))


def _dd(s: str) -> str:
    """Decode CF proxy domain (from upstream)."""
    if not s[-4:] == '.com':
        return s
    p, n = s[:-4], sum(c.isalpha() for c in s[:-4])
    return ''.join(
        chr((ord(c) - (97 if c > '`' else 65) - n) % 26 +
            (97 if c > '`' else 65))
        if c.isalpha() else c for c in p
    ) + _S


CFPROXY_DEFAULT_DOMAINS: List[str] = [_dd(d) for d in _CFPROXY_ENC]


@dataclass
class ProxyConfig:
    """Central proxy configuration."""
    port: int = 10080
    host: str = '127.0.0.1'
    dc_redirects: Dict[int, str] = field(
        default_factory=lambda: {2: '149.154.167.220', 4: '149.154.167.220'})
    buffer_size: int = 256 * 1024
    pool_size: int = 4
    pool_max_age: float = 120.0
    # CF proxy settings
    fallback_cfproxy: bool = True
    fallback_cfproxy_priority: bool = True
    cfproxy_user_domain: str = ''
    # Cloudflare tunnel override (our addition for SOCKS5 mode)
    cf_domain: str = ''
    cf_ip: str = ''
    # Logging
    verbose: bool = False
    log_file: str = ''
    log_max_mb: float = 5
    log_backups: int = 0


proxy_config = ProxyConfig()


def _fetch_cfproxy_domain_list() -> List[str]:
    """Fetch CF proxy domain list from GitHub (from upstream)."""
    try:
        req = Request(
            CFPROXY_DOMAINS_URL + "?" +
            "".join(random.choices(string.ascii_letters, k=7)),
            headers={'User-Agent': 'tg-ws-proxy'})
        with urlopen(req, timeout=10) as resp:
            text = resp.read().decode('utf-8', errors='replace')
        encoded = [
            line.strip() for line in text.splitlines()
            if line.strip() and not line.startswith('#')
        ]
        return [_dd(d) for d in encoded]
    except Exception as exc:
        log.warning("Failed to fetch CF proxy domain list: %s", repr(exc))
        return []


def refresh_cfproxy_domains() -> None:
    """Refresh CF proxy domains from GitHub."""
    if proxy_config.cfproxy_user_domain:
        return

    fetched = _fetch_cfproxy_domain_list()

    if fetched:
        seen = set()
        pool = [d for d in fetched if not (d in seen or seen.add(d))]
        balancer.update_domains_list(pool)
        log.info("CF proxy domain pool updated from GitHub (%d domains)",
                 len(pool))


_refresh_stop: threading.Event = threading.Event()


def start_cfproxy_domain_refresh() -> None:
    """Start background thread for CF domain refresh (from upstream)."""
    global _refresh_stop
    _refresh_stop.set()
    _refresh_stop = threading.Event()
    stop = _refresh_stop

    balancer.update_domains_list(CFPROXY_DEFAULT_DOMAINS)

    def _loop():
        refresh_cfproxy_domains()
        while not stop.wait(timeout=3600):
            refresh_cfproxy_domains()

    threading.Thread(
        target=_loop, daemon=True,
        name='cfproxy-domains-refresh').start()


def parse_dc_ip_list(dc_ip_list: List[str]) -> Dict[int, str]:
    """Parse list of 'DC:IP' strings into {dc: ip} dict."""
    dc_redirects: Dict[int, str] = {}
    for entry in dc_ip_list:
        if ':' not in entry:
            raise ValueError(
                f"Invalid --dc-ip format {entry!r}, expected DC:IP")
        dc_s, ip_s = entry.split(':', 1)
        try:
            dc_n = int(dc_s)
            _socket.inet_aton(ip_s)
        except (ValueError, OSError):
            raise ValueError(f"Invalid --dc-ip {entry!r}")
        dc_redirects[dc_n] = ip_s
    return dc_redirects
