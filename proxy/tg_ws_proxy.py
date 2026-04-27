"""
Telegram WS Bridge Proxy — SOCKS5 front-end.

Accepts SOCKS5 connections, detects Telegram traffic by destination IP,
extracts DC from MTProto init, and bridges through WebSocket to Telegram DCs.
Non-Telegram traffic is passed through transparently.

Based on Flowseal/tg-ws-proxy with SOCKS5 interface instead of MTProto proxy.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import logging.handlers
import os
import socket as _socket
import struct
import sys
import time
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

# Allow running as `python proxy/tg_ws_proxy.py` (e.g. from Docker)
if __name__ == '__main__' and (__package__ is None or __package__ == ''):
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)
    __package__ = 'proxy'

from .utils import (
    PROTO_INTERMEDIATE, VALID_PROTOS,
    IP_TO_DC, human_bytes, is_telegram_ip, is_http_transport,
    st_H,
)
from .stats import stats
from .config import (
    proxy_config, parse_dc_ip_list,
    start_cfproxy_domain_refresh,
)
from .bridge import (
    dc_from_init, patch_init_dc, MsgSplitter,
    bridge_ws, pipe, do_fallback,
)
from .raw_websocket import RawWebSocket, WsHandshakeError, set_sock_opts

log = logging.getLogger('tg-ws-proxy')

# DCs where WS is known to fail (302 redirect)
# Raw TCP fallback will be used instead
# Keyed by (dc, is_media)
_ws_blacklist: Set[Tuple[int, bool]] = set()

# Rate-limit re-attempts per (dc, is_media)
_dc_fail_until: Dict[Tuple[int, bool], float] = {}
_DC_FAIL_COOLDOWN = 30.0   # seconds to keep reduced WS timeout after failure
_WS_FAIL_TIMEOUT = 2.0     # quick-retry timeout after a recent WS failure

_SOCKS5_REPLIES = {s: bytes([0x05, s, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                   for s in (0x00, 0x05, 0x07, 0x08)}


def _socks5_reply(status):
    return _SOCKS5_REPLIES[status]


def _ws_domains(dc: int, is_media) -> List[str]:
    """Generate WS domain list for a DC, handling DC 203 -> 2 override."""
    if dc == 203:
        dc = 2
    if is_media is None or is_media:
        return [f'kws{dc}-1.web.telegram.org', f'kws{dc}.web.telegram.org']
    return [f'kws{dc}.web.telegram.org', f'kws{dc}-1.web.telegram.org']


# --- WS Connection Pool (upgraded from upstream: deque, is_closing check, reset) ---

class _WsPool:
    def __init__(self):
        self._idle: Dict[Tuple[int, bool], deque] = {}
        self._refilling: Set[Tuple[int, bool]] = set()

    async def get(self, dc: int, is_media: bool,
                  target_ip: str, domains: List[str]
                  ) -> Optional[RawWebSocket]:
        key = (dc, is_media)
        now = time.monotonic()

        bucket = self._idle.get(key)
        if bucket is None:
            bucket = deque()
            self._idle[key] = bucket
        while bucket:
            ws, created = bucket.popleft()
            age = now - created
            if (age > proxy_config.pool_max_age or ws._closed
                    or ws.writer.transport.is_closing()):
                asyncio.create_task(self._quiet_close(ws))
                continue
            stats.pool_hits += 1
            log.debug("WS pool hit for DC%d%s (age=%.1fs, left=%d)",
                      dc, 'm' if is_media else '', age, len(bucket))
            self._schedule_refill(key, target_ip, domains)
            return ws

        stats.pool_misses += 1
        self._schedule_refill(key, target_ip, domains)
        return None

    def _schedule_refill(self, key, target_ip, domains):
        if key in self._refilling:
            return
        self._refilling.add(key)
        asyncio.create_task(self._refill(key, target_ip, domains))

    async def _refill(self, key, target_ip, domains):
        dc, is_media = key
        try:
            bucket = self._idle.setdefault(key, deque())
            needed = proxy_config.pool_size - len(bucket)
            if needed <= 0:
                return
            tasks = [asyncio.create_task(
                self._connect_one(target_ip, domains))
                for _ in range(needed)]
            for t in tasks:
                try:
                    ws = await t
                    if ws:
                        bucket.append((ws, time.monotonic()))
                except Exception:
                    pass
            log.debug("WS pool refilled DC%d%s: %d ready",
                      dc, 'm' if is_media else '', len(bucket))
        finally:
            self._refilling.discard(key)

    @staticmethod
    async def _connect_one(target_ip, domains) -> Optional[RawWebSocket]:
        for domain in domains:
            try:
                return await RawWebSocket.connect(
                    target_ip, domain, timeout=8)
            except WsHandshakeError as exc:
                if exc.is_redirect:
                    continue
                return None
            except Exception:
                return None
        return None

    @staticmethod
    async def _quiet_close(ws):
        try:
            await ws.close()
        except Exception:
            pass

    async def warmup(self, dc_opt: Dict[int, str]):
        """Pre-fill pool for all configured DCs on startup."""
        for dc, target_ip in dc_opt.items():
            if target_ip is None:
                continue
            for is_media in (False, True):
                domains = _ws_domains(dc, is_media)
                key = (dc, is_media)
                self._schedule_refill(key, target_ip, domains)
        log.info("WS pool warmup started for %d DC(s)", len(dc_opt))

    def reset(self):
        """Clear all pooled connections (from upstream)."""
        self._idle.clear()
        self._refilling.clear()


_ws_pool = _WsPool()
_client_tasks: Set[asyncio.Task] = set()


# --- SOCKS5 Client Handler ---

async def _handle_client(reader, writer):
    stats.connections_total += 1
    stats.connections_active += 1
    peer = writer.get_extra_info('peername')
    label = f"{peer[0]}:{peer[1]}" if peer else "?"

    set_sock_opts(writer.transport)

    try:
        # -- SOCKS5 greeting --
        hdr = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        if hdr[0] != 5:
            log.debug("[%s] not SOCKS5 (ver=%d)", label, hdr[0])
            writer.close()
            return
        nmethods = hdr[1]
        await reader.readexactly(nmethods)
        writer.write(b'\x05\x00')  # no-auth
        await writer.drain()

        # -- SOCKS5 CONNECT request --
        req = await asyncio.wait_for(reader.readexactly(4), timeout=10)
        _ver, cmd, _rsv, atyp = req
        if cmd != 1:
            writer.write(_socks5_reply(0x07))
            await writer.drain()
            writer.close()
            return

        if atyp == 1:  # IPv4
            raw = await reader.readexactly(4)
            dst = _socket.inet_ntoa(raw)
        elif atyp == 3:  # domain
            dlen = (await reader.readexactly(1))[0]
            dst = (await reader.readexactly(dlen)).decode()
        elif atyp == 4:  # IPv6
            raw = await reader.readexactly(16)
            dst = _socket.inet_ntop(_socket.AF_INET6, raw)
        else:
            writer.write(_socks5_reply(0x08))
            await writer.drain()
            writer.close()
            return

        port = st_H.unpack(await reader.readexactly(2))[0]

        if ':' in dst:
            log.error(
                "[%s] IPv6 address detected: %s:%d — "
                "IPv6 addresses are not supported; "
                "disable IPv6 to continue using the proxy.",
                label, dst, port)
            writer.write(_socks5_reply(0x05))
            await writer.drain()
            writer.close()
            return

        # -- Non-Telegram IP -> direct passthrough --
        if not is_telegram_ip(dst):
            stats.connections_passthrough += 1
            log.debug("[%s] passthrough -> %s:%d", label, dst, port)
            try:
                rr, rw = await asyncio.wait_for(
                    asyncio.open_connection(dst, port), timeout=10)
            except Exception as exc:
                log.warning("[%s] passthrough failed to %s: %s: %s",
                            label, dst, type(exc).__name__,
                            str(exc) or "(no message)")
                writer.write(_socks5_reply(0x05))
                await writer.drain()
                writer.close()
                return

            writer.write(_socks5_reply(0x00))
            await writer.drain()

            tasks = [asyncio.create_task(pipe(reader, rw)),
                     asyncio.create_task(pipe(rr, writer))]
            await asyncio.wait(tasks,
                               return_when=asyncio.FIRST_COMPLETED)
            for t in tasks:
                t.cancel()
            for t in tasks:
                try:
                    await t
                except BaseException:
                    pass
            return

        # -- Telegram DC: accept SOCKS, read init --
        writer.write(_socks5_reply(0x00))
        await writer.drain()

        try:
            init = await asyncio.wait_for(
                reader.readexactly(64), timeout=15)
        except asyncio.IncompleteReadError:
            log.debug("[%s] client disconnected before init", label)
            return

        # HTTP transport -> reject
        if is_http_transport(init):
            stats.connections_http_rejected += 1
            log.debug("[%s] HTTP transport to %s:%d (rejected)",
                      label, dst, port)
            writer.close()
            return

        # -- Extract DC ID --
        dc, is_media, proto = dc_from_init(init)
        dc_opt = proxy_config.dc_redirects

        init_patched = False
        # Android (may be iOS too) with useSecret=0 has random dc_id bytes
        if dc is None:
            if dst in IP_TO_DC:
                dc, is_media = IP_TO_DC.get(dst)
            else:
                # Dynamic fallback for unknown IPs
                if dst.startswith('149.154.175.'):
                    dc, is_media = 1, True
                elif dst.startswith('149.154.167.'):
                    dc, is_media = 2, True
                elif dst.startswith('91.108.56.'):
                    dc, is_media = 5, True
                elif dst.startswith('149.154.164.') or dst.startswith('149.154.166.'):
                    dc, is_media = 4, True
                elif dst.startswith('149.154.'):
                    dc, is_media = 4, True
                else:
                    dc, is_media = 2, True  # Safe global default

            if dc in dc_opt:
                init = patch_init_dc(init, -dc if is_media else dc)
                init_patched = True

        if dc is None or dc not in dc_opt:
            log.warning("[%s] unknown DC%s for %s:%d -> TCP passthrough",
                        label, dc, dst, port)
            from .bridge import tcp_fallback
            await tcp_fallback(reader, writer, dst, port, init, label)
            return

        dc_key = (dc, is_media if is_media is not None else True)
        now = time.monotonic()
        media_tag = (" media" if is_media
                     else (" media?" if is_media is None else ""))

        # -- WS blacklist check --
        if dc_key in _ws_blacklist:
            log.debug("[%s] DC%d%s WS blacklisted -> TCP %s:%d",
                      label, dc, media_tag, dst, port)
            splitter = None
            if proto is not None:
                try:
                    splitter = MsgSplitter(init, proto)
                except Exception:
                    pass
            ok = await do_fallback(
                reader, writer, init, label,
                dc=dc, dst=dst, port=port,
                is_media=is_media, media_tag=media_tag,
                splitter=splitter)
            if ok:
                log.info("[%s] DC%d%s fallback closed", label, dc, media_tag)
            return

        # -- Try WebSocket via direct connection --
        fail_until = _dc_fail_until.get(dc_key, 0)
        ws_timeout = _WS_FAIL_TIMEOUT if now < fail_until else 10.0

        domains = _ws_domains(dc, is_media)
        target = dc_opt[dc]
        ws = None
        ws_failed_redirect = False
        all_redirects = True

        ws = await _ws_pool.get(dc, is_media, target, domains)
        if ws:
            log.info("[%s] DC%d%s (%s:%d) -> pool hit via %s",
                     label, dc, media_tag, dst, port, target)
        else:
            for domain in domains:
                url = f'wss://{domain}/apiws'
                log.info("[%s] DC%d%s (%s:%d) -> %s via %s",
                         label, dc, media_tag, dst, port, url, target)
                try:
                    ws = await RawWebSocket.connect(target, domain,
                                                    timeout=ws_timeout)
                    all_redirects = False
                    break
                except WsHandshakeError as exc:
                    stats.ws_errors += 1
                    if exc.is_redirect:
                        ws_failed_redirect = True
                        log.warning("[%s] DC%d%s got %d from %s -> %s",
                                    label, dc, media_tag,
                                    exc.status_code, domain,
                                    exc.location or '?')
                        continue
                    else:
                        all_redirects = False
                        log.warning("[%s] DC%d%s WS handshake: %s",
                                    label, dc, media_tag, exc.status_line)
                except Exception as exc:
                    stats.ws_errors += 1
                    all_redirects = False
                    err_str = str(exc)
                    if ('CERTIFICATE_VERIFY_FAILED' in err_str or
                            'Hostname mismatch' in err_str):
                        log.warning("[%s] DC%d%s SSL error: %s",
                                    label, dc, media_tag, exc)
                    else:
                        log.warning("[%s] DC%d%s WS connect failed: %s",
                                    label, dc, media_tag, exc)

        # -- WS failed -> fallback --
        if ws is None:
            if ws_failed_redirect and all_redirects:
                _ws_blacklist.add(dc_key)
                log.warning(
                    "[%s] DC%d%s blacklisted for WS (all 302)",
                    label, dc, media_tag)
            elif ws_failed_redirect:
                _dc_fail_until[dc_key] = now + _DC_FAIL_COOLDOWN
            else:
                _dc_fail_until[dc_key] = now + _DC_FAIL_COOLDOWN
                log.info("[%s] DC%d%s WS cooldown for %ds",
                         label, dc, media_tag, int(_DC_FAIL_COOLDOWN))

            splitter_fb = None
            if proto is not None:
                try:
                    splitter_fb = MsgSplitter(init, proto)
                except Exception:
                    pass
            ok = await do_fallback(
                reader, writer, init, label,
                dc=dc, dst=dst, port=port,
                is_media=is_media, media_tag=media_tag,
                splitter=splitter_fb)
            if ok:
                log.info("[%s] DC%d%s fallback closed",
                         label, dc, media_tag)
            return

        # -- WS success --
        _dc_fail_until.pop(dc_key, None)
        stats.connections_ws += 1

        splitter = None
        if proto is not None and (init_patched or is_media or
                                  proto != PROTO_INTERMEDIATE):
            try:
                splitter = MsgSplitter(init, proto)
                log.debug("[%s] MsgSplitter activated for proto 0x%08X",
                          label, proto)
            except Exception:
                pass

        # Send the buffered init packet
        await ws.send(init)

        # Bidirectional bridge
        await bridge_ws(reader, writer, ws, label,
                        dc=dc, dst=dst, port=port, is_media=is_media,
                        splitter=splitter)

    except asyncio.TimeoutError:
        log.warning("[%s] timeout during SOCKS5 handshake", label)
    except asyncio.IncompleteReadError:
        log.debug("[%s] client disconnected", label)
    except asyncio.CancelledError:
        log.debug("[%s] cancelled", label)
    except ConnectionResetError:
        log.debug("[%s] connection reset", label)
    except OSError as exc:
        if getattr(exc, 'winerror', None) == 1236:
            log.debug("[%s] connection aborted by local system", label)
        else:
            log.error("[%s] unexpected os error: %s", label, exc)
    except Exception as exc:
        log.error("[%s] unexpected: %s", label, exc, exc_info=True)
    finally:
        stats.connections_active -= 1
        try:
            writer.close()
            await writer.wait_closed()
        except BaseException:
            pass


# --- Server lifecycle ---

_server_instance = None
_server_stop_event = None


async def _run(stop_event: Optional[asyncio.Event] = None):
    global _server_instance, _server_stop_event
    _server_stop_event = stop_event

    _ws_pool.reset()
    _ws_blacklist.clear()
    _dc_fail_until.clear()
    _client_tasks.clear()

    # Load CF settings from environment (our SOCKS5 addition)
    if not proxy_config.cf_domain:
        proxy_config.cf_domain = os.environ.get('CF_DOMAIN', '')
    if not proxy_config.cf_ip:
        proxy_config.cf_ip = os.environ.get('CF_IP', '')

    # Start CF proxy domain refresh if no custom CF domain
    if proxy_config.fallback_cfproxy and not proxy_config.cf_domain:
        user = proxy_config.cfproxy_user_domain
        if user:
            from .balancer import balancer
            balancer.update_domains_list([user])
        else:
            start_cfproxy_domain_refresh()

    dc_opt = proxy_config.dc_redirects

    def client_cb(r, w):
        task = asyncio.create_task(_handle_client(r, w))
        _client_tasks.add(task)
        task.add_done_callback(_client_tasks.discard)

    server = await asyncio.start_server(
        client_cb, proxy_config.host, proxy_config.port)
    _server_instance = server

    for sock in server.sockets:
        try:
            sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

    log.info("=" * 60)
    log.info("  Telegram WS Bridge Proxy (SOCKS5)")
    log.info("  Listening on   %s:%d", proxy_config.host, proxy_config.port)
    if proxy_config.cf_domain:
        log.info("  CF Domain:     %s", proxy_config.cf_domain)
    if proxy_config.cf_ip:
        log.info("  CF IP:         %s", proxy_config.cf_ip)
    log.info("  Target DC IPs:")
    for dc in sorted(dc_opt.keys()):
        ip = dc_opt.get(dc)
        log.info("    DC%d: %s", dc, ip)
    if proxy_config.fallback_cfproxy:
        prio = ('CF first' if proxy_config.fallback_cfproxy_priority
                else 'TCP first')
        log.info("  CF proxy:      enabled (%s)", prio)
    log.info("=" * 60)
    log.info("  Configure Telegram Desktop:")
    log.info("    SOCKS5 proxy -> %s:%d  (no user/pass)",
             proxy_config.host, proxy_config.port)
    log.info("=" * 60)

    async def log_stats():
        try:
            while True:
                await asyncio.sleep(60)
                bl = ', '.join(
                    f'DC{d}{"m" if m else ""}'
                    for d, m in sorted(_ws_blacklist)) or 'none'
                log.info("stats: %s | ws_bl: %s", stats.summary(), bl)
        except asyncio.CancelledError:
            raise

    log_stats_task = asyncio.create_task(log_stats())

    await _ws_pool.warmup(dc_opt)

    try:
        async with server:
            if stop_event:
                serve_task = asyncio.create_task(server.serve_forever())
                stop_task = asyncio.create_task(stop_event.wait())
                done, _ = await asyncio.wait(
                    (serve_task, stop_task),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if stop_task in done:
                    server.close()
                    await server.wait_closed()
                    if not serve_task.done():
                        serve_task.cancel()
                        try:
                            await serve_task
                        except asyncio.CancelledError:
                            pass
                else:
                    stop_task.cancel()
                    try:
                        await stop_task
                    except asyncio.CancelledError:
                        pass
            else:
                await server.serve_forever()
    finally:
        log_stats_task.cancel()
        try:
            await log_stats_task
        except asyncio.CancelledError:
            pass
    _server_instance = None


def run_proxy(stop_event: Optional[asyncio.Event] = None):
    """Run the proxy (blocking). Can be called from threads."""
    asyncio.run(_run(stop_event))


def main():
    ap = argparse.ArgumentParser(
        description='Telegram Desktop WebSocket Bridge Proxy (SOCKS5)')
    ap.add_argument('--port', type=int, default=proxy_config.port,
                    help=f'Listen port (default {proxy_config.port})')
    ap.add_argument('--host', type=str, default='127.0.0.1',
                    help='Listen host (default 127.0.0.1)')
    ap.add_argument('--dc-ip', metavar='DC:IP', action='append',
                    default=[],
                    help='Target IP for a DC, e.g. --dc-ip 1:149.154.175.205'
                         ' --dc-ip 2:149.154.167.220')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='Debug logging')
    ap.add_argument('--log-file', type=str, default=None, metavar='PATH',
                    help='Log to file with rotation (default: stderr only)')
    ap.add_argument('--log-max-mb', type=float, default=5, metavar='MB',
                    help='Max log file size in MB before rotation (default 5)')
    ap.add_argument('--log-backups', type=int, default=0, metavar='N',
                    help='Number of rotated log files to keep (default 0)')
    ap.add_argument('--buf-kb', type=int, default=256, metavar='KB',
                    help='Socket send/recv buffer size in KB (default 256)')
    ap.add_argument('--pool-size', type=int, default=4, metavar='N',
                    help='WS connection pool size per DC (default 4, min 0)')
    ap.add_argument('--cfproxy-domain', type=str, default='',
                    metavar='DOMAIN',
                    help='User defined Cloudflare-proxied domain for WS '
                         'fallback')
    ap.add_argument('--no-cfproxy', action='store_true',
                    help='Disable Cloudflare proxy fallback')
    ap.add_argument('--cfproxy-priority', type=bool, default=True,
                    help='Try cfproxy before tcp fallback (default: true)')
    args = ap.parse_args()

    if not args.dc_ip:
        args.dc_ip = ['2:149.154.167.220', '4:149.154.167.220']

    try:
        dc_opt = parse_dc_ip_list(args.dc_ip)
    except ValueError as e:
        log.error(str(e))
        sys.exit(1)

    # Populate config
    proxy_config.port = args.port
    proxy_config.host = args.host
    proxy_config.dc_redirects = dc_opt
    proxy_config.buffer_size = max(4, args.buf_kb) * 1024
    proxy_config.pool_size = max(0, args.pool_size)
    proxy_config.fallback_cfproxy = not args.no_cfproxy
    proxy_config.fallback_cfproxy_priority = args.cfproxy_priority
    proxy_config.cfproxy_user_domain = args.cfproxy_domain.strip()
    proxy_config.verbose = args.verbose

    # CF env vars (our SOCKS5 addition)
    proxy_config.cf_domain = os.environ.get('CF_DOMAIN', '')
    proxy_config.cf_ip = os.environ.get('CF_IP', '')

    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_fmt = logging.Formatter('%(asctime)s  %(levelname)-5s  %(message)s',
                                datefmt='%H:%M:%S')
    root = logging.getLogger()
    root.setLevel(log_level)

    console = logging.StreamHandler()
    console.setFormatter(log_fmt)
    root.addHandler(console)

    if args.log_file:
        fh = logging.handlers.RotatingFileHandler(
            args.log_file,
            maxBytes=max(32 * 1024, int(args.log_max_mb * 1024 * 1024)),
            backupCount=max(0, args.log_backups),
            encoding='utf-8',
        )
        fh.setFormatter(log_fmt)
        root.addHandler(fh)

    logging.getLogger('asyncio').setLevel(logging.WARNING)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        log.info("Shutting down. Final stats: %s", stats.summary())


if __name__ == '__main__':
    main()
