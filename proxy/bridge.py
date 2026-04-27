"""
Bidirectional bridge logic: TCP <-> WebSocket and TCP <-> TCP.

Also includes MsgSplitter for splitting MTProto transport packets,
DC init extraction/patching, and CF proxy fallback.
"""
from __future__ import annotations

import asyncio
import logging
import struct
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .utils import (
    ZERO_64, PROTO_ABRIDGED, PROTO_INTERMEDIATE, PROTO_PADDED_INTERMEDIATE,
    VALID_PROTOS, DC_DEFAULT_IPS, human_bytes, st_Ih, st_I_le,
)
from .stats import stats
from .config import proxy_config
from .balancer import balancer
from .raw_websocket import RawWebSocket

log = logging.getLogger('tg-ws-proxy')


# --- DC extraction & patching (SOCKS5-specific) ---

def dc_from_init(data: bytes):
    """
    Extract DC ID from the 64-byte MTProto obfuscation init packet.
    Returns (dc_id, is_media, proto) or (None, False, None) on failure.
    """
    try:
        cipher = Cipher(algorithms.AES(data[8:40]), modes.CTR(data[40:56]))
        encryptor = cipher.encryptor()
        keystream = encryptor.update(ZERO_64)
        plain = (int.from_bytes(data[56:64], 'big') ^
                 int.from_bytes(keystream[56:64], 'big')).to_bytes(8, 'big')

        proto, dc_raw = st_Ih.unpack(plain[:6])

        log.debug("dc_from_init: proto=0x%08X dc_raw=%d plain=%s",
                  proto, dc_raw, plain.hex())

        if proto in VALID_PROTOS:
            dc = abs(dc_raw)
            if 1 <= dc <= 5 or dc == 203:
                return dc, (dc_raw < 0), proto
            # Valid protocol but invalid dc_id (e.g. Android with useSecret=0)
            # Return proto so MsgSplitter knows the protocol type
            return None, False, proto
    except Exception as exc:
        log.debug("DC extraction failed: %s", exc)

    return None, False, None


def patch_init_dc(data: bytes, dc: int) -> bytes:
    """
    Patch dc_id in the 64-byte MTProto init packet.
    Mobile clients with useSecret=0 leave bytes 60-61 as random.
    """
    if len(data) < 64:
        return data

    new_dc = struct.pack('<h', dc)
    try:
        cipher = Cipher(algorithms.AES(data[8:40]), modes.CTR(data[40:56]))
        enc = cipher.encryptor()
        ks = enc.update(ZERO_64)
        patched = bytearray(data[:64])
        patched[60] = ks[60] ^ new_dc[0]
        patched[61] = ks[61] ^ new_dc[1]
        log.debug("init patched: dc_id -> %d", dc)
        if len(data) > 64:
            return bytes(patched) + data[64:]
        return bytes(patched)
    except Exception:
        return data


# --- MsgSplitter ---

class MsgSplitter:
    """
    Splits client TCP data into individual MTProto transport packets so
    each can be sent as a separate WebSocket frame.

    Some mobile clients coalesce multiple MTProto packets into one TCP
    write, and TCP reads may also cut a packet in half.  Keep a rolling
    buffer so incomplete packets are not forwarded as standalone frames.
    """

    __slots__ = ('_dec', '_proto', '_cipher_buf', '_plain_buf', '_disabled')

    def __init__(self, init_data: bytes, proto: int):
        cipher = Cipher(algorithms.AES(init_data[8:40]),
                        modes.CTR(init_data[40:56]))
        self._dec = cipher.encryptor()
        self._dec.update(ZERO_64)  # skip init packet
        self._proto = proto
        self._cipher_buf = bytearray()
        self._plain_buf = bytearray()
        self._disabled = False

    def split(self, chunk: bytes) -> List[bytes]:
        """Decrypt to find packet boundaries, return complete ciphertext packets."""
        if not chunk:
            return []
        if self._disabled:
            return [chunk]

        self._cipher_buf.extend(chunk)
        self._plain_buf.extend(self._dec.update(chunk))

        parts = []
        while self._cipher_buf:
            packet_len = self._next_packet_len()
            if packet_len is None:
                break
            if packet_len <= 0:
                parts.append(bytes(self._cipher_buf))
                self._cipher_buf.clear()
                self._plain_buf.clear()
                self._disabled = True
                break
            parts.append(bytes(self._cipher_buf[:packet_len]))
            del self._cipher_buf[:packet_len]
            del self._plain_buf[:packet_len]
        return parts

    def flush(self) -> List[bytes]:
        if not self._cipher_buf:
            return []
        tail = bytes(self._cipher_buf)
        self._cipher_buf.clear()
        self._plain_buf.clear()
        return [tail]

    def _next_packet_len(self) -> Optional[int]:
        if not self._plain_buf:
            return None
        if self._proto == PROTO_ABRIDGED:
            return self._next_abridged_len()
        if self._proto in (PROTO_INTERMEDIATE, PROTO_PADDED_INTERMEDIATE):
            return self._next_intermediate_len()
        return 0

    def _next_abridged_len(self) -> Optional[int]:
        first = self._plain_buf[0]
        if first in (0x7F, 0xFF):
            if len(self._plain_buf) < 4:
                return None
            payload_len = int.from_bytes(self._plain_buf[1:4], 'little') * 4
            header_len = 4
        else:
            payload_len = (first & 0x7F) * 4
            header_len = 1

        if payload_len <= 0:
            return 0

        packet_len = header_len + payload_len
        if len(self._plain_buf) < packet_len:
            return None
        return packet_len

    def _next_intermediate_len(self) -> Optional[int]:
        if len(self._plain_buf) < 4:
            return None

        payload_len = st_I_le.unpack_from(self._plain_buf, 0)[0] & 0x7FFFFFFF
        if payload_len <= 0:
            return 0

        packet_len = 4 + payload_len
        if len(self._plain_buf) < packet_len:
            return None
        return packet_len


# --- Bridge functions ---

async def bridge_ws(reader, writer, ws: RawWebSocket, label,
                    dc=None, dst=None, port=None, is_media=False,
                    splitter: MsgSplitter = None):
    """Bidirectional TCP <-> WebSocket forwarding (SOCKS5 transparent mode)."""
    dc_tag = f"DC{dc}{'m' if is_media else ''}" if dc else "DC?"
    dst_tag = f"{dst}:{port}" if dst else "?"

    up_bytes = 0
    down_bytes = 0
    up_packets = 0
    down_packets = 0
    start_time = asyncio.get_running_loop().time()

    async def tcp_to_ws():
        nonlocal up_bytes, up_packets
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    if splitter:
                        tail = splitter.flush()
                        if tail:
                            await ws.send(tail[0])
                    break
                n = len(chunk)
                stats.bytes_up += n
                up_bytes += n
                up_packets += 1
                if splitter:
                    parts = splitter.split(chunk)
                    if not parts:
                        continue
                    if len(parts) > 1:
                        await ws.send_batch(parts)
                    else:
                        await ws.send(parts[0])
                else:
                    await ws.send(chunk)
        except (asyncio.CancelledError, ConnectionError, OSError):
            return
        except Exception as e:
            log.debug("[%s] tcp->ws ended: %s", label, e)

    async def ws_to_tcp():
        nonlocal down_bytes, down_packets
        try:
            while True:
                data = await ws.recv()
                if data is None:
                    break
                n = len(data)
                stats.bytes_down += n
                down_bytes += n
                down_packets += 1
                writer.write(data)
                await writer.drain()
        except (asyncio.CancelledError, ConnectionError, OSError):
            return
        except Exception as e:
            log.debug("[%s] ws->tcp ended: %s", label, e)

    tasks = [asyncio.create_task(tcp_to_ws()),
             asyncio.create_task(ws_to_tcp())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        elapsed = asyncio.get_running_loop().time() - start_time
        log.info("[%s] %s (%s) WS session closed: "
                 "^%s (%d pkts) v%s (%d pkts) in %.1fs",
                 label, dc_tag, dst_tag,
                 human_bytes(up_bytes), up_packets,
                 human_bytes(down_bytes), down_packets,
                 elapsed)
        try:
            await ws.close()
        except BaseException:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except BaseException:
            pass


async def bridge_tcp(reader, writer, remote_reader, remote_writer,
                     label, dc=None, dst=None, port=None,
                     is_media=False):
    """Bidirectional TCP <-> TCP forwarding (for fallback)."""
    async def forward(src, dst_w, is_up):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                n = len(data)
                if is_up:
                    stats.bytes_up += n
                else:
                    stats.bytes_down += n
                dst_w.write(data)
                await dst_w.drain()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.debug("[%s] forward ended: %s", label, e)

    tasks = [
        asyncio.create_task(forward(reader, remote_writer, True)),
        asyncio.create_task(forward(remote_reader, writer, False)),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        for w in (writer, remote_writer):
            try:
                w.close()
                await w.wait_closed()
            except BaseException:
                pass


async def pipe(r, w):
    """Plain TCP relay for non-Telegram traffic."""
    try:
        while True:
            data = await r.read(65536)
            if not data:
                break
            w.write(data)
            await w.drain()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass
    finally:
        try:
            w.close()
            await w.wait_closed()
        except Exception:
            pass


async def tcp_fallback(reader, writer, dst, port, init, label,
                       dc=None, is_media=False):
    """
    Fall back to direct TCP to the original DC IP.
    Throttled by ISP, but functional.  Returns True on success.
    """
    try:
        rr, rw = await asyncio.wait_for(
            asyncio.open_connection(dst, port), timeout=10)
    except Exception as exc:
        log.warning("[%s] TCP fallback connect to %s:%d failed: %s",
                    label, dst, port, exc)
        return False

    stats.connections_tcp_fallback += 1
    rw.write(init)
    await rw.drain()
    await bridge_tcp(reader, writer, rr, rw, label,
                     dc=dc, dst=dst, port=port, is_media=is_media)
    return True


async def cfproxy_fallback(reader, writer, init, label,
                           dc: int, is_media: bool,
                           splitter: MsgSplitter = None):
    """
    Fallback via CF proxy domain (ported from upstream).
    Returns True on success.
    """
    media_tag = ' media' if is_media else ''
    ws = None
    chosen_domain = None

    log.info("[%s] DC%d%s -> trying CF proxy",
             label, dc, media_tag)

    for base_domain in balancer.get_domains_for_dc(dc):
        domain = f'kws{dc}.{base_domain}'
        try:
            ws = await RawWebSocket.connect(domain, domain, timeout=10.0)
            chosen_domain = base_domain
            break
        except Exception as exc:
            log.warning("[%s] DC%d%s CF proxy failed: %s",
                        label, dc, media_tag, repr(exc))

    if ws is None:
        return False

    if chosen_domain and balancer.update_domain_for_dc(dc, chosen_domain):
        log.info("[%s] Switched active CF domain", label)

    stats.connections_cfproxy += 1
    await ws.send(init)
    await bridge_ws(reader, writer, ws, label,
                    dc=dc, is_media=is_media,
                    splitter=splitter)
    return True


async def do_fallback(reader, writer, init, label,
                      dc: int, dst: str, port: int,
                      is_media: bool, media_tag: str,
                      splitter: MsgSplitter = None):
    """
    Combined fallback: try CF proxy and/or TCP, respecting priority.
    Returns True on success.
    """
    use_cf = proxy_config.fallback_cfproxy
    cf_first = proxy_config.fallback_cfproxy_priority

    methods: List[str] = ['tcp']
    if use_cf:
        methods.insert(0 if cf_first else 1, 'cf')

    for method in methods:
        if method == 'cf':
            ok = await cfproxy_fallback(
                reader, writer, init, label,
                dc=dc, is_media=is_media,
                splitter=splitter)
            if ok:
                return True
        elif method == 'tcp':
            log.info("[%s] DC%d%s -> TCP fallback to %s:%d",
                     label, dc, media_tag, dst, port)
            ok = await tcp_fallback(
                reader, writer, dst, port, init, label,
                dc=dc, is_media=is_media)
            if ok:
                return True
    return False
