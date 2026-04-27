"""Connection and traffic statistics."""
from __future__ import annotations

from .utils import human_bytes


class Stats:
    def __init__(self):
        self.connections_total = 0
        self.connections_active = 0
        self.connections_ws = 0
        self.connections_tcp_fallback = 0
        self.connections_cfproxy = 0
        self.connections_http_rejected = 0
        self.connections_passthrough = 0
        self.ws_errors = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self.pool_hits = 0
        self.pool_misses = 0

    def summary(self) -> str:
        pool_total = self.pool_hits + self.pool_misses
        pool_s = (f"{self.pool_hits}/{pool_total}"
                  if pool_total else "n/a")
        return (f"total={self.connections_total} "
                f"active={self.connections_active} "
                f"ws={self.connections_ws} "
                f"tcp_fb={self.connections_tcp_fallback} "
                f"cf={self.connections_cfproxy} "
                f"http_skip={self.connections_http_rejected} "
                f"pass={self.connections_passthrough} "
                f"err={self.ws_errors} "
                f"pool={pool_s} "
                f"up={human_bytes(self.bytes_up)} "
                f"down={human_bytes(self.bytes_down)}")


stats = Stats()
