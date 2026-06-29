"""Live network capture adapter: scapy packets -> flows -> feature rows.

This is the bridge between a real network interface and the model. It sniffs
packets with scapy, converts each into a scapy-free :class:`~netsentinel.flow.PacketInfo`,
feeds them to a :class:`~netsentinel.flow.FlowTracker`, and invokes a callback
with a feature row each time a connection completes.

Requires administrator/root privileges (raw-socket capture) and the optional
``scapy`` dependency (``pip install -e .[live]``).
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable

from .flow import PacketInfo, FlowTracker

logger = logging.getLogger(__name__)

_PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp"}


def _to_packet_info(pkt) -> PacketInfo | None:
    """Convert a scapy packet to a :class:`PacketInfo`, or None if not IP."""
    from scapy.all import ICMP, IP, TCP, UDP  # lazy import; scapy is optional

    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    protocol = _PROTO_NAMES.get(int(ip.proto), "other")
    info = PacketInfo(
        ts=float(pkt.time) if hasattr(pkt, "time") else time.time(),
        src_ip=ip.src,
        dst_ip=ip.dst,
        protocol=protocol,
        length=len(pkt),
    )
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info.src_port, info.dst_port = int(tcp.sport), int(tcp.dport)
        info.tcp_flags = int(tcp.flags)
        info.payload_len = len(tcp.payload)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        info.src_port, info.dst_port = int(udp.sport), int(udp.dport)
        info.payload_len = len(udp.payload)
    elif pkt.haslayer(ICMP):
        info.payload_len = len(pkt[ICMP].payload)
    return info


class LiveCapture:
    """Sniffs an interface and emits completed-flow feature rows via a callback."""

    def __init__(self, on_flow: Callable[[dict], None], iface: str | None = None) -> None:
        """Create a live capture session.

        Args:
            on_flow: Called with a feature dict each time a connection completes.
            iface: Network interface to sniff (None = scapy's default).
        """
        self.on_flow = on_flow
        self.iface = iface
        self.tracker = FlowTracker()
        self._last_expire = time.time()

    def _handle(self, pkt) -> None:
        info = _to_packet_info(pkt)
        if info is None:
            return
        row = self.tracker.update(info)
        if row is not None:
            self.on_flow(row)

        # Periodically flush idle flows (e.g. UDP, or TCP without clean close).
        now = time.time()
        if now - self._last_expire >= 1.0:
            for row in self.tracker.expire(now):
                self.on_flow(row)
            self._last_expire = now

    def run(self, count: int = 0) -> None:
        """Start capturing. Blocks until ``count`` packets seen (0 = forever)."""
        from scapy.all import sniff

        logger.info("starting live capture on %s (Ctrl-C to stop)", self.iface or "default iface")
        sniff(prn=self._handle, store=False, iface=self.iface, count=count)
        # Flush any flows still open when capture stops.
        for row in self.tracker.expire(time.time() + 999):
            self.on_flow(row)
