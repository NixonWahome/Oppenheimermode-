"""Optional live packet capture (requires admin/root + scapy).

This is a thin utility for capturing raw traffic off the wire. Note that
turning live packets into the full 41-feature NSL-KDD schema requires flow
aggregation that is out of scope here (see README "Limitations"); the live
capture path is provided for inspection and future work, while the model demo
runs on replayed flow records.
"""
from __future__ import annotations

import logging
from collections import deque
from threading import Thread

logger = logging.getLogger(__name__)


class PacketSniffer:
    """Captures packets into a rolling window using scapy."""

    def __init__(self, window_size: int = 500) -> None:
        self.packet_window: deque[dict] = deque(maxlen=window_size)
        self._thread: Thread | None = None

    def _packet_callback(self, pkt) -> None:
        from scapy.all import IP, TCP  # imported lazily; scapy is optional

        if not pkt.haslayer(IP):
            return
        self.packet_window.append(
            {
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "protocol": int(pkt[IP].proto),
                "packet_size": len(pkt),
                "dst_port": int(pkt[TCP].dport) if pkt.haslayer(TCP) else None,
            }
        )

    def start(self) -> None:
        """Start capturing in a background thread."""
        from scapy.all import sniff

        self._thread = Thread(
            target=sniff,
            kwargs={"prn": self._packet_callback, "store": False},
            daemon=True,
        )
        self._thread.start()
        logger.info("packet capture started")

    def get_batch(self) -> list[dict]:
        """Return a snapshot of the current packet window."""
        return list(self.packet_window)
