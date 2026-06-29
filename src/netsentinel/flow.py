"""Turn a stream of packets into NSL-KDD-style connection (flow) records.

The model was trained on *flow-level* features: each row of NSL-KDD summarizes
one connection (bytes sent, protocol, service, error rates, how many other
connections went to the same host recently, ...). Live packets are individual
fragments, so to score real traffic we must group packets into flows and
reconstruct those features. That reconstruction is exactly what this module
does — and it is the piece that lets the model run on a real network rather
than on a replayed CSV.

Design notes
------------
* This module is deliberately **decoupled from scapy**: it consumes plain
  :class:`PacketInfo` records, so the flow logic is unit-testable without raw
  sockets or admin privileges. :mod:`netsentinel.live_capture` provides the
  scapy adapter that produces ``PacketInfo`` objects from the wire.
* **Feature coverage is honest.** Header/timing-derived features (bytes,
  protocol, service, flags, duration, and the time-window traffic statistics)
  are computed for real. NSL-KDD's *content* features (e.g. ``num_failed_logins``,
  ``hot``) require deep payload inspection and are out of scope; they default
  to 0. The model's strongest signals (see the feature-importance plot) are the
  ones we do compute, so live scoring remains meaningful.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass

from .data import CATEGORICAL_FEATURES, COLUMNS, NON_FEATURE_COLUMNS

# Feature columns the model expects, in order (41 features, no label/difficulty).
FEATURE_COLUMNS: list[str] = [c for c in COLUMNS if c not in NON_FEATURE_COLUMNS]

# Common destination ports -> NSL-KDD service names. Unknown services are fine:
# the model's OneHotEncoder was fit with handle_unknown="ignore".
SERVICE_BY_PORT: dict[int, str] = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 67: "dhcp", 69: "tftp_u", 79: "finger", 80: "http",
    110: "pop_3", 111: "sunrpc", 113: "auth", 119: "nntp", 123: "ntp_u",
    143: "imap4", 161: "snmp", 179: "bgp", 389: "ldap", 443: "http_443",
    445: "microsoft_ds", 514: "shell", 515: "printer", 993: "imap4",
    3306: "sql_net", 8001: "http_8001",
}

# Time window (seconds) used for the "count"/"srv_count" traffic statistics.
# NSL-KDD uses a 2-second connection window.
TRAFFIC_WINDOW = 2.0

# How long a flow can sit idle before we consider it complete and emit it.
FLOW_IDLE_TIMEOUT = 5.0

# TCP flag bits.
_FIN, _SYN, _RST, _PSH, _ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class PacketInfo:
    """A minimal, scapy-free description of one captured packet."""

    ts: float
    src_ip: str
    dst_ip: str
    protocol: str  # "tcp" | "udp" | "icmp"
    length: int
    payload_len: int = 0
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int = 0


@dataclass
class _Flow:
    """Accumulated state for one connection, keyed by (src, dst, dport, proto)."""

    src_ip: str
    dst_ip: str
    dst_port: int | None
    protocol: str
    start_ts: float
    last_ts: float
    src_bytes: int = 0
    dst_bytes: int = 0
    flag_bits: int = 0  # OR of all TCP flags seen
    finished: bool = False

    def service(self) -> str:
        return SERVICE_BY_PORT.get(self.dst_port or -1, "other")

    def nsl_flag(self) -> str:
        """Approximate the NSL-KDD connection ``flag`` from observed TCP flags."""
        if self.protocol != "tcp":
            return "SF"
        if self.flag_bits & _RST:
            return "REJ"
        if (self.flag_bits & _SYN) and not (self.flag_bits & _ACK):
            return "S0"  # SYN sent, never acknowledged
        if (self.flag_bits & _SYN) and (self.flag_bits & _FIN):
            return "SF"  # established and cleanly closed
        return "OTH"


def _flow_key(p: PacketInfo) -> tuple:
    """Direction-independent key so both halves of a connection share a flow."""
    a = (p.src_ip, p.src_port)
    b = (p.dst_ip, p.dst_port)
    lo, hi = sorted([a, b])
    return (lo, hi, p.protocol)


class FlowTracker:
    """Aggregates :class:`PacketInfo` records into flows and emits completed ones.

    Feed packets with :meth:`update`; it returns a feature dict whenever a flow
    completes (TCP FIN/RST). Call :meth:`expire` periodically to flush flows
    that have gone idle.
    """

    def __init__(self) -> None:
        self._flows: dict[tuple, _Flow] = {}
        # Recent connection history for time-window traffic statistics:
        # entries are (timestamp, dst_ip, service, nsl_flag).
        self._history: deque[tuple[float, str, str, str]] = deque()

    def update(self, p: PacketInfo) -> dict | None:
        """Incorporate a packet; return a feature dict if a flow just completed."""
        key = _flow_key(p)
        flow = self._flows.get(key)
        if flow is None:
            flow = _Flow(
                src_ip=p.src_ip, dst_ip=p.dst_ip, dst_port=p.dst_port,
                protocol=p.protocol, start_ts=p.ts, last_ts=p.ts,
            )
            self._flows[key] = flow

        flow.last_ts = p.ts
        flow.flag_bits |= p.tcp_flags
        # Bytes are attributed by direction relative to the flow's originator.
        if p.src_ip == flow.src_ip:
            flow.src_bytes += p.payload_len
        else:
            flow.dst_bytes += p.payload_len

        # A TCP connection is "complete" once a FIN or RST has been seen.
        if p.protocol == "tcp" and (p.tcp_flags & (_FIN | _RST)):
            flow.finished = True
            return self._emit(key)
        return None

    def expire(self, now: float | None = None) -> list[dict]:
        """Emit feature dicts for flows idle longer than :data:`FLOW_IDLE_TIMEOUT`."""
        now = time.time() if now is None else now
        emitted = []
        for key, flow in list(self._flows.items()):
            if now - flow.last_ts >= FLOW_IDLE_TIMEOUT:
                emitted.append(self._emit(key))
        return emitted

    def _emit(self, key: tuple) -> dict:
        flow = self._flows.pop(key)
        self._record_history(flow)
        return self._features(flow)

    def _record_history(self, flow: _Flow) -> None:
        self._history.append((flow.last_ts, flow.dst_ip, flow.service(), flow.nsl_flag()))
        self._trim_history(flow.last_ts)

    def _trim_history(self, now: float) -> None:
        while self._history and now - self._history[0][0] > TRAFFIC_WINDOW:
            self._history.popleft()

    def _features(self, flow: _Flow) -> dict:
        """Build a full 41-feature row (computed features set, rest default to 0)."""
        self._trim_history(flow.last_ts)
        service = flow.service()

        same_host = [h for h in self._history if h[1] == flow.dst_ip]
        same_srv = [h for h in self._history if h[2] == service]
        count = len(same_host)
        srv_count = len(same_srv)

        def _rate(subset: list, predicate) -> float:
            return (sum(1 for h in subset if predicate(h)) / len(subset)) if subset else 0.0

        # Every feature defaults to 0; we then fill the ones we can compute.
        feats: dict = {col: 0 for col in FEATURE_COLUMNS}
        feats.update(
            {
                "duration": int(flow.last_ts - flow.start_ts),
                "protocol_type": flow.protocol,
                "service": service,
                "flag": flow.nsl_flag(),
                "src_bytes": flow.src_bytes,
                "dst_bytes": flow.dst_bytes,
                "land": int(flow.src_ip == flow.dst_ip),
                "count": count,
                "srv_count": srv_count,
                "same_srv_rate": _rate(same_host, lambda h: h[2] == service),
                "diff_srv_rate": _rate(same_host, lambda h: h[2] != service),
                "serror_rate": _rate(same_host, lambda h: h[3] in ("S0", "S1", "S2", "S3")),
                "srv_serror_rate": _rate(same_srv, lambda h: h[3] in ("S0", "S1", "S2", "S3")),
                "rerror_rate": _rate(same_host, lambda h: h[3] == "REJ"),
                "srv_rerror_rate": _rate(same_srv, lambda h: h[3] == "REJ"),
            }
        )
        # Categorical columns must stay strings; everything else numeric.
        for col in feats:
            if col not in CATEGORICAL_FEATURES and not isinstance(feats[col], (int, float)):
                feats[col] = 0
        # Metadata (underscore-prefixed) carried alongside the model features so
        # the runtime knows which real IP to block. Not used by the model.
        feats["_src_ip"] = flow.src_ip
        feats["_dst_ip"] = flow.dst_ip
        return feats
