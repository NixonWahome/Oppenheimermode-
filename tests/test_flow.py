"""Tests for packet-to-flow aggregation and NSL-KDD feature reconstruction.

These run without scapy or admin rights because FlowTracker consumes plain
PacketInfo records.
"""
from __future__ import annotations

from netsentinel.flow import FEATURE_COLUMNS, FlowTracker, PacketInfo

_FIN, _SYN, _ACK = 0x01, 0x02, 0x10


def _syn(src, dst, sport, dport, ts, payload=0):
    return PacketInfo(ts, src, dst, "tcp", 60 + payload, payload, sport, dport, _SYN)


def test_completed_tcp_flow_emits_features():
    tracker = FlowTracker()
    c, s = "10.0.0.5", "10.0.0.9"
    # SYN out, data back, FIN closes the connection.
    assert tracker.update(_syn(c, s, 5000, 80, ts=0.0)) is None
    assert tracker.update(PacketInfo(0.5, s, c, "tcp", 500, 440, 80, 5000, _ACK)) is None
    row = tracker.update(PacketInfo(1.0, c, s, "tcp", 60, 0, 5000, 80, _FIN | _ACK))

    assert row is not None
    # Every model feature is present...
    assert all(col in row for col in FEATURE_COLUMNS)
    # ...and the header/timing-derived ones are computed for real.
    assert row["protocol_type"] == "tcp"
    assert row["service"] == "http"  # dst port 80
    assert row["dst_bytes"] == 440
    assert row["duration"] == 1  # ~1 second
    assert row["_src_ip"] == c


def test_traffic_window_counts_recent_connections_to_same_host():
    tracker = FlowTracker()
    victim = "10.0.0.50"
    # Three quick connections to the same host within the 2s window.
    for i, sport in enumerate((1111, 2222, 3333)):
        tracker.update(_syn("10.0.0.1", victim, sport, 80, ts=i * 0.1))
        row = tracker.update(
            PacketInfo(i * 0.1 + 0.01, "10.0.0.1", victim, "tcp", 60, 0, sport, 80, _FIN)
        )
    # The last flow should see the earlier ones in its host count.
    assert row["count"] >= 2
    assert row["same_srv_rate"] > 0


def test_unfinished_flow_is_emitted_on_expire():
    tracker = FlowTracker()
    tracker.update(_syn("10.0.0.2", "10.0.0.3", 4444, 53, ts=0.0))
    # No FIN/RST, so it only comes out once it goes idle past the timeout.
    assert tracker.expire(now=1.0) == []
    emitted = tracker.expire(now=100.0)
    assert len(emitted) == 1
