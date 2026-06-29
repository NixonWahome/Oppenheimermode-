"""Automated response: block offending IPs and log to a SIEM.

Blocking is cross-platform (iptables on Linux, netsh on Windows) and runs in
``dry_run`` mode by default so the system never touches the host firewall
unless explicitly enabled — important for a tool that takes automated action.
"""
from __future__ import annotations

import datetime
import logging
import platform
import subprocess

from . import config

logger = logging.getLogger(__name__)


class FirewallManager:
    """Blocks source IPs and records actions to Elasticsearch."""

    def __init__(self, dry_run: bool = True, enable_siem: bool = False) -> None:
        """Create a firewall manager.

        Args:
            dry_run: If True (default), log the action that *would* be taken
                instead of modifying the host firewall.
            enable_siem: If True, attempt to log events to Elasticsearch.
        """
        self.dry_run = dry_run
        self._blocked: set[str] = set()
        self.es = None
        if enable_siem:
            self._connect_siem()

    def _connect_siem(self) -> None:
        try:
            from elasticsearch import Elasticsearch

            self.es = Elasticsearch(config.ELASTICSEARCH_URL)
        except Exception as exc:  # pragma: no cover - optional dependency/service
            logger.warning("SIEM logging disabled (Elasticsearch unavailable): %s", exc)
            self.es = None

    def block_ip(self, ip: str, reason: str) -> None:
        """Block an IP at the OS firewall (or simulate it in dry-run mode)."""
        if ip in self._blocked:
            return
        self._blocked.add(ip)

        if self.dry_run:
            logger.info("[dry-run] would block %s (%s)", ip, reason)
        else:
            self._apply_block(ip)
            logger.info("blocked %s (%s)", ip, reason)

        self._log_to_siem(ip, reason)

    def _apply_block(self, ip: str) -> None:
        system = platform.system()
        try:
            if system == "Windows":
                subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=NetSentinel block {ip}", "dir=in", "action=block",
                        f"remoteip={ip}",
                    ],
                    check=True,
                )
            else:  # Linux / macOS with iptables
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True
                )
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            logger.error("failed to block %s: %s", ip, exc)

    def _log_to_siem(self, ip: str, reason: str) -> None:
        if self.es is None:
            return
        doc = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "threat_ip": ip,
            "action": "blocked",
            "reason": reason,
        }
        try:
            self.es.index(index=config.ELASTICSEARCH_INDEX, document=doc)
        except Exception as exc:  # pragma: no cover - depends on live service
            logger.error("SIEM log failed for %s: %s", ip, exc)
