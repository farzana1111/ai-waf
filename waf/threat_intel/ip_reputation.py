"""IP reputation scoring and blocklist management.

Provides in-memory IP allow/block lists and a simple reputation
scoring mechanism that downstream components can use to fast-path
or reject requests before more expensive analysis.
"""

import logging
import time

logger = logging.getLogger(__name__)


class IPReputationChecker:
    """Score and classify IP addresses using in-memory lists.

    Maintains a *blocklist* (IP → reason mapping) and an *allowlist*
    (set of IPs).  Allowed IPs always receive a perfect score;
    blocked IPs always receive zero.  Unknown IPs receive a neutral
    score of 50.
    """

    def __init__(self) -> None:
        self._blocklist: dict[str, dict] = {}
        self._allowlist: set[str] = set()

    def check_ip(self, ip_address: str) -> dict:
        """Return a reputation verdict for *ip_address*.

        Returns:
            A dict with keys ``score`` (0–100), ``is_blocked`` (bool),
            and ``reason`` (str).
        """
        if ip_address in self._allowlist:
            return {"score": 100, "is_blocked": False, "reason": "allowlisted"}

        if ip_address in self._blocklist:
            entry = self._blocklist[ip_address]
            return {
                "score": 0,
                "is_blocked": True,
                "reason": entry.get("reason", "blocklisted"),
            }

        return {"score": 50, "is_blocked": False, "reason": "unknown"}

    def add_to_blocklist(self, ip: str, reason: str = "manual") -> None:
        """Add *ip* to the blocklist with an optional *reason*.

        If the IP is currently on the allowlist it is removed from
        there first.
        """
        self._allowlist.discard(ip)
        self._blocklist[ip] = {
            "reason": reason,
            "added_at": time.time(),
        }
        logger.info("IP %s added to blocklist: %s", ip, reason)

    def add_to_allowlist(self, ip: str) -> None:
        """Add *ip* to the allowlist.

        If the IP is currently on the blocklist it is removed from
        there first.
        """
        self._blocklist.pop(ip, None)
        self._allowlist.add(ip)
        logger.info("IP %s added to allowlist", ip)

    def remove_from_blocklist(self, ip: str) -> None:
        """Remove *ip* from the blocklist if present."""
        if self._blocklist.pop(ip, None) is not None:
            logger.info("IP %s removed from blocklist", ip)
