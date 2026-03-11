"""Cyber threat intelligence feed management.

Aggregates threat data from multiple external feed URLs with a simple
time-based cache so that feeds are not re-fetched more often than
necessary.
"""

import logging
import time

logger = logging.getLogger(__name__)


class FeedManager:
    """Manage and cache external threat intelligence feeds.

    Feeds are identified by *name* and backed by a remote *url*.
    Fetched data is cached for *cache_ttl* seconds before the next
    :meth:`update_feeds` call will re-fetch it.

    .. important::
       The default :meth:`_fetch_feed` implementation is a **placeholder**
       that returns empty indicator lists.  Subclass ``FeedManager`` and
       override :meth:`_fetch_feed` with a real HTTP client to pull live
       threat data.
    """

    def __init__(self, cache_ttl: int = 3600) -> None:
        self._feeds: dict[str, str] = {}
        self._cache: dict[str, dict] = {}
        self._cache_ttl = cache_ttl

    def add_feed(self, name: str, url: str) -> None:
        """Register a threat feed identified by *name* at *url*."""
        self._feeds[name] = url
        logger.info("Threat feed '%s' registered: %s", name, url)

    def update_feeds(self) -> None:
        """Fetch and parse all registered feeds.

        Only feeds whose cache has expired (or have never been fetched)
        are updated.  Network errors are logged and silently skipped so
        that a single failing feed does not break the update cycle.

        .. note::
           The actual HTTP fetch is a placeholder.  Integrators should
           override :meth:`_fetch_feed` with a real implementation.
        """
        for name, url in self._feeds.items():
            cached = self._cache.get(name)
            if cached and (time.time() - cached.get("fetched_at", 0)) < self._cache_ttl:
                logger.debug("Feed '%s' still cached; skipping update", name)
                continue

            data = self._fetch_feed(name, url)
            self._cache[name] = {
                "data": data,
                "fetched_at": time.time(),
            }

    def get_threat_data(self) -> dict:
        """Return combined threat data from all cached feeds.

        Returns:
            A dict mapping feed names to their cached data payloads.
        """
        return {
            name: entry.get("data", {})
            for name, entry in self._cache.items()
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fetch_feed(name: str, url: str) -> dict:
        """Fetch and parse a single feed (placeholder).

        Override this method with a real HTTP client (e.g. ``requests``)
        to fetch and parse feed content from *url*.
        """
        logger.info("Fetching feed '%s' from %s (placeholder – no data returned)", name, url)
        return {"source": name, "url": url, "indicators": []}
