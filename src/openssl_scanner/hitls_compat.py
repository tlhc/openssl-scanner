"""OpenSSL -> openHiTLS API compatibility lookup."""

import json
import os
import logging
from typing import Dict, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class HiTLSCompat:
    """Loads OpenSSL-to-openHiTLS mapping and provides per-symbol lookup."""

    def __init__(self) -> None:
        self._mapping: Dict[str, Dict] = {}
        self._loaded: bool = False

    def load(self, path: Optional[str] = None) -> int:
        """Load mapping from JSON file.

        Args:
            path: Path to mapping JSON. If None, uses built-in
                  data/hitls_compat.json.

        Returns:
            Number of symbols loaded.

        Raises:
            FileNotFoundError: If the mapping file does not exist.
            ValueError: If the JSON structure is invalid.
        """
        if path is None:
            path = os.path.join(
                os.path.dirname(__file__), 'data', 'hitls_compat.json'
            )

        if not os.path.isfile(path):
            raise FileNotFoundError(f"HiTLS mapping not found: {path}")

        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        mapping = data.get('mapping')
        if not isinstance(mapping, dict):
            raise ValueError(
                f"Invalid hitls_compat.json: 'mapping' key missing or not a dict"
            )

        self._mapping = mapping
        self._loaded = True
        logger.info("Loaded %d HiTLS compat mappings from %s", len(mapping), path)
        return len(mapping)

    def is_loaded(self) -> bool:
        return self._loaded

    def lookup(self, symbol: str) -> Tuple[str, Optional[str]]:
        """Look up openHiTLS compatibility for an OpenSSL symbol.

        Returns:
            (status, hitls_equiv) where status is one of
            'available', 'partial', 'not_available', 'unknown'.
        """
        if not self._loaded:
            return ('unknown', None)
        entry = self._mapping.get(symbol)
        if entry is None:
            return ('unknown', None)
        return (entry.get('status', 'unknown'), entry.get('hitls'))

    def get_coverage_stats(self, symbols: Set[str]) -> Dict[str, int]:
        """Compute coverage statistics for a set of OpenSSL symbols.

        Returns:
            Dict with counts: available, partial, not_available, unknown.
        """
        stats = {'available': 0, 'partial': 0, 'not_available': 0, 'unknown': 0}
        for sym in symbols:
            status, _ = self.lookup(sym)
            bucket = status if status in stats else 'unknown'
            stats[bucket] += 1
        return stats

    def get_all_mappings(self) -> Dict[str, Dict]:
        """Return the full mapping dict (for serialization)."""
        return dict(self._mapping)
