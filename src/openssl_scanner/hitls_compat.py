"""OpenSSL -> openHiTLS API compatibility lookup."""

import json
import logging
import os
from typing import Any, Dict, Optional, Set, Tuple, Union

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

        with open(path, encoding='utf-8') as f:
            data = json.load(f)

        mapping = data.get('mapping')
        if not isinstance(mapping, dict):
            raise ValueError(
                "Invalid hitls_compat.json: 'mapping' key missing or not a dict"
            )

        self._mapping = mapping
        self._loaded = True
        logger.info("Loaded %d HiTLS compat mappings from %s", len(mapping), path)
        return len(mapping)

    def is_loaded(self) -> bool:
        return self._loaded

    def lookup_entry(self, symbol: str) -> Dict[str, Any]:
        """Return the full compatibility entry for a symbol.

        Returns a normalized dict with at least:
            status, hitls, notes
        """
        if not self._loaded:
            return {
                'status': 'unknown',
                'hitls': None,
                'notes': None,
            }
        entry = self._mapping.get(symbol)
        if entry is None:
            return {
                'status': 'unknown',
                'hitls': None,
                'notes': None,
            }
        return dict(entry)

    def lookup(self, symbol: str) -> Tuple[str, Optional[str]]:
        """Look up openHiTLS compatibility for an OpenSSL symbol.

        Returns:
            (status, hitls_equiv) where status is one of
            'available', 'partial', 'not_available', 'unknown'.
        """
        entry = self.lookup_entry(symbol)
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

    def get_coverage_summary(
        self, symbols: Set[str]
    ) -> Dict[str, Union[int, float]]:
        """Compute counts and replacement ratios for a symbol set."""
        stats = self.get_coverage_stats(symbols)
        total = len(symbols)
        if total == 0:
            direct_ratio = 0.0
            combined_ratio = 0.0
        else:
            direct_ratio = round((stats['available'] / total) * 100, 2)
            combined_ratio = round(
                ((stats['available'] + stats['partial']) / total) * 100, 2
            )
        summary: Dict[str, Union[int, float]] = dict(stats)
        summary['total_symbols'] = total
        summary['direct_replace_ratio'] = direct_ratio
        summary['direct_or_partial_replace_ratio'] = combined_ratio
        return summary

    def get_all_mappings(self) -> Dict[str, Dict[str, Any]]:
        """Return the full mapping dict (for serialization)."""
        return dict(self._mapping)
