"""
OpenSSL symbol matcher - Strict mode only.

Matches symbols against actual OpenSSL library exports for 100% accuracy.
"""

import os
import logging
from typing import List, Set, Dict, Optional

from .constants import OPENSSL_LIBRARY_PATTERNS, SYMBOL_CATEGORIES

logger = logging.getLogger(__name__)


class OpenSSLMatcher:
    """
    Matches symbols against OpenSSL library exports.

    Requires loading actual OpenSSL library (libcrypto.so/libssl.so) to extract
    exported symbols. Only symbols that exist in OpenSSL will be matched,
    eliminating all false positives.
    """

    def __init__(self) -> None:
        self._openssl_exports: Set[str] = set()
        self._libcrypto_path: Optional[str] = None
        self._libssl_path: Optional[str] = None
        self._lib_patterns = OPENSSL_LIBRARY_PATTERNS
        self._categories = SYMBOL_CATEGORIES

    def load_openssl_symbols(self, libcrypto_path: str,
                              libssl_path: Optional[str] = None) -> int:
        """
        Load exported symbols from OpenSSL libraries.

        Must be called before any symbol matching operations.

        Args:
            libcrypto_path: Path to libcrypto.so
            libssl_path: Path to libssl.so (optional)

        Returns:
            Number of symbols loaded

        Raises:
            FileNotFoundError: If libcrypto_path does not exist
            ValueError: If no symbols could be extracted
        """
        from .elf_analyzer import ELFAnalyzer

        if not os.path.isfile(libcrypto_path):
            raise FileNotFoundError(f"libcrypto not found: {libcrypto_path}")

        analyzer = ELFAnalyzer()
        exports: Set[str] = set()

        for lib_path in [libcrypto_path, libssl_path]:
            if not lib_path or not os.path.isfile(lib_path):
                continue

            symbols = analyzer.get_defined_symbols(lib_path)
            if symbols:
                exports.update(symbols)
                logger.info(f"Loaded {len(symbols)} symbols from {lib_path}")

        if not exports:
            raise ValueError(f"No symbols extracted from {libcrypto_path}")

        self._openssl_exports = exports
        self._libcrypto_path = libcrypto_path
        self._libssl_path = libssl_path

        return len(exports)

    def is_loaded(self) -> bool:
        """Check if OpenSSL symbols have been loaded."""
        return len(self._openssl_exports) > 0

    def is_openssl_symbol(self, symbol: str) -> bool:
        """
        Check if a symbol belongs to OpenSSL.

        Args:
            symbol: Symbol name to check

        Returns:
            True if symbol exists in loaded OpenSSL exports

        Raises:
            RuntimeError: If OpenSSL symbols have not been loaded
        """
        if not self._openssl_exports:
            raise RuntimeError("OpenSSL symbols not loaded. Call load_openssl_symbols() first.")
        return symbol in self._openssl_exports

    def is_openssl_library(self, lib_name: str) -> bool:
        """
        Check if a library name indicates an OpenSSL library.

        Args:
            lib_name: Library filename (e.g., "libcrypto.so.3")

        Returns:
            True if this is an OpenSSL library
        """
        base = lib_name.lower()
        for pattern in self._lib_patterns:
            if base.startswith(pattern):
                return True
        return False

    def categorize_symbol(self, symbol: str) -> str:
        """
        Categorize an OpenSSL symbol into its functional group.

        Args:
            symbol: OpenSSL symbol name

        Returns:
            Category name or "other" if not matched
        """
        for category, prefixes in self._categories.items():
            for prefix in prefixes:
                if symbol.startswith(prefix):
                    return category
        return "other"

    def filter_openssl_symbols(self, symbols: List[str]) -> List[str]:
        """
        Filter a list of symbols to only OpenSSL ones.

        Args:
            symbols: List of symbol names

        Returns:
            List containing only OpenSSL symbols.
            Returns empty list if symbols not loaded (discovery mode).
        """
        if not self._openssl_exports:
            return []
        return [s for s in symbols if s in self._openssl_exports]

    def categorize_symbols(self, symbols: List[str]) -> Dict[str, List[str]]:
        """
        Categorize a list of symbols by their OpenSSL category.

        Args:
            symbols: List of symbol names

        Returns:
            Dict mapping category -> list of symbols
        """
        result: Dict[str, List[str]] = {}
        for symbol in self.filter_openssl_symbols(symbols):
            cat = self.categorize_symbol(symbol)
            if cat not in result:
                result[cat] = []
            result[cat].append(symbol)
        return result

    def get_all_exports(self) -> Set[str]:
        """Return all loaded OpenSSL symbols."""
        return self._openssl_exports.copy()

    def get_stats(self) -> Dict[str, any]:
        """Return matcher statistics."""
        return {
            'symbols_loaded': len(self._openssl_exports),
            'libcrypto_path': self._libcrypto_path,
            'libssl_path': self._libssl_path,
        }
