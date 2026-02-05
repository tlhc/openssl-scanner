"""
OpenSSL library auto-discovery module.

Provides unified mechanisms for finding OpenSSL libraries:
- From binary dependency tree
- From directory scan
- From system default paths
"""

import os
import logging
from typing import Optional, Tuple, List

from .constants import DEFAULT_SEARCH_PATHS, OPENSSL_LIBRARY_PATTERNS

logger = logging.getLogger(__name__)


class OpenSSLDiscovery:
    """
    Discovers OpenSSL libraries using multiple strategies.

    Strategies (in order of preference):
    1. From binary's dependency tree (most accurate)
    2. From target directory (for directory scan mode)
    3. From system default paths (fallback)
    """

    def __init__(self, additional_paths: Optional[List[str]] = None) -> None:
        self._additional_paths = additional_paths or []

    def discover_from_binary(self, binary_path: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Discover OpenSSL libraries from a binary's dependency tree.

        Args:
            binary_path: Path to the ELF binary

        Returns:
            Tuple of (libcrypto_path, libssl_path)
        """
        from .scanner import Scanner

        scanner = Scanner(search_paths=self._additional_paths, workers=1)
        binary_dir = os.path.dirname(binary_path)
        scanner.add_search_path(binary_dir)

        return scanner.find_openssl_libraries(binary_path)

    def discover_from_directory(self, dir_path: str,
                                 recursive: bool = True) -> Tuple[Optional[str], Optional[str]]:
        """
        Discover OpenSSL libraries by scanning a directory.

        Args:
            dir_path: Directory to search
            recursive: Whether to search subdirectories

        Returns:
            Tuple of (libcrypto_path, libssl_path)
        """
        libcrypto = None
        libssl = None

        for root, dirs, files in os.walk(dir_path):
            for name in files:
                name_lower = name.lower()
                if not self._is_openssl_lib_name(name_lower):
                    continue

                full_path = os.path.join(root, name)
                if 'crypto' in name_lower and not libcrypto:
                    libcrypto = full_path
                elif 'ssl' in name_lower and not libssl:
                    libssl = full_path

            if not recursive:
                break
            if libcrypto and libssl:
                break

        return libcrypto, libssl

    def discover_from_system(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Discover OpenSSL libraries from system default paths.

        Returns:
            Tuple of (libcrypto_path, libssl_path)
        """
        libcrypto = None
        libssl = None

        search_paths = self._additional_paths + DEFAULT_SEARCH_PATHS

        for search_dir in search_paths:
            if not os.path.isdir(search_dir):
                continue
            try:
                for name in os.listdir(search_dir):
                    name_lower = name.lower()
                    if not self._is_openssl_lib_name(name_lower):
                        continue

                    full_path = os.path.join(search_dir, name)
                    if not os.path.isfile(full_path):
                        continue

                    if 'crypto' in name_lower and not libcrypto:
                        libcrypto = full_path
                    elif 'ssl' in name_lower and not libssl:
                        libssl = full_path
            except PermissionError:
                continue

            if libcrypto and libssl:
                break

        return libcrypto, libssl

    def discover(self, target: str, is_directory: bool = False,
                 recursive: bool = True) -> Tuple[Optional[str], Optional[str]]:
        """
        Unified discovery method that tries multiple strategies.

        Args:
            target: Path to binary or directory
            is_directory: Whether target is a directory
            recursive: For directory mode, whether to search subdirs

        Returns:
            Tuple of (libcrypto_path, libssl_path)
        """
        libcrypto = None
        libssl = None

        if is_directory:
            logger.debug("Discovering OpenSSL in directory: %s", target)
            libcrypto, libssl = self.discover_from_directory(target, recursive)
        else:
            logger.debug("Discovering OpenSSL from binary dependencies: %s", target)
            libcrypto, libssl = self.discover_from_binary(target)

        if not libcrypto:
            logger.debug("Falling back to system path discovery")
            libcrypto, libssl = self.discover_from_system()

        return libcrypto, libssl

    def discover_from_libraries(self, lib_paths: List[str]) -> Tuple[Optional[str], Optional[str]]:
        """
        Discover OpenSSL libraries from a list of library paths.

        Used in process scan mode where we have the exact list of
        loaded libraries from /proc/pid/maps.

        Args:
            lib_paths: List of absolute paths to shared libraries

        Returns:
            Tuple of (libcrypto_path, libssl_path)
        """
        libcrypto = None
        libssl = None
        for path in lib_paths:
            basename = os.path.basename(path).lower()
            if not self._is_openssl_lib_name(basename):
                continue
            if 'crypto' in basename and not libcrypto:
                libcrypto = path
            elif 'ssl' in basename and not libssl:
                libssl = path
        return libcrypto, libssl

    def _is_openssl_lib_name(self, name: str) -> bool:
        """Check if filename matches OpenSSL library pattern."""
        if '.so' not in name:
            return False
        for pattern in OPENSSL_LIBRARY_PATTERNS:
            if name.startswith(pattern):
                return True
        return False
