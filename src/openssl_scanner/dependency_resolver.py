"""
Library dependency resolver.

Resolves library paths and builds dependency trees.
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .elf_analyzer import ELFAnalyzer, ELFInfo
from .openssl_matcher import OpenSSLMatcher
from .constants import DEFAULT_SEARCH_PATHS

logger = logging.getLogger(__name__)


def discover_lib_dirs(sysroot: str, max_depth: int = 50) -> List[str]:
    """
    Discover directories containing shared libraries under sysroot.

    Scans recursively (up to max_depth) for directories with .so files.
    Skips non-library directories (python, share, locale, etc.) for speed.

    Args:
        sysroot: Root filesystem path to scan
        max_depth: Maximum directory depth to scan (default: 50)

    Returns:
        List of directory paths containing .so files, sorted by depth
    """
    lib_dirs: Set[str] = set()
    sysroot = os.path.abspath(sysroot)

    if not os.path.isdir(sysroot):
        logger.warning(f"Sysroot not found: {sysroot}")
        return []

    skip_dirs = {
        'python', 'python2', 'python2.7', 'python3', 'python3.8', 'python3.9',
        'python3.10', 'python3.11', 'python3.12', 'python3.13', 'python3.14',
        'site-packages', 'dist-packages', '__pycache__',
        'share', 'locale', 'man', 'doc', 'docs', 'info', 'help',
        'include', 'headers', 'icons', 'themes', 'fonts',
        'src', 'test', 'tests', 'examples', 'samples',
        '.git', '.svn', 'node_modules', 'cargo', 'rustlib',
    }

    base_depth = sysroot.rstrip(os.sep).count(os.sep)

    for root, dirs, files in os.walk(sysroot, followlinks=True):
        current_depth = root.count(os.sep) - base_depth

        if current_depth >= max_depth:
            dirs[:] = []
            continue

        dirs[:] = [d for d in dirs
                   if not d.startswith('.') and d not in skip_dirs]

        for f in files:
            if f.endswith('.so') or '.so.' in f:
                lib_dirs.add(root)
                break

    result = sorted(lib_dirs, key=lambda p: p.count(os.sep))
    logger.info(f"Discovered {len(result)} library directories under {sysroot}")
    return result


@dataclass
class DependencyNode:
    """Node in the dependency tree."""
    name: str
    path: Optional[str]
    is_openssl_lib: bool = False
    openssl_symbols: List[str] = field(default_factory=list)
    children: List['DependencyNode'] = field(default_factory=list)
    error: Optional[str] = None


class DependencyResolver:
    """
    Resolves library dependencies and builds dependency trees.

    Library resolution follows this order:
    1. DT_RPATH from the binary (deprecated)
    2. LD_LIBRARY_PATH environment variable
    3. DT_RUNPATH from the binary
    4. System default paths (/lib, /usr/lib, etc.)
    5. User-specified additional paths

    For OpenHarmony, typical paths include:
    - /system/lib64 (64-bit system libraries)
    - /vendor/lib64 (vendor-specific libraries)
    """

    def __init__(self, search_paths: Optional[List[str]] = None,
                 matcher: Optional[OpenSSLMatcher] = None) -> None:
        self._analyzer = ELFAnalyzer()
        self._matcher = matcher or OpenSSLMatcher()
        self._search_paths = list(search_paths or []) + DEFAULT_SEARCH_PATHS
        self._cache: Dict[str, Optional[str]] = {}
        self._analyzed: Dict[str, ELFInfo] = {}

    def add_search_path(self, path: str) -> None:
        """Add a library search path."""
        if path not in self._search_paths:
            self._search_paths.insert(0, path)

    def resolve_library(self, lib_name: str,
                        rpath: Optional[str] = None,
                        runpath: Optional[str] = None,
                        origin: Optional[str] = None) -> Optional[str]:
        """
        Resolve a library name to its full path.

        Args:
            lib_name: Library name (e.g., "libcrypto.so.3")
            rpath: DT_RPATH from requesting binary
            runpath: DT_RUNPATH from requesting binary
            origin: Directory of the requesting binary ($ORIGIN)

        Returns:
            Full path to the library or None if not found
        """
        cache_key = f"{lib_name}:{rpath}:{runpath}:{origin}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        search_order = []

        if rpath:
            for p in rpath.split(':'):
                p = p.replace('$ORIGIN', origin or '')
                search_order.append(p)

        if runpath:
            for p in runpath.split(':'):
                p = p.replace('$ORIGIN', origin or '')
                search_order.append(p)

        search_order.extend(self._search_paths)

        for dir_path in search_order:
            full_path = os.path.join(dir_path, lib_name)
            if os.path.isfile(full_path):
                self._cache[cache_key] = full_path
                return full_path

        self._cache[cache_key] = None
        return None

    def build_dependency_tree(self, root_path: str,
                               max_depth: int = 20) -> DependencyNode:
        """
        Build a complete dependency tree starting from a root binary.

        Args:
            root_path: Path to the root executable or library
            max_depth: Maximum recursion depth (prevents infinite loops)

        Returns:
            Root DependencyNode with all dependencies as children
        """
        visited: Set[str] = set()
        return self._build_tree_recursive(root_path, visited, max_depth)

    def _build_tree_recursive(self, path: str,
                               visited: Set[str],
                               depth: int) -> DependencyNode:
        """Recursively build dependency tree."""
        name = os.path.basename(path)
        is_openssl = self._matcher.is_openssl_library(name)

        if depth <= 0:
            return DependencyNode(
                name=name,
                path=path,
                is_openssl_lib=is_openssl,
                error="max depth exceeded"
            )

        real_path = os.path.realpath(path) if os.path.exists(path) else path
        if real_path in visited:
            return DependencyNode(
                name=name,
                path=path,
                is_openssl_lib=is_openssl,
                error="circular dependency"
            )

        visited.add(real_path)

        info = self._get_elf_info(path)
        if not info:
            return DependencyNode(
                name=name,
                path=path if os.path.exists(path) else None,
                is_openssl_lib=is_openssl,
                error="not found or invalid ELF"
            )

        openssl_syms = self._matcher.filter_openssl_symbols(
            [s.name for s in info.undefined_symbols]
        )

        node = DependencyNode(
            name=name,
            path=info.path,
            is_openssl_lib=is_openssl,
            openssl_symbols=openssl_syms,
        )

        origin = os.path.dirname(info.path)

        for lib_name in info.needed_libs:
            lib_path = self.resolve_library(
                lib_name,
                rpath=info.rpath,
                runpath=info.runpath,
                origin=origin
            )

            if lib_path:
                child = self._build_tree_recursive(
                    lib_path, visited, depth - 1
                )
            else:
                child = DependencyNode(
                    name=lib_name,
                    path=None,
                    is_openssl_lib=self._matcher.is_openssl_library(lib_name),
                    error="library not found"
                )

            node.children.append(child)

        return node

    def _get_elf_info(self, path: str) -> Optional[ELFInfo]:
        """Get cached ELF info or analyze the file."""
        if path in self._analyzed:
            return self._analyzed[path]

        info = self._analyzer.analyze(path)
        if info:
            self._analyzed[path] = info
        return info

    def get_all_dependencies(self, root_path: str) -> Dict[str, Optional[str]]:
        """
        Get flat dictionary of all dependencies.

        Args:
            root_path: Path to root binary

        Returns:
            Dict mapping library name -> resolved path (or None)
        """
        tree = self.build_dependency_tree(root_path)
        result: Dict[str, Optional[str]] = {}
        self._flatten_tree(tree, result)
        return result

    def _flatten_tree(self, node: DependencyNode,
                       result: Dict[str, Optional[str]]) -> None:
        """Flatten dependency tree to dictionary."""
        if node.name not in result:
            result[node.name] = node.path

        for child in node.children:
            self._flatten_tree(child, result)
