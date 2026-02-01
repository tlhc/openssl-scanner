"""
Core scanner implementation.

Orchestrates ELF analysis, dependency resolution, and symbol matching.
"""

import os
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from .elf_analyzer import ELFAnalyzer, ELFInfo
from .dependency_resolver import DependencyResolver, DependencyNode
from .dependency_graph import DependencyGraph, ImportChain, DepthInfo
from .openssl_matcher import OpenSSLMatcher
from . import __version__

logger = logging.getLogger(__name__)


@dataclass
class FileResult:
    """Scan result for a single file."""
    path: str
    file_type: str  # executable, shared_library, or unknown
    arch: str
    direct_deps: List[str]
    openssl_direct: bool
    openssl_transitive: bool
    openssl_libs: List[str]
    openssl_symbols: List[str]
    error: Optional[str] = None


@dataclass
class ScanResult:
    """Complete scan result."""
    target: str
    scan_time: str
    tool_version: str
    arch: str
    report_type: str = "single"  # "single" or "aggregated"

    total_files_scanned: int = 0
    total_elf_files: int = 0
    files_with_openssl: int = 0

    openssl_libs_found: List[str] = field(default_factory=list)
    dependency_tree: Optional[DependencyNode] = None

    files_detail: List[FileResult] = field(default_factory=list)
    symbols_by_file: Dict[str, List[str]] = field(default_factory=dict)
    symbols_by_category: Dict[str, List[str]] = field(default_factory=dict)
    all_unique_symbols: List[str] = field(default_factory=list)

    # Dependency analysis (tree scan mode)
    symbols_by_depth: Dict[int, List[str]] = field(default_factory=dict)
    import_chains: Dict[str, List[str]] = field(default_factory=dict)

    # Dependency analysis (directory scan mode) - richer format
    import_chains_detail: Dict[str, List[ImportChain]] = field(default_factory=dict)
    depth_info: Dict[int, DepthInfo] = field(default_factory=dict)
    dependency_edges: List[tuple] = field(default_factory=list)

    errors: List[Dict[str, str]] = field(default_factory=list)


class Scanner:
    """
    Main scanner class that coordinates all analysis.

    Supports two modes:
    1. Tree mode: Start from a binary and recursively scan dependencies
    2. Directory mode: Scan all ELF files in a directory

    Uses thread pool for parallel file analysis.
    """

    def __init__(self,
                 search_paths: Optional[List[str]] = None,
                 workers: int = 4,
                 matcher: Optional[OpenSSLMatcher] = None) -> None:
        self._analyzer = ELFAnalyzer()
        self._matcher = matcher or OpenSSLMatcher()
        self._resolver = DependencyResolver(search_paths, matcher=self._matcher)
        self._workers = workers

    def add_search_path(self, path: str) -> None:
        """Add library search path."""
        self._resolver.add_search_path(path)

    def find_openssl_libraries(self, root_path: str) -> tuple:
        """
        Find OpenSSL libraries (libcrypto, libssl) from dependency tree.

        Performs a preliminary dependency scan to locate OpenSSL libraries
        that the target binary depends on.

        Args:
            root_path: Path to root executable or library

        Returns:
            Tuple of (libcrypto_path, libssl_path), either can be None
        """
        tree = self._resolver.build_dependency_tree(root_path)
        return self._collect_openssl_libs(tree)

    def _collect_openssl_libs(self, node: DependencyNode) -> tuple:
        """Recursively find OpenSSL libraries in dependency tree."""
        libcrypto = None
        libssl = None

        if node.is_openssl_lib and node.path:
            name_lower = node.name.lower()
            if 'crypto' in name_lower:
                libcrypto = node.path
            elif 'ssl' in name_lower:
                libssl = node.path

        for child in node.children:
            child_crypto, child_ssl = self._collect_openssl_libs(child)
            if child_crypto and not libcrypto:
                libcrypto = child_crypto
            if child_ssl and not libssl:
                libssl = child_ssl

        return libcrypto, libssl

    def scan_file(self, path: str) -> FileResult:
        """
        Scan a single ELF file.

        Args:
            path: Path to ELF file

        Returns:
            FileResult with analysis results
        """
        if not os.path.isfile(path):
            return FileResult(
                path=path,
                file_type='unknown',
                arch='unknown',
                direct_deps=[],
                openssl_direct=False,
                openssl_transitive=False,
                openssl_libs=[],
                openssl_symbols=[],
                error='File not found'
            )

        info = self._analyzer.analyze(path)
        if not info:
            return FileResult(
                path=path,
                file_type='unknown',
                arch='unknown',
                direct_deps=[],
                openssl_direct=False,
                openssl_transitive=False,
                openssl_libs=[],
                openssl_symbols=[],
                error='Not a valid ELF file'
            )

        openssl_symbols = self._matcher.filter_openssl_symbols(
            [s.name for s in info.undefined_symbols]
        )

        openssl_libs = [lib for lib in info.needed_libs
                        if self._matcher.is_openssl_library(lib)]
        openssl_direct = len(openssl_libs) > 0

        return FileResult(
            path=path,
            file_type=info.elf_type,
            arch=info.arch,
            direct_deps=info.needed_libs,
            openssl_direct=openssl_direct,
            openssl_transitive=False,  # Set later in tree scan
            openssl_libs=openssl_libs,
            openssl_symbols=openssl_symbols,
        )

    def scan_tree(self, root_path: str) -> ScanResult:
        """
        Scan from a root binary, following all dependencies.

        Args:
            root_path: Path to starting executable or library

        Returns:
            Complete ScanResult
        """
        result = self._create_result(root_path)

        tree = self._resolver.build_dependency_tree(root_path)
        result.dependency_tree = tree

        all_paths = self._collect_tree_paths(tree)
        result.total_files_scanned = len(all_paths)

        arch = None
        files: List[FileResult] = []
        all_symbols: Set[str] = set()
        symbols_by_file: Dict[str, List[str]] = {}
        openssl_libs: Set[str] = set()

        with ThreadPoolExecutor(max_workers=self._workers) as executor:
            future_to_path = {
                executor.submit(self.scan_file, p): p
                for p in all_paths if p
            }

            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    file_result = future.result()
                    files.append(file_result)

                    if file_result.arch != 'unknown' and not arch:
                        arch = file_result.arch

                    if file_result.openssl_symbols:
                        symbols_by_file[file_result.path] = file_result.openssl_symbols
                        all_symbols.update(file_result.openssl_symbols)

                    for lib in file_result.openssl_libs:
                        resolved = self._resolver.resolve_library(lib)
                        if resolved:
                            openssl_libs.add(resolved)

                except Exception as e:
                    logger.error(f"Error scanning {path}: {e}")
                    result.errors.append({
                        'file': path,
                        'error': str(e),
                        'severity': 'error'
                    })

        result.total_elf_files = len([f for f in files if f.file_type != 'unknown'])
        result.files_with_openssl = len([f for f in files if f.openssl_symbols])
        result.files_detail = files
        result.symbols_by_file = symbols_by_file
        result.all_unique_symbols = sorted(all_symbols)
        result.openssl_libs_found = sorted(openssl_libs)
        result.arch = arch or 'unknown'

        result.symbols_by_category = self._matcher.categorize_symbols(
            list(all_symbols)
        )

        self._mark_transitive_deps(result)
        self._compute_symbols_by_depth(result)
        self._compute_import_chains(result)

        return result

    def scan_directory(self, dir_path: str, recursive: bool = True) -> ScanResult:
        """
        Scan all ELF files in a directory.

        Args:
            dir_path: Directory to scan
            recursive: Whether to scan subdirectories

        Returns:
            Complete ScanResult
        """
        result = self._create_result(dir_path)

        elf_files = []
        total_files = 0

        for root, dirs, files in os.walk(dir_path):
            for name in files:
                total_files += 1
                path = os.path.join(root, name)
                if self._analyzer.is_elf_file(path):
                    elf_files.append(path)

            if not recursive:
                dirs.clear()

        result.total_files_scanned = total_files

        arch = None
        file_results: List[FileResult] = []
        all_symbols: Set[str] = set()
        symbols_by_file: Dict[str, List[str]] = {}
        openssl_libs: Set[str] = set()

        with ThreadPoolExecutor(max_workers=self._workers) as executor:
            future_to_path = {
                executor.submit(self.scan_file, p): p
                for p in elf_files
            }

            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    file_result = future.result()
                    file_results.append(file_result)

                    if file_result.arch != 'unknown' and not arch:
                        arch = file_result.arch

                    if file_result.openssl_symbols:
                        symbols_by_file[file_result.path] = file_result.openssl_symbols
                        all_symbols.update(file_result.openssl_symbols)

                    for lib in file_result.openssl_libs:
                        resolved = self._resolver.resolve_library(lib)
                        if resolved:
                            openssl_libs.add(resolved)
                        else:
                            openssl_libs.add(lib)

                except Exception as e:
                    logger.error(f"Error scanning {path}: {e}")
                    result.errors.append({
                        'file': path,
                        'error': str(e),
                        'severity': 'error'
                    })

        result.total_elf_files = len(file_results)
        result.files_with_openssl = len([f for f in file_results if f.openssl_symbols])
        result.files_detail = file_results
        result.symbols_by_file = symbols_by_file
        result.all_unique_symbols = sorted(all_symbols)
        result.openssl_libs_found = sorted(openssl_libs)
        result.arch = arch or 'unknown'

        result.symbols_by_category = self._matcher.categorize_symbols(
            list(all_symbols)
        )

        self._compute_dependency_graph(result, file_results, openssl_libs)

        return result

    def _compute_dependency_graph(self, result: ScanResult,
                                   file_results: List[FileResult],
                                   openssl_libs: Set[str]) -> None:
        """
        Build dependency graph and compute import chains for directory scan.

        Adds import_chains_detail, depth_info, and dependency_edges to result.
        """
        logger.info("Building dependency graph...")

        graph = DependencyGraph(self._matcher)

        for lib_path in openssl_libs:
            graph.add_openssl_lib(lib_path)

        for fr in file_results:
            if fr.error:
                continue
            graph.add_file(fr.path, fr.direct_deps, fr.openssl_symbols)

        logger.info(f"Graph stats: {graph.get_stats()}")

        logger.info("Computing import chains...")
        result.import_chains_detail = graph.compute_import_chains()

        logger.info("Computing depth info...")
        result.depth_info = graph.compute_by_depth()

        result.dependency_edges = graph.get_edges()

        self._convert_to_legacy_format(result)

        logger.info(f"Found {len(result.import_chains_detail)} symbols with import chains")

    def _convert_to_legacy_format(self, result: ScanResult) -> None:
        """
        Convert detailed import chains to legacy format for backward compatibility.

        Legacy format: symbol -> list of chain strings
        """
        for symbol, chains in result.import_chains_detail.items():
            result.import_chains[symbol] = [
                c.chain for c in chains
            ]

        for depth, info in result.depth_info.items():
            result.symbols_by_depth[depth] = info.symbols

    def _create_result(self, target: str) -> ScanResult:
        """Create initial ScanResult."""
        return ScanResult(
            target=target,
            scan_time=datetime.now().isoformat(),
            tool_version=__version__,
            arch='unknown',
        )

    def _collect_tree_paths(self, node: DependencyNode) -> List[str]:
        """Collect all file paths from dependency tree."""
        paths: Set[str] = set()
        self._collect_paths_recursive(node, paths)
        return list(paths)

    def _collect_paths_recursive(self, node: DependencyNode,
                                   paths: Set[str]) -> None:
        """Recursively collect paths."""
        if node.path:
            paths.add(node.path)
        for child in node.children:
            self._collect_paths_recursive(child, paths)

    def _mark_transitive_deps(self, result: ScanResult) -> None:
        """Mark files with transitive OpenSSL dependencies."""
        if not result.dependency_tree:
            return

        openssl_paths = self._find_openssl_paths(result.dependency_tree)

        for file_result in result.files_detail:
            if not file_result.openssl_direct and file_result.path:
                file_result.openssl_transitive = self._has_transitive_openssl(
                    file_result.path, openssl_paths, result.dependency_tree
                )

    def _find_openssl_paths(self, node: DependencyNode) -> Set[str]:
        """Find all paths to OpenSSL libraries in tree."""
        result: Set[str] = set()
        if node.is_openssl_lib and node.path:
            result.add(node.path)
        for child in node.children:
            result.update(self._find_openssl_paths(child))
        return result

    def _has_transitive_openssl(self, path: str,
                                 openssl_paths: Set[str],
                                 tree: DependencyNode) -> bool:
        """Check if path has transitive OpenSSL dependency."""
        return len(openssl_paths) > 0

    def _compute_symbols_by_depth(self, result: ScanResult) -> None:
        """
        Compute symbols grouped by dependency depth.

        Depth 0: root binary
        Depth 1: direct dependencies
        Depth 2+: transitive dependencies
        """
        if not result.dependency_tree:
            return

        depth_symbols: Dict[int, Set[str]] = {}
        self._collect_symbols_by_depth(result.dependency_tree, 0, depth_symbols)

        result.symbols_by_depth = {
            depth: sorted(symbols)
            for depth, symbols in sorted(depth_symbols.items())
        }

    def _collect_symbols_by_depth(self, node: DependencyNode, depth: int,
                                   depth_symbols: Dict[int, Set[str]]) -> None:
        """Recursively collect symbols at each depth level."""
        if node.openssl_symbols:
            if depth not in depth_symbols:
                depth_symbols[depth] = set()
            depth_symbols[depth].update(node.openssl_symbols)

        for child in node.children:
            if child.error != "circular dependency":
                self._collect_symbols_by_depth(child, depth + 1, depth_symbols)

    def _compute_import_chains(self, result: ScanResult) -> None:
        """
        Compute import chains from root to each OpenSSL symbol.

        For each symbol, records the path(s) through which it is imported.
        Example: "SSL_connect" -> ["curl -> libcurl.so.4 -> libssl.so.3"]
        """
        if not result.dependency_tree:
            return

        chains: Dict[str, List[str]] = {}
        root_name = result.dependency_tree.name
        self._collect_import_chains(result.dependency_tree, [root_name], chains)

        result.import_chains = {
            symbol: sorted(set(paths))
            for symbol, paths in sorted(chains.items())
        }

    def _collect_import_chains(self, node: DependencyNode, path: List[str],
                                chains: Dict[str, List[str]]) -> None:
        """Recursively collect import chains for each symbol."""
        if node.openssl_symbols:
            chain_str = " -> ".join(path)
            for symbol in node.openssl_symbols:
                if symbol not in chains:
                    chains[symbol] = []
                chains[symbol].append(chain_str)

        for child in node.children:
            if child.error != "circular dependency":
                child_path = path + [child.name]
                self._collect_import_chains(child, child_path, chains)
