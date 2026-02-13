"""
Core scanner implementation.

Orchestrates ELF analysis, dependency resolution, and symbol matching.
"""

import os
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set
from concurrent.futures import ProcessPoolExecutor, as_completed

from .elf_analyzer import ELFAnalyzer, ELFInfo
from .dependency_resolver import DependencyResolver, DependencyNode
from .dependency_graph import DependencyGraph, ImportChain, DepthInfo
from .openssl_matcher import OpenSSLMatcher
from .constants import OPENSSL_LIBRARY_PATTERNS
from . import __version__

logger = logging.getLogger(__name__)


def _analyze_file_worker(args: tuple) -> 'FileResult':
    """
    Worker function for parallel file analysis.

    Must be at module level for ProcessPoolExecutor pickling.
    """
    path, openssl_exports = args
    analyzer = ELFAnalyzer()

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

    info = analyzer.analyze(path)
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

    undefined_names = [s.name for s in info.undefined_symbols]
    openssl_symbols = [s for s in undefined_names if s in openssl_exports]

    defined_names = [s.name for s in info.defined_symbols]
    openssl_defined = [s for s in defined_names if s in openssl_exports]

    openssl_lib_patterns = ('libcrypto', 'libssl', 'libopenssl')
    openssl_libs = [lib for lib in info.needed_libs
                    if any(lib.lower().startswith(p) for p in openssl_lib_patterns)]
    openssl_direct = len(openssl_libs) > 0

    static_openssl = False
    # Check if we define OpenSSL symbols that we don't import (implies implementation)
    implemented_openssl = set(openssl_defined) - set(openssl_symbols)
    if implemented_openssl:
        logger.debug(
            "static OpenSSL %s: implemented=%d needed=%s",
            os.path.basename(path), len(implemented_openssl), info.needed_libs)
        
        # We consider it static OpenSSL if it implements symbols, even if it also imports some
        if not openssl_symbols:
            openssl_symbols = openssl_defined
        else:
            # Hybrid case: add implemented symbols to the list of "used" symbols
            for s in openssl_defined:
                if s not in openssl_symbols:
                    openssl_symbols.append(s)
        
        openssl_direct = True
        static_openssl = True

    uses_dlopen = False
    dlsym_symbols = []
    dlopen_libs = []
    dlopen_confidence = 'high'

    if info.has_dlopen or info.has_dlsym:
        from .dlopen_analyzer import detect_dlopen_openssl
        exclude_ossl = set(openssl_symbols) | set(openssl_defined)
        dlopen_result = detect_dlopen_openssl(path, openssl_exports,
                                               OPENSSL_LIBRARY_PATTERNS,
                                               exclude_symbols=exclude_ossl)
        if dlopen_result:
            dlopen_libs = dlopen_result.dlopen_libs
            if not openssl_direct or dlopen_libs:
                uses_dlopen = True
                dlopen_confidence = dlopen_result.confidence
                direct_set = set(openssl_symbols)
                dlsym_symbols = [s for s in dlopen_result.dlsym_symbols
                                 if s not in direct_set]
                overlap = len(dlopen_result.dlsym_symbols) - len(dlsym_symbols)
                logger.debug(
                    "dlopen classify %s: UND_ossl=%d rodata_ossl=%d "
                    "overlap=%d dlopen_only=%d direct=%s libs=%s conf=%s",
                    os.path.basename(path), len(openssl_symbols),
                    len(dlopen_result.dlsym_symbols), overlap,
                    len(dlsym_symbols), openssl_direct, dlopen_libs,
                    dlopen_confidence)
                openssl_symbols.extend(dlsym_symbols)
            elif dlopen_result.dlsym_symbols:
                logger.debug(
                    "dlopen skip %s: direct OpenSSL link + no lib "
                    "patterns in .rodata, ignoring %d matches",
                    os.path.basename(path),
                    len(dlopen_result.dlsym_symbols))

    return FileResult(
        path=path,
        file_type=info.elf_type,
        arch=info.arch,
        direct_deps=info.needed_libs,
        openssl_direct=openssl_direct,
        openssl_transitive=False,
        openssl_libs=openssl_libs,
        openssl_symbols=openssl_symbols,
        static_openssl=static_openssl,
        uses_dlopen=uses_dlopen,
        dlsym_symbols=dlsym_symbols,
        dlopen_libs=dlopen_libs,
        dlopen_confidence=dlopen_confidence,
    )


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
    static_openssl: bool = False
    uses_dlopen: bool = False
    dlsym_symbols: List[str] = field(default_factory=list)
    dlopen_libs: List[str] = field(default_factory=list)
    dlopen_confidence: str = 'high'


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

    # Process scan mode
    process_info: Optional[Dict] = None

    # Package scan mode
    package_info: Optional[Dict] = None

    # Static OpenSSL detection
    files_with_static_openssl: int = 0

    # dlopen/dlsym detection
    files_with_dlopen: int = 0
    dlsym_symbols_by_file: Dict[str, List[str]] = field(default_factory=dict)
    all_dlsym_symbols: List[str] = field(default_factory=list)
    dlopen_libs_detected: List[str] = field(default_factory=list)


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

        openssl_defined = self._matcher.filter_openssl_symbols(
            [s.name for s in info.defined_symbols]
        )

        openssl_libs = [lib for lib in info.needed_libs
                        if self._matcher.is_openssl_library(lib)]
        openssl_direct = len(openssl_libs) > 0

        static_openssl = False
        # Check if we define OpenSSL symbols that we don't import (implies implementation)
        implemented_openssl = set(openssl_defined) - set(openssl_symbols)
        if implemented_openssl:
            logger.debug(
                "static OpenSSL %s: implemented=%d needed=%s",
                os.path.basename(path), len(implemented_openssl), info.needed_libs)
            
            # We consider it static OpenSSL if it implements symbols, even if it also imports some
            if not openssl_symbols:
                openssl_symbols = openssl_defined
            else:
                # Hybrid case: add implemented symbols to the list of "used" symbols
                for s in openssl_defined:
                    if s not in openssl_symbols:
                        openssl_symbols.append(s)
            
            openssl_direct = True
            static_openssl = True

        uses_dlopen = False
        dlsym_symbols = []
        dlopen_libs = []
        dlopen_confidence = 'high'

        if info.has_dlopen or info.has_dlsym:
            from .dlopen_analyzer import detect_dlopen_openssl
            openssl_exports = self._matcher.get_openssl_exports()
            exclude_ossl = set(openssl_symbols) | set(openssl_defined)
            dlopen_result = detect_dlopen_openssl(path, openssl_exports,
                                                   OPENSSL_LIBRARY_PATTERNS,
                                                   exclude_symbols=exclude_ossl)
            if dlopen_result:
                dlopen_libs = dlopen_result.dlopen_libs
                if not openssl_direct or dlopen_libs:
                    uses_dlopen = True
                    dlopen_confidence = dlopen_result.confidence
                    direct_set = set(openssl_symbols)
                    dlsym_symbols = [s for s in dlopen_result.dlsym_symbols
                                     if s not in direct_set]
                    overlap = len(dlopen_result.dlsym_symbols) - len(dlsym_symbols)
                    logger.debug(
                        "dlopen classify %s: UND_ossl=%d rodata_ossl=%d "
                        "overlap=%d dlopen_only=%d direct=%s libs=%s conf=%s",
                        os.path.basename(path), len(openssl_symbols),
                        len(dlopen_result.dlsym_symbols), overlap,
                        len(dlsym_symbols), openssl_direct, dlopen_libs,
                        dlopen_confidence)
                    openssl_symbols.extend(dlsym_symbols)
                elif dlopen_result.dlsym_symbols:
                    logger.debug(
                        "dlopen skip %s: direct OpenSSL link + no lib "
                        "patterns in .rodata, ignoring %d matches",
                        os.path.basename(path),
                        len(dlopen_result.dlsym_symbols))

        return FileResult(
            path=path,
            file_type=info.elf_type,
            arch=info.arch,
            direct_deps=info.needed_libs,
            openssl_direct=openssl_direct,
            openssl_transitive=False,
            openssl_libs=openssl_libs,
            openssl_symbols=openssl_symbols,
            static_openssl=static_openssl,
            uses_dlopen=uses_dlopen,
            dlsym_symbols=dlsym_symbols,
            dlopen_libs=dlopen_libs,
            dlopen_confidence=dlopen_confidence,
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

        openssl_exports = self._matcher.get_openssl_exports()
        work_items = [(p, openssl_exports) for p in all_paths if p]

        with ProcessPoolExecutor(max_workers=self._workers) as executor:
            future_to_path = {
                executor.submit(_analyze_file_worker, item): item[0]
                for item in work_items
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
        self._aggregate_dlopen(result)

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

        openssl_exports = self._matcher.get_openssl_exports()
        work_items = [(p, openssl_exports) for p in elf_files]

        with ProcessPoolExecutor(max_workers=self._workers) as executor:
            future_to_path = {
                executor.submit(_analyze_file_worker, item): item[0]
                for item in work_items
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
        self._aggregate_dlopen(result)

        return result

    def scan_process(self, process_info, dependency_tree=None) -> ScanResult:
        """
        Scan a running process's loaded libraries for OpenSSL dependencies.

        Uses library paths from /proc/<pid>/maps (populated in process_info).
        Optionally cross-references with a DT_NEEDED dependency tree to
        identify dlopen-loaded libraries (runtime_only).

        Args:
            process_info: ProcessInfo from proc_analyzer with mapped_libraries
            dependency_tree: Optional DependencyNode tree for hierarchy enrichment

        Returns:
            Complete ScanResult with report_type="process"
        """
        result = self._create_result(process_info.exe_path)
        result.report_type = "process"

        scan_paths = []
        deleted_libs = []

        if process_info.exe_path and os.path.isfile(process_info.exe_path):
            scan_paths.append(process_info.exe_path)

        for lib in process_info.mapped_libraries:
            if lib.deleted:
                deleted_libs.append(lib.path)
                logger.warning("Skipping deleted library: %s", lib.path)
                continue
            if os.path.isfile(lib.path):
                scan_paths.append(lib.path)
            else:
                logger.warning("Library not accessible: %s", lib.path)

        if dependency_tree:
            tree_paths = set()
            self._collect_paths_recursive(dependency_tree, tree_paths)
            tree_realpaths = set()
            for tp in tree_paths:
                try:
                    tree_realpaths.add(os.path.realpath(tp))
                except OSError:
                    tree_realpaths.add(tp)
            for lib in process_info.mapped_libraries:
                try:
                    real = os.path.realpath(lib.path)
                except OSError:
                    real = lib.path
                if real not in tree_realpaths and lib.path not in tree_paths:
                    lib.runtime_only = True

        result.dependency_tree = dependency_tree
        result.total_files_scanned = len(scan_paths)

        arch = None
        files: List[FileResult] = []
        all_symbols: Set[str] = set()
        symbols_by_file: Dict[str, List[str]] = {}
        openssl_libs: Set[str] = set()

        openssl_exports = self._matcher.get_openssl_exports()
        work_items = [(p, openssl_exports) for p in scan_paths]

        with ProcessPoolExecutor(max_workers=self._workers) as executor:
            future_to_path = {
                executor.submit(_analyze_file_worker, item): item[0]
                for item in work_items
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
                    logger.error("Error scanning %s: %s", path, e)
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

        if dependency_tree:
            self._mark_transitive_deps(result)
            self._compute_symbols_by_depth(result)
            self._compute_import_chains(result)

        self._aggregate_dlopen(result)

        runtime_libs = [lib.basename for lib in process_info.mapped_libraries
                        if lib.runtime_only]
        result.process_info = {
            'pid': process_info.pid,
            'name': process_info.name,
            'exe_path': process_info.exe_path,
            'cmdline': process_info.cmdline,
            'uid': process_info.uid,
            'threads': process_info.threads,
            'vm_rss_kb': process_info.vm_rss_kb,
            'mapped_libraries_count': len(process_info.mapped_libraries),
            'runtime_loaded_count': len(runtime_libs),
            'runtime_loaded_libs': runtime_libs,
            'deleted_libraries': deleted_libs,
        }

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

    @staticmethod
    def _aggregate_dlopen(result: ScanResult) -> None:
        """Aggregate dlopen and static detection results from file results."""
        dlsym_symbols_by_file: Dict[str, List[str]] = {}
        all_dlsym_set: Set[str] = set()
        dlopen_libs_set: Set[str] = set()
        files_with_dlopen = 0
        files_with_static_openssl = 0

        for fr in result.files_detail:
            if fr.static_openssl:
                files_with_static_openssl += 1
            if fr.uses_dlopen:
                files_with_dlopen += 1
            if fr.dlsym_symbols:
                dlsym_symbols_by_file[fr.path] = fr.dlsym_symbols
                all_dlsym_set.update(fr.dlsym_symbols)
            for lib in fr.dlopen_libs:
                dlopen_libs_set.add(lib)

        result.files_with_static_openssl = files_with_static_openssl
        result.files_with_dlopen = files_with_dlopen
        result.dlsym_symbols_by_file = dlsym_symbols_by_file
        result.all_dlsym_symbols = sorted(all_dlsym_set)
        result.dlopen_libs_detected = sorted(dlopen_libs_set)

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
