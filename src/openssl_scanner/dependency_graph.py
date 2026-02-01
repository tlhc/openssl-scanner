"""
Dependency graph for directory scan mode.

Builds a graph from DT_NEEDED relationships and computes
paths to OpenSSL libraries for import chain analysis.
"""

import os
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ImportChain:
    """A single import chain for a symbol."""
    source_file: str
    chain: str
    depth: int


@dataclass
class DepthInfo:
    """Symbols at a specific depth from OpenSSL."""
    count: int
    symbols: List[str]
    files: List[str]


class DependencyGraph:
    """
    Builds and analyzes dependency relationships between ELF files.

    Used in directory scan mode to compute:
    - Import chains (how each file reaches OpenSSL)
    - Depth analysis (distance from OpenSSL)
    - Dependency edges for visualization
    """

    def __init__(self, openssl_matcher) -> None:
        self._matcher = openssl_matcher

        self._adjacency: Dict[str, List[str]] = {}
        self._reverse: Dict[str, List[str]] = {}

        self._file_to_path: Dict[str, str] = {}
        self._path_to_symbols: Dict[str, List[str]] = {}

        self._openssl_libs: Set[str] = set()

        self._path_cache: Dict[str, List[List[str]]] = {}

    def add_file(self, path: str, direct_deps: List[str],
                 openssl_symbols: List[str]) -> None:
        """
        Add a file and its dependencies to the graph.

        Args:
            path: Full path to the ELF file
            direct_deps: List of DT_NEEDED library names
            openssl_symbols: OpenSSL symbols used by this file
        """
        basename = os.path.basename(path)

        self._file_to_path[basename] = path
        self._file_to_path[path] = path

        self._path_to_symbols[path] = openssl_symbols

        if self._matcher.is_openssl_library(basename):
            self._openssl_libs.add(path)
            self._openssl_libs.add(basename)

        self._adjacency[path] = direct_deps
        for dep in direct_deps:
            self._reverse.setdefault(dep, []).append(path)

    def add_openssl_lib(self, lib_path: str) -> None:
        """Register an OpenSSL library path."""
        self._openssl_libs.add(lib_path)
        self._openssl_libs.add(os.path.basename(lib_path))

    def find_all_paths_to_openssl(self, source: str,
                                   max_depth: int = 10) -> List[List[str]]:
        """
        Find ALL paths from source file to any OpenSSL library.

        Uses BFS to find all paths up to max_depth.

        Args:
            source: Starting file path or name
            max_depth: Maximum path length to search

        Returns:
            List of paths, each path is a list of file names
        """
        source_path = self._file_to_path.get(source, source)

        if source_path in self._path_cache:
            return self._path_cache[source_path]

        all_paths: List[List[str]] = []

        queue: deque = deque()
        queue.append((source_path, [os.path.basename(source_path)], set([source_path])))

        while queue:
            current, path, visited = queue.popleft()

            if len(path) > max_depth:
                continue

            deps = self._adjacency.get(current, [])
            for dep in deps:
                dep_basename = os.path.basename(dep) if '/' in dep else dep

                if dep in self._openssl_libs or dep_basename in self._openssl_libs:
                    complete_path = path + [dep_basename]
                    all_paths.append(complete_path)
                    continue

                resolved = self._resolve_dep(dep, current)
                if resolved and resolved not in visited:
                    new_visited = visited | {resolved}
                    queue.append((resolved, path + [dep_basename], new_visited))

        self._path_cache[source_path] = all_paths
        return all_paths

    def _resolve_dep(self, dep_name: str, from_file: str) -> Optional[str]:
        """
        Resolve a dependency name to a full path.

        First checks if we've seen this file in the scan,
        then tries common system paths.
        """
        if dep_name in self._file_to_path:
            return self._file_to_path[dep_name]

        if '/' in dep_name and os.path.isfile(dep_name):
            return dep_name

        from_dir = os.path.dirname(from_file)
        local_path = os.path.join(from_dir, dep_name)
        if os.path.isfile(local_path):
            self._file_to_path[dep_name] = local_path
            return local_path

        return None

    def compute_import_chains(self) -> Dict[str, List[ImportChain]]:
        """
        Compute import chains for all symbols.

        Returns:
            Dict mapping symbol name to list of ImportChain objects
        """
        import_chains: Dict[str, List[ImportChain]] = {}

        for file_path, symbols in self._path_to_symbols.items():
            if not symbols:
                continue

            paths = self.find_all_paths_to_openssl(file_path)
            if not paths:
                continue

            for symbol in symbols:
                if symbol not in import_chains:
                    import_chains[symbol] = []

                for path in paths:
                    chain_str = " -> ".join(path)
                    depth = len(path) - 1

                    import_chains[symbol].append(ImportChain(
                        source_file=file_path,
                        chain=chain_str,
                        depth=depth
                    ))

        return import_chains

    def compute_by_depth(self) -> Dict[int, DepthInfo]:
        """
        Compute symbols grouped by their depth from OpenSSL.

        Depth is the minimum distance from any file using the symbol
        to an OpenSSL library.

        Returns:
            Dict mapping depth to DepthInfo
        """
        depth_data: Dict[int, Dict] = {}

        for file_path, symbols in self._path_to_symbols.items():
            if not symbols:
                continue

            paths = self.find_all_paths_to_openssl(file_path)
            if not paths:
                continue

            min_depth = min(len(p) - 1 for p in paths)

            if min_depth not in depth_data:
                depth_data[min_depth] = {
                    'symbols': set(),
                    'files': set()
                }

            depth_data[min_depth]['symbols'].update(symbols)
            depth_data[min_depth]['files'].add(file_path)

        return {
            depth: DepthInfo(
                count=len(data['symbols']),
                symbols=sorted(data['symbols']),
                files=sorted(data['files'])
            )
            for depth, data in sorted(depth_data.items())
        }

    def get_edges(self) -> List[Tuple[str, str]]:
        """
        Get all dependency edges for visualization.

        Returns:
            List of (from_file, to_file) tuples
        """
        edges = []
        for source, deps in self._adjacency.items():
            for dep in deps:
                edges.append((os.path.basename(source), dep))
        return edges

    def get_stats(self) -> Dict:
        """Get graph statistics."""
        return {
            'total_nodes': len(self._adjacency),
            'total_edges': sum(len(deps) for deps in self._adjacency.values()),
            'openssl_libs': len(self._openssl_libs),
            'files_with_symbols': len([p for p, s in self._path_to_symbols.items() if s])
        }
