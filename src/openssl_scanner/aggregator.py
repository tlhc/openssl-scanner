"""
Aggregator for multiple scan reports.

Combines multiple single scan reports into an aggregated analysis,
optionally grouping by component using a mapping file.
"""

import json
import os
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set

from . import __version__

logger = logging.getLogger(__name__)


@dataclass
class ExecutableDetail:
    """Detailed statistics for a single executable within a component."""
    name: str
    path: str
    unique_symbols: List[str] = field(default_factory=list)
    by_category: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class ComponentStats:
    """Statistics for a single component."""
    name: str
    executables: List[str] = field(default_factory=list)
    executables_detail: Dict[str, ExecutableDetail] = field(default_factory=dict)
    unique_symbols: Set[str] = field(default_factory=set)
    by_category: Dict[str, Set[str]] = field(default_factory=dict)

    def add_executable(self, exe_name: str, exe_path: str,
                       symbols: List[str], categories: Dict[str, List[str]]) -> None:
        """Add an executable with its symbols to this component."""
        if exe_name not in self.executables:
            self.executables.append(exe_name)

        exe_by_category = {}
        for cat, cat_symbols in categories.items():
            exe_cat_symbols = [s for s in cat_symbols if s in symbols]
            if exe_cat_symbols:
                exe_by_category[cat] = exe_cat_symbols

        self.executables_detail[exe_name] = ExecutableDetail(
            name=exe_name,
            path=exe_path,
            unique_symbols=symbols,
            by_category=exe_by_category
        )

        self.unique_symbols.update(symbols)
        for cat, cat_symbols in categories.items():
            if cat not in self.by_category:
                self.by_category[cat] = set()
            self.by_category[cat].update(cat_symbols)

    def add_symbols(self, symbols: List[str], categories: Dict[str, List[str]]) -> None:
        """Add symbols from a scan report (legacy method for compatibility)."""
        self.unique_symbols.update(symbols)
        for cat, cat_symbols in categories.items():
            if cat not in self.by_category:
                self.by_category[cat] = set()
            self.by_category[cat].update(cat_symbols)


@dataclass
class ImportChainEntry:
    """A single import chain entry with source context."""
    component: str
    binary: str
    chain: str
    depth: int


@dataclass
class AggregatedResult:
    """Result of aggregating multiple scan reports."""
    aggregation_time: str
    tool_version: str
    source_reports_count: int
    mapping_file: Optional[str]

    total_components: int = 0
    total_executables: int = 0
    global_unique_symbols: Set[str] = field(default_factory=set)

    components: Dict[str, ComponentStats] = field(default_factory=dict)
    unclassified: ComponentStats = field(default_factory=lambda: ComponentStats(name="unclassified"))

    import_chains: Dict[str, List[ImportChainEntry]] = field(default_factory=dict)
    by_depth: Dict[int, Dict] = field(default_factory=dict)
    global_by_category: Dict[str, Set[str]] = field(default_factory=dict)


class Aggregator:
    """
    Aggregates multiple scan reports into a unified analysis.

    Supports:
    - Grouping by component using mapping file
    - Automatic component naming (basename) when no mapping provided
    - Ranking by unique symbol count
    """

    def __init__(self, mapping_file: Optional[str] = None) -> None:
        self._mapping: Dict[str, List[str]] = {}
        self._mapping_file = mapping_file
        self._basename_to_component: Dict[str, str] = {}

        if mapping_file:
            self._load_mapping(mapping_file)

    def _load_mapping(self, mapping_file: str) -> None:
        """Load component mapping from JSON file."""
        if not os.path.isfile(mapping_file):
            raise FileNotFoundError(f"Mapping file not found: {mapping_file}")

        with open(mapping_file, 'r', encoding='utf-8') as f:
            self._mapping = json.load(f)

        for component, executables in self._mapping.items():
            for exe in executables:
                basename = os.path.basename(exe)
                self._basename_to_component[basename] = component

        logger.info(f"Loaded mapping with {len(self._mapping)} components")

    def _find_component(self, scan_root: str) -> Optional[str]:
        """Find component name for a scan root path using basename matching."""
        basename = os.path.basename(scan_root)
        return self._basename_to_component.get(basename)

    def aggregate(self, reports_dir: str) -> AggregatedResult:
        """
        Aggregate all scan reports in a directory.

        Args:
            reports_dir: Directory containing scan report JSON files

        Returns:
            AggregatedResult with combined statistics
        """
        result = AggregatedResult(
            aggregation_time=datetime.now().isoformat(),
            tool_version=__version__,
            source_reports_count=0,
            mapping_file=self._mapping_file,
        )

        report_files = self._find_report_files(reports_dir)
        logger.info(f"Found {len(report_files)} report files")

        for report_path in report_files:
            try:
                self._process_report(report_path, result)
            except Exception as e:
                logger.warning(f"Failed to process {report_path}: {e}")

        self._finalize_result(result)
        return result

    def _find_report_files(self, reports_dir: str) -> List[str]:
        """Find all valid scan report JSON files in directory."""
        report_files = []

        for name in os.listdir(reports_dir):
            if not name.endswith('.json'):
                continue

            path = os.path.join(reports_dir, name)
            if not os.path.isfile(path):
                continue

            if self._is_valid_report(path):
                report_files.append(path)

        return report_files

    def _is_valid_report(self, path: str) -> bool:
        """Check if file is a valid single scan report."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            meta = data.get('meta', {})
            if 'tool_version' not in meta:
                return False

            report_type = meta.get('report_type', 'single')
            return report_type == 'single'

        except (json.JSONDecodeError, KeyError):
            return False

    def _process_report(self, report_path: str, result: AggregatedResult) -> None:
        """Process a single report and add to aggregated result."""
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        meta = data.get('meta', {})
        scan_root = meta.get('scan_root', '')

        symbols_data = data.get('openssl_symbols', {})
        all_symbols = symbols_data.get('all_unique', [])
        by_category = {
            cat: info.get('symbols', [])
            for cat, info in symbols_data.get('by_category', {}).items()
        }

        if self._mapping:
            component_name = self._find_component(scan_root)
            if component_name:
                self._add_to_component(result, component_name, scan_root, all_symbols, by_category)
            else:
                self._add_to_unclassified(result, scan_root, all_symbols, by_category)
                component_name = 'unclassified'
        else:
            component_name = os.path.basename(scan_root)
            self._add_to_component(result, component_name, scan_root, all_symbols, by_category)

        exe_basename = os.path.basename(scan_root)

        self._merge_import_chains(result, symbols_data, component_name, exe_basename)
        self._merge_by_depth(result, symbols_data, component_name, exe_basename)
        self._merge_by_category(result, by_category)

        result.source_reports_count += 1
        result.global_unique_symbols.update(all_symbols)

    def _merge_import_chains(self, result: AggregatedResult,
                              symbols_data: Dict, component: str, binary: str) -> None:
        """Merge import_chains from a single report into aggregated result."""
        import_chains = symbols_data.get('import_chains', {})

        for symbol, chains in import_chains.items():
            if symbol not in result.import_chains:
                result.import_chains[symbol] = []

            for chain_item in chains:
                if isinstance(chain_item, dict):
                    chain_str = chain_item.get('chain', '')
                    depth = chain_item.get('depth', 0)
                else:
                    chain_str = str(chain_item)
                    depth = chain_str.count(' -> ')

                entry = ImportChainEntry(
                    component=component,
                    binary=binary,
                    chain=chain_str,
                    depth=depth
                )
                result.import_chains[symbol].append(entry)

    def _merge_by_depth(self, result: AggregatedResult,
                         symbols_data: Dict, component: str, binary: str) -> None:
        """Merge by_depth from a single report into aggregated result."""
        by_depth = symbols_data.get('by_depth', {})

        for depth_key, depth_data in by_depth.items():
            depth_str = depth_key.replace('depth_', '') if isinstance(depth_key, str) else str(depth_key)
            try:
                depth_num = int(depth_str)
            except ValueError:
                continue

            if depth_num not in result.by_depth:
                result.by_depth[depth_num] = {
                    'symbols': set(),
                    'files': set(),
                    'components': set()
                }

            symbols = depth_data.get('symbols', [])
            if isinstance(symbols, list):
                result.by_depth[depth_num]['symbols'].update(symbols)
            result.by_depth[depth_num]['files'].add(binary)
            result.by_depth[depth_num]['components'].add(component)

    def _merge_by_category(self, result: AggregatedResult,
                            by_category: Dict[str, List[str]]) -> None:
        """Merge by_category into global aggregation."""
        for cat, symbols in by_category.items():
            if cat not in result.global_by_category:
                result.global_by_category[cat] = set()
            result.global_by_category[cat].update(symbols)

    def _add_to_component(self, result: AggregatedResult, component_name: str,
                          executable: str, symbols: List[str],
                          by_category: Dict[str, List[str]]) -> None:
        """Add scan data to a component."""
        if component_name not in result.components:
            result.components[component_name] = ComponentStats(name=component_name)

        component = result.components[component_name]
        exe_basename = os.path.basename(executable)
        component.add_executable(exe_basename, executable, symbols, by_category)

    def _add_to_unclassified(self, result: AggregatedResult, executable: str,
                              symbols: List[str], by_category: Dict[str, List[str]]) -> None:
        """Add scan data to unclassified."""
        exe_basename = os.path.basename(executable)
        if exe_basename not in result.unclassified.executables:
            result.unclassified.executables.append(exe_basename)
        result.unclassified.add_symbols(symbols, by_category)

    def _finalize_result(self, result: AggregatedResult) -> None:
        """Calculate final statistics."""
        result.total_components = len(result.components)
        result.total_executables = sum(
            len(c.executables) for c in result.components.values()
        ) + len(result.unclassified.executables)


class AggregatedReporter:
    """Generates reports from aggregated results."""

    def generate_json(self, result: AggregatedResult, pretty: bool = True) -> str:
        """Generate JSON report from aggregated result."""
        data = self._result_to_dict(result)
        indent = 2 if pretty else None
        return json.dumps(data, indent=indent, ensure_ascii=False)

    def generate_summary(self, result: AggregatedResult, top_n: int = 20) -> str:
        """Generate console summary."""
        lines = []
        width = 80

        lines.append('=' * width)
        title = "OpenSSL Dependency Aggregation Report"
        lines.append(title.center(width))
        lines.append('=' * width)
        lines.append('')

        lines.append(f"Aggregation Time: {result.aggregation_time}")
        lines.append(f"Source Reports:   {result.source_reports_count}")
        if result.mapping_file:
            lines.append(f"Mapping File:     {result.mapping_file}")
        lines.append('')

        lines.append('-' * width)
        lines.append('SUMMARY'.center(width))
        lines.append('-' * width)
        lines.append('')
        lines.append(f"Total Components:        {result.total_components}")
        lines.append(f"Total Executables:       {result.total_executables}")
        lines.append(f"Global Unique Symbols:   {len(result.global_unique_symbols)}")
        lines.append('')

        ranking = self._get_ranking(result)

        lines.append('-' * width)
        lines.append(f'TOP {min(top_n, len(ranking))} COMPONENTS'.center(width))
        lines.append('-' * width)
        lines.append('')

        lines.append(f" {'Rank':<6} {'Component':<35} {'Symbols':>10} {'%':>8}")
        lines.append('-' * width)

        total_symbols = len(result.global_unique_symbols) or 1
        for i, (component, count) in enumerate(ranking[:top_n], 1):
            pct = (count / total_symbols) * 100
            lines.append(f" {i:<6} {component:<35} {count:>10} {pct:>7.1f}%")

        lines.append('')

        if result.unclassified.executables:
            lines.append('-' * width)
            lines.append('UNCLASSIFIED'.center(width))
            lines.append('-' * width)
            lines.append('')
            lines.append(f"Executables: {len(result.unclassified.executables)}")
            lines.append(f"Symbols:     {len(result.unclassified.unique_symbols)}")
            lines.append('')

        lines.append('-' * width)
        lines.append('')

        return '\n'.join(lines)

    def _get_ranking(self, result: AggregatedResult) -> List[tuple]:
        """Get components ranked by unique symbol count."""
        ranking = [
            (name, len(stats.unique_symbols))
            for name, stats in result.components.items()
        ]
        ranking.sort(key=lambda x: x[1], reverse=True)
        return ranking

    def _result_to_dict(self, result: AggregatedResult) -> dict:
        """Convert AggregatedResult to dictionary for JSON."""
        ranking = self._get_ranking(result)

        return {
            'meta': {
                'tool_version': result.tool_version,
                'report_type': 'aggregated',
                'aggregation_time': result.aggregation_time,
                'source_reports_count': result.source_reports_count,
                'mapping_file': result.mapping_file,
            },
            'summary': {
                'total_components': result.total_components,
                'total_executables': result.total_executables,
                'global_unique_symbols': len(result.global_unique_symbols),
            },
            'ranking': [
                {
                    'rank': i,
                    'component': name,
                    'unique_symbols_count': count,
                }
                for i, (name, count) in enumerate(ranking, 1)
            ],
            'components': {
                name: {
                    'executables': stats.executables,
                    'executables_detail': {
                        exe_name: {
                            'name': exe_detail.name,
                            'path': exe_detail.path,
                            'unique_symbols_count': len(exe_detail.unique_symbols),
                            'unique_symbols': sorted(exe_detail.unique_symbols),
                            'by_category': {
                                cat: {
                                    'count': len(syms),
                                    'symbols': sorted(syms),
                                }
                                for cat, syms in exe_detail.by_category.items()
                            },
                        }
                        for exe_name, exe_detail in stats.executables_detail.items()
                    },
                    'unique_symbols_count': len(stats.unique_symbols),
                    'unique_symbols': sorted(stats.unique_symbols),
                    'by_category': {
                        cat: {
                            'count': len(symbols),
                            'symbols': sorted(symbols),
                        }
                        for cat, symbols in stats.by_category.items()
                    },
                }
                for name, stats in result.components.items()
            },
            'unclassified': {
                'executables': result.unclassified.executables,
                'unique_symbols_count': len(result.unclassified.unique_symbols),
                'unique_symbols': sorted(result.unclassified.unique_symbols),
            } if result.unclassified.executables else None,
            'global_unique_symbols': sorted(result.global_unique_symbols),
            'openssl_symbols': {
                'import_chains': {
                    symbol: [
                        {
                            'component': entry.component,
                            'binary': entry.binary,
                            'chain': entry.chain,
                            'depth': entry.depth,
                        }
                        for entry in entries
                    ]
                    for symbol, entries in sorted(result.import_chains.items())
                },
                'by_depth': {
                    f'depth_{depth}': {
                        'count': len(data['symbols']),
                        'symbols': sorted(data['symbols']),
                        'files': sorted(data['files']),
                        'components': sorted(data['components']),
                    }
                    for depth, data in sorted(result.by_depth.items())
                },
                'by_category': {
                    cat: {
                        'count': len(symbols),
                        'symbols': sorted(symbols),
                    }
                    for cat, symbols in sorted(result.global_by_category.items())
                },
            },
        }
