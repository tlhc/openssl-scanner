"""
Report generator for scan results.

Generates JSON reports and console summaries.
"""

import json
from dataclasses import asdict
from typing import Dict, List, Optional

from .scanner import ScanResult, FileResult
from .dependency_resolver import DependencyNode
from .constants import CATEGORY_DISPLAY_ORDER


class Reporter:
    """
    Generates reports from scan results.

    Supports:
    - JSON report with full details
    - Console summary with visual formatting
    - Symbol statistics and charts
    """

    def generate_json(self, result: ScanResult, pretty: bool = True) -> str:
        """
        Generate JSON report from scan result.

        Args:
            result: ScanResult to convert
            pretty: Whether to format with indentation

        Returns:
            JSON string
        """
        data = self._result_to_dict(result)
        indent = 2 if pretty else None
        return json.dumps(data, indent=indent, ensure_ascii=False)

    def generate_summary(self, result: ScanResult) -> str:
        """
        Generate console summary with ASCII formatting.

        Args:
            result: ScanResult to summarize

        Returns:
            Formatted string for console output
        """
        lines = []
        width = 80

        lines.append('=' * width)
        title = "OpenSSL Symbol Dependency Scanner v" + result.tool_version
        lines.append(title.center(width))
        lines.append('=' * width)
        lines.append('')
        lines.append(f"Scan Target: {result.target}")
        lines.append(f"Scan Time:   {result.scan_time}")
        lines.append(f"Architecture: {result.arch}")
        if result.process_info:
            pi = result.process_info
            lines.append(f"Process:     {pi['name']} (PID {pi['pid']})")
            lines.append(f"Command:     {pi.get('cmdline', '')}")
            libs_count = pi.get('mapped_libraries_count', 0)
            runtime_count = pi.get('runtime_loaded_count', 0)
            if runtime_count > 0:
                lines.append(f"Libraries:   {libs_count} loaded ({runtime_count} via dlopen)")
            else:
                lines.append(f"Libraries:   {libs_count} loaded")
        if result.package_info:
            pi = result.package_info
            lines.append(f"Package:     {pi.get('package_type', '').upper()} - {pi.get('bundle_name', 'unknown')}")
            lines.append(f"Module:      {pi.get('module_name', '')} ({pi.get('module_type', '')})")
            lines.append(f"Version:     {pi.get('version_name', '')} (code: {pi.get('version_code', '')})")
            scanned_abi = pi.get('scanned_abi', '')
            if isinstance(scanned_abi, list):
                scanned_abi = ', '.join(scanned_abi)
            lines.append(f"ABI:         {scanned_abi}")
            native_count = pi.get('native_libs_count', 0)
            lines.append(f"Native Libs: {native_count}")
        lines.append('')

        lines.append('-' * width)
        lines.append('SCAN SUMMARY'.center(width))
        lines.append('-' * width)
        lines.append('')
        lines.append(f"Total Files Scanned:       {result.total_files_scanned}")
        lines.append(f"ELF Files Found:           {result.total_elf_files}")
        lines.append(f"Files with OpenSSL Deps:   {result.files_with_openssl}")
        if result.files_with_static_openssl > 0:
            lines.append(f"Static OpenSSL Link:       {result.files_with_static_openssl}")
        if result.files_with_dlopen > 0:
            lines.append(f"Files using dlopen:        {result.files_with_dlopen}")
            lines.append(f"dlopen OpenSSL Symbols:    {len(result.all_dlsym_symbols)} unique")
            if result.dlopen_libs_detected:
                libs_str = ', '.join(result.dlopen_libs_detected)
                lines.append(f"dlopen Libraries:          {libs_str}")
        lines.append('')

        if result.openssl_libs_found:
            lines.append("OpenSSL Libraries Found:")
            for lib in result.openssl_libs_found:
                lines.append(f"  - {lib}")
            lines.append('')

        if result.dependency_tree:
            lines.append('-' * width)
            lines.append('DEPENDENCY TREE'.center(width))
            lines.append('-' * width)
            lines.append('')
            lines.extend(self._format_tree(result.dependency_tree))
            lines.append('')
            lines.append("(* = OpenSSL library)")
            lines.append('')

        lines.append('-' * width)
        lines.append('OPENSSL SYMBOLS SUMMARY'.center(width))
        lines.append('-' * width)
        lines.append('')

        total_symbols = sum(len(s) for s in result.symbols_by_file.values())
        lines.append(f"Total OpenSSL Symbols Referenced: {total_symbols}")
        lines.append(f"Unique Symbols: {len(result.all_unique_symbols)}")
        lines.append('')

        if result.symbols_by_depth:
            lines.append("By Dependency Depth:")
            for depth in sorted(result.symbols_by_depth.keys()):
                symbols = result.symbols_by_depth[depth]
                depth_label = "root" if depth == 0 else f"depth {depth}"
                lines.append(f"  {depth_label:12s}: {len(symbols)} unique symbols")
            lines.append('')

        if result.symbols_by_category:
            lines.append("By Category:")
            max_count = max(len(s) for s in result.symbols_by_category.values())
            max_bar_width = 30

            for cat in CATEGORY_DISPLAY_ORDER:
                if cat not in result.symbols_by_category:
                    continue
                symbols = result.symbols_by_category[cat]
                count = len(symbols)
                bar_len = int((count / max_count) * max_bar_width) if max_count > 0 else 0
                bar = '#' * bar_len
                lines.append(f"  {cat:20s} {bar:30s} {count}")

            for cat, symbols in result.symbols_by_category.items():
                if cat not in CATEGORY_DISPLAY_ORDER and cat != 'other':
                    count = len(symbols)
                    bar_len = int((count / max_count) * max_bar_width) if max_count > 0 else 0
                    bar = '#' * bar_len
                    lines.append(f"  {cat:20s} {bar:30s} {count}")

            if 'other' in result.symbols_by_category:
                count = len(result.symbols_by_category['other'])
                bar_len = int((count / max_count) * max_bar_width) if max_count > 0 else 0
                bar = '#' * bar_len
                lines.append(f"  {'other':20s} {bar:30s} {count}")

            lines.append('')

        if result.all_unique_symbols:
            lines.append("Top 10 Most Common Symbols:")
            symbol_counts = {}
            for file_symbols in result.symbols_by_file.values():
                for s in file_symbols:
                    symbol_counts[s] = symbol_counts.get(s, 0) + 1

            sorted_symbols = sorted(symbol_counts.items(),
                                    key=lambda x: x[1], reverse=True)

            for i, (sym, count) in enumerate(sorted_symbols[:10], 1):
                lines.append(f"  {i:2d}. {sym:40s} ({count} files)")

            lines.append('')

        if result.errors:
            lines.append('-' * width)
            lines.append('WARNINGS'.center(width))
            lines.append('-' * width)
            lines.append('')
            for err in result.errors[:10]:
                severity = err.get('severity', 'warning').upper()
                lines.append(f"[{severity}] {err['file']}: {err['error']}")
            if len(result.errors) > 10:
                lines.append(f"... and {len(result.errors) - 10} more warnings")
            lines.append('')

        lines.append('-' * width)
        lines.append('')

        return '\n'.join(lines)

    def _result_to_dict(self, result: ScanResult) -> dict:
        """Convert ScanResult to dictionary for JSON."""
        data = {
            'meta': {
                'tool_version': result.tool_version,
                'report_type': result.report_type,
                'scan_time': result.scan_time,
                'scan_root': result.target,
                'target_arch': result.arch,
            },
            'summary': {
                'total_files_scanned': result.total_files_scanned,
                'total_elf_files': result.total_elf_files,
                'files_with_openssl_deps': result.files_with_openssl,
                'total_openssl_symbols': sum(
                    len(s) for s in result.symbols_by_file.values()
                ),
                'unique_openssl_symbols': len(result.all_unique_symbols),
                'openssl_libs_found': result.openssl_libs_found,
                'files_with_static_openssl': result.files_with_static_openssl,
                'files_with_dlopen': result.files_with_dlopen,
                'dlopen_unique_symbols': len(result.all_dlsym_symbols),
                'dlopen_libs_detected': result.dlopen_libs_detected,
            },
            'openssl_symbols': {
                'by_file': {
                    path: {
                        'count': len(symbols),
                        'symbols': symbols,
                    }
                    for path, symbols in result.symbols_by_file.items()
                },
                'by_category': {
                    cat: {
                        'count': len(symbols),
                        'symbols': symbols,
                    }
                    for cat, symbols in result.symbols_by_category.items()
                },
                'by_depth': self._format_by_depth(result),
                'import_chains': self._format_import_chains(result),
                'all_unique': result.all_unique_symbols,
            },
            'files_detail': [
                self._file_result_to_dict(f) for f in result.files_detail
            ],
            'errors': result.errors,
        }

        if result.files_with_dlopen > 0:
            data['dlopen_analysis'] = {
                'files_with_dlopen': result.files_with_dlopen,
                'dlopen_symbols_by_file': {
                    path: {'count': len(syms), 'symbols': syms}
                    for path, syms in result.dlsym_symbols_by_file.items()
                },
                'all_dlopen_symbols': result.all_dlsym_symbols,
                'dlopen_libs_detected': result.dlopen_libs_detected,
            }

        if result.dependency_tree:
            data['dependency_tree'] = self._tree_to_dict(result.dependency_tree)

        if result.process_info:
            data['meta']['process'] = result.process_info

        if result.package_info:
            data['meta']['package'] = result.package_info

        return data

    def _file_result_to_dict(self, file_result: FileResult) -> dict:
        """Convert FileResult to dictionary."""
        d = {
            'path': file_result.path,
            'type': file_result.file_type,
            'arch': file_result.arch,
            'direct_deps': file_result.direct_deps,
            'openssl_deps': {
                'direct': file_result.openssl_direct,
                'transitive': file_result.openssl_transitive,
                'libs': file_result.openssl_libs,
            },
            'openssl_symbols_used': file_result.openssl_symbols,
            'static_openssl': file_result.static_openssl,
            'static_openssl_version': file_result.static_openssl_version,
            'static_ssl_library': file_result.static_ssl_library,
            'static_openssl_confidence': file_result.static_openssl_confidence,
            'static_openssl_confidence_reason': file_result.static_openssl_confidence_reason,
            'openssl_exported': file_result.openssl_exported,
            'error': file_result.error,
        }
        if file_result.uses_dlopen:
            d['dlopen_detection'] = {
                'uses_dlopen': True,
                'dlopen_symbols': file_result.dlsym_symbols,
                'dlopen_libs': file_result.dlopen_libs,
                'confidence': file_result.dlopen_confidence,
            }
        if file_result.fingerprint_detail:
            d['fingerprint_detail'] = file_result.fingerprint_detail
        return d

    def _format_by_depth(self, result) -> dict:
        """
        Format by_depth for JSON output.

        Uses depth_info (with files) when available from directory scan,
        falls back to symbols_by_depth for tree scan mode.
        """
        if result.depth_info:
            return {
                f"depth_{depth}": {
                    'count': info.count,
                    'symbols': info.symbols,
                    'files': info.files,
                }
                for depth, info in result.depth_info.items()
            }

        return {
            f"depth_{depth}": {
                'count': len(symbols),
                'symbols': symbols,
            }
            for depth, symbols in result.symbols_by_depth.items()
        }

    def _format_import_chains(self, result) -> dict:
        """
        Format import chains for JSON output.

        Uses detailed format (with source_file, chain, depth) when available,
        falls back to legacy format (chain strings only) otherwise.
        """
        if result.import_chains_detail:
            return {
                symbol: [
                    {
                        'source_file': chain.source_file,
                        'chain': chain.chain,
                        'depth': chain.depth
                    }
                    for chain in chains
                ]
                for symbol, chains in result.import_chains_detail.items()
            }

        return result.import_chains

    def _tree_to_dict(self, node: DependencyNode) -> dict:
        """Convert DependencyNode to dictionary."""
        data = {
            'name': node.name,
            'path': node.path,
            'is_openssl_lib': node.is_openssl_lib,
            'openssl_symbols_count': len(node.openssl_symbols),
        }

        if node.error:
            data['error'] = node.error

        if node.children:
            data['children'] = [
                self._tree_to_dict(child) for child in node.children
            ]

        return data

    def _format_tree(self, node: DependencyNode,
                      prefix: str = '', is_last: bool = True) -> List[str]:
        """Format dependency tree as ASCII art."""
        lines = []

        marker = '*' if node.is_openssl_lib else ''
        sym_info = ''
        if node.openssl_symbols:
            sym_info = f" [OpenSSL: {len(node.openssl_symbols)} symbols]"
        elif node.error:
            sym_info = f" ({node.error})"

        connector = '+-- ' if is_last else '+-- '
        lines.append(f"{prefix}{connector}{node.name}{marker}{sym_info}")

        child_prefix = prefix + ('    ' if is_last else '|   ')

        for i, child in enumerate(node.children):
            is_last_child = (i == len(node.children) - 1)
            lines.extend(self._format_tree(child, child_prefix, is_last_child))

        return lines
