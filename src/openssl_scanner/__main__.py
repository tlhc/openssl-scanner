"""
Command-line interface for OpenSSL Symbol Dependency Scanner.

Usage:
    openssl-scanner scan /path/to/binary -o report.json
    openssl-scanner scan /path/to/dir --scan-dir -o report.json
    openssl-scanner proc --pid 1234 -o report.json
    openssl-scanner hap MyApp.hap -o report.json
    openssl-scanner source /path/to/src -o report.xlsx
    openssl-scanner source /path/to/a /path/to/b -o /tmp/reports/
    openssl-scanner source -f targets.txt -o /tmp/reports/
    openssl-scanner source-merge /tmp/reports/*.xlsx -o combined.xlsx
    openssl-scanner combo-scan /path/to/opensource -o report.xlsx
    openssl-scanner update-data --openssl-lib /path/to/libcrypto.so
    openssl-scanner vendor-tree-sitter
    openssl-scanner aggregate /path/to/reports/ -o aggregated.json
    openssl-scanner export report.json -o report.xlsx
"""

import argparse
import logging
import os
import sys
import time
import zipfile
from typing import List, Optional

from . import __version__
from .scanner import Scanner
from .reporter import Reporter
from .openssl_matcher import OpenSSLMatcher
from .openssl_discovery import OpenSSLDiscovery
from .aggregator import Aggregator, AggregatedReporter
from .exporter import Exporter
from .dependency_resolver import discover_lib_dirs

SOURCE_EXTS = {'.c', '.h', '.cpp', '.hpp', '.cc', '.cxx', '.hxx', '.rs'}
SOURCE_GLOBS = ['*.c', '*.h', '*.cpp', '*.hpp', '*.cc', '*.cxx', '*.hxx', '*.rs']


def setup_logging(verbose: bool, log_file: Optional[str] = None) -> None:
    """Configure logging handlers."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'

    handlers: List[logging.Handler] = []

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console.setFormatter(logging.Formatter(fmt))
    handlers.append(console)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(fmt))
        handlers.append(file_handler)

    logging.basicConfig(level=level, handlers=handlers)


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog='openssl-scanner',
        description='OpenSSL Symbol Dependency Scanner for OpenHarmony',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}',
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    create_scan_parser(subparsers)
    create_proc_parser(subparsers)
    create_hap_parser(subparsers)
    create_source_parser(subparsers)
    create_source_merge_parser(subparsers)
    create_source_probe_parser(subparsers)
    create_combo_scan_parser(subparsers)
    create_vendor_rg_parser(subparsers)
    create_update_data_parser(subparsers)
    create_vendor_tree_sitter_parser(subparsers)
    create_aggregate_parser(subparsers)
    create_export_parser(subparsers)

    return parser


def create_scan_parser(subparsers) -> None:
    """Create parser for scan command."""
    scan_parser = subparsers.add_parser(
        'scan',
        help='Scan binary or directory for OpenSSL dependencies',
        epilog='''
Examples:
  # Scan executable (auto-detect OpenSSL libraries)
  openssl-scanner scan /system/bin/my_app

  # Scan directory (auto-detect OpenSSL libraries)
  openssl-scanner scan /system/lib64 --scan-dir

  # Explicit OpenSSL library path (optional)
  openssl-scanner scan /system/bin/my_app --openssl-lib /system/lib64/libcrypto.so
''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    scan_parser.add_argument(
        'target',
        help='Target executable or directory to scan',
    )

    scan_parser.add_argument(
        '--openssl-lib',
        dest='openssl_lib',
        help='Path to libcrypto.so (auto-detected if not specified)',
    )

    scan_parser.add_argument(
        '--openssl-ssl',
        dest='openssl_ssl',
        help='Path to libssl.so (optional)',
    )

    scan_parser.add_argument(
        '-o', '--output',
        default='openssl_deps_report.json',
        help='Output JSON report file (default: openssl_deps_report.json)',
    )

    scan_parser.add_argument(
        '-L', '--lib-path',
        action='append',
        dest='lib_paths',
        default=[],
        help='Additional library search path (can be used multiple times)',
    )

    scan_parser.add_argument(
        '--sysroot',
        help='Root filesystem path for cross-analysis (auto-discovers lib directories)',
    )

    scan_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging',
    )

    scan_parser.add_argument(
        '-j', '--jobs',
        type=int,
        default=os.cpu_count() or 4,
        help=f'Number of parallel workers (default: {os.cpu_count() or 4})',
    )

    scan_parser.add_argument(
        '--scan-dir',
        action='store_true',
        help='Scan all ELF files in directory instead of dependency tree',
    )

    scan_parser.add_argument(
        '--json-only',
        action='store_true',
        help='Output JSON only, suppress console summary',
    )

    scan_parser.add_argument(
        '--no-recursive',
        action='store_true',
        help='Do not scan subdirectories (only with --scan-dir)',
    )

    scan_parser.add_argument(
        '--log-file',
        help='Write logs to file',
    )


def create_proc_parser(subparsers) -> None:
    """Create parser for proc command."""
    proc_parser = subparsers.add_parser(
        'proc',
        help='Scan a running process for OpenSSL dependencies (Linux only)',
        epilog='''
Examples:
  # Scan by PID
  openssl-scanner proc --pid 1234

  # Scan by process name
  openssl-scanner proc --name nginx

  # With explicit OpenSSL library
  openssl-scanner proc --pid 1234 --openssl-lib /usr/lib/libcrypto.so.3
''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target_group = proc_parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '--pid',
        type=int,
        help='Process ID to scan',
    )
    target_group.add_argument(
        '--name',
        dest='process_name',
        help='Process name to scan (exact match)',
    )

    proc_parser.add_argument(
        '--openssl-lib',
        dest='openssl_lib',
        help='Path to libcrypto.so (auto-detected from mapped libraries if not specified)',
    )

    proc_parser.add_argument(
        '--openssl-ssl',
        dest='openssl_ssl',
        help='Path to libssl.so (optional)',
    )

    proc_parser.add_argument(
        '-o', '--output',
        default='openssl_deps_report.json',
        help='Output JSON report file (default: openssl_deps_report.json)',
    )

    proc_parser.add_argument(
        '-L', '--lib-path',
        action='append',
        dest='lib_paths',
        default=[],
        help='Additional library search path (can be used multiple times)',
    )

    proc_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging',
    )

    proc_parser.add_argument(
        '-j', '--jobs',
        type=int,
        default=os.cpu_count() or 4,
        help=f'Number of parallel workers (default: {os.cpu_count() or 4})',
    )

    proc_parser.add_argument(
        '--json-only',
        action='store_true',
        help='Output JSON only, suppress console summary',
    )

    proc_parser.add_argument(
        '--include-deleted',
        action='store_true',
        help='Include deleted (unlinked) libraries in analysis',
    )

    proc_parser.add_argument(
        '--log-file',
        help='Write logs to file',
    )


def create_hap_parser(subparsers) -> None:
    """Create parser for hap command."""
    hap_parser = subparsers.add_parser(
        'hap',
        help='Scan HAP/HAR/HSP/APP/ZIP packages for OpenSSL dependencies',
        epilog='''
Examples:
  # Scan single HAP (XLSX output, default)
  openssl-scanner hap MyApp.hap -o report.xlsx

  # Scan APP pack (all HAPs inside)
  openssl-scanner hap MyApp.app -o report.xlsx

  # HTML interactive report
  openssl-scanner hap MyApp.hap -o report.html

  # JSON output
  openssl-scanner hap MyApp.hap -o report.json

  # Scan HAR third-party library
  openssl-scanner hap thirdparty.har -o report.xlsx

  # Specify ABI to scan
  openssl-scanner hap MyApp.hap --abi armeabi-v7a -o report.xlsx

  # Scan ZIP package (nested HAP/ZIP supported)
  openssl-scanner hap MyBundle.zip -o report.xlsx

  # Batch scan directory (single merged report)
  openssl-scanner hap /path/to/packages/ -o report.xlsx

  # Batch scan directory (per-package independent reports)
  openssl-scanner hap /path/to/packages/ -o /tmp/reports/

  # With external OpenSSL reference library
  openssl-scanner hap MyApp.hap --openssl-lib /system/lib64/libcrypto.so.3
''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    hap_parser.add_argument(
        'target',
        help='HAP/HAR/HSP/APP/ZIP file or directory containing packages',
    )

    hap_parser.add_argument(
        '--abi',
        help='Target ABI to scan (default: auto-detect, prefer arm64-v8a)',
    )

    hap_parser.add_argument(
        '--openssl-lib',
        dest='openssl_lib',
        help='Path to external libcrypto.so (when package does not bundle OpenSSL)',
    )

    hap_parser.add_argument(
        '--openssl-ssl',
        dest='openssl_ssl',
        help='Path to external libssl.so (optional)',
    )

    hap_parser.add_argument(
        '-o', '--output',
        default='openssl_deps_report.xlsx',
        help='Output file (.xlsx/.html/.json) or directory for per-package reports (default: openssl_deps_report.xlsx)',
    )

    hap_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging',
    )

    hap_parser.add_argument(
        '-j', '--jobs',
        type=int,
        default=os.cpu_count() or 4,
        help=f'Number of parallel workers (default: {os.cpu_count() or 4})',
    )

    hap_parser.add_argument(
        '--json-only',
        action='store_true',
        help='Output JSON only, suppress console summary',
    )

    hap_parser.add_argument(
        '--keep-extracted',
        action='store_true',
        help='Keep extracted files (do not clean up temp directory)',
    )

    hap_parser.add_argument(
        '--log-file',
        help='Write logs to file',
    )


def create_source_parser(subparsers) -> None:
    """Create parser for source command."""
    src_parser = subparsers.add_parser(
        'source',
        help='Scan source code for OpenSSL API call sites',
        epilog='''
Examples:
  # Scan C/C++ source directory
  openssl-scanner source /path/to/src -o report.xlsx

  # Scan single file
  openssl-scanner source /path/to/file.c -o report.xlsx

  # Scan multiple projects, each gets its own report
  openssl-scanner source /path/to/nginx /path/to/curl -o /tmp/reports/

  # Batch scan from a path list file (one path per line)
  openssl-scanner source -f targets.txt -o /tmp/reports/

  # Mix: file list + extra paths
  openssl-scanner source -f targets.txt /extra/path -o /tmp/reports/

  # JSON output
  openssl-scanner source /path/to/src -o report.json
''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    src_parser.add_argument(
        'target',
        nargs='*',
        help='Source file(s) or directory(ies) to scan',
    )

    src_parser.add_argument(
        '-f', '--from-file',
        help='Read target paths from file (one path per line)',
    )

    src_parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output path (.xlsx/.json file for single target, directory for multiple)',
    )

    src_parser.add_argument(
        '-j', '--jobs',
        type=int,
        default=os.cpu_count() or 4,
        help=f'Number of parallel workers (default: {os.cpu_count() or 4})',
    )

    src_parser.add_argument(
        '--no-recursive',
        action='store_true',
        help='Do not scan subdirectories',
    )

    src_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging',
    )

    src_parser.add_argument(
        '--json-only',
        action='store_true',
        help='Output JSON only, suppress console summary',
    )

    src_parser.add_argument(
        '--log-file',
        help='Write logs to file',
    )


def create_source_merge_parser(subparsers) -> None:
    """Create parser for source-merge command."""
    parser = subparsers.add_parser(
        'source-merge',
        help='Merge multiple source scan XLSX reports into one workbook',
        epilog='''
Examples:
  # Merge individual reports
  openssl-scanner source-merge nginx.xlsx curl.xlsx openssl.xlsx -o combined.xlsx

  # Merge all reports in a directory
  openssl-scanner source-merge /tmp/reports/*.xlsx -o combined.xlsx
''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        'inputs',
        nargs='+',
        help='Source scan XLSX report files to merge',
    )

    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output merged XLSX file path',
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging',
    )

    parser.add_argument(
        '--log-file',
        help='Write logs to file',
    )


def create_source_probe_parser(subparsers) -> None:
    """Create parser for source-probe command."""
    parser = subparsers.add_parser(
        'source-probe',
        help='Discover directories containing OpenSSL API usage in source code',
        epilog='''
Examples:
  # Discover project directories with OpenSSL usage
  openssl-scanner source-probe /path/to/opensource

  # Redirect to file, then batch scan
  openssl-scanner source-probe /path/to/root > targets.txt
  openssl-scanner source -f targets.txt -o /tmp/reports/

  # Verbose: show per-directory scan details on stderr
  openssl-scanner source-probe /path/to/root -v > targets.txt

Output format (compatible with source -f):
  # comment lines (metadata)
  /path/to/project_a
  /path/to/project_b/src

Auto-consolidation: when multiple subdirectories under the same
parent contain OpenSSL usage, the parent is reported instead.
''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        'root',
        help='Root directory to probe for OpenSSL usage',
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show per-directory match details on stderr',
    )

    parser.add_argument(
        '--log-file',
        help='Write logs to file',
    )


def create_vendor_rg_parser(subparsers) -> None:
    """Create parser for vendor-rg command."""
    parser = subparsers.add_parser(
        'vendor-rg',
        help='Download ripgrep binary for the current platform',
        description=(
            'Download a pre-built ripgrep (rg) binary for the current '
            'platform and store it in _vendor/rg/_plat/. This enables '
            'fast source-probe without requiring rg in system PATH. '
            'Requires internet access (downloads from GitHub).'
        ),
    )

    parser.add_argument(
        '--version',
        dest='rg_version',
        help='ripgrep version to download (default: latest)',
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging',
    )

    parser.add_argument(
        '--log-file',
        help='Write logs to file',
    )


def create_aggregate_parser(subparsers) -> None:
    """Create parser for aggregate command."""
    agg_parser = subparsers.add_parser(
        'aggregate',
        help='Aggregate multiple scan reports',
        epilog='''
Examples:
  # Aggregate all reports in directory
  openssl-scanner aggregate /path/to/reports/ -o aggregated.json

  # Use component mapping file
  openssl-scanner aggregate /path/to/reports/ -m component_map.json -o aggregated.json

Mapping file format (JSON):
  {
    "component_name": ["/path/to/executable1", "/path/to/executable2"],
    "another_component": ["/path/to/executable3"]
  }
''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    agg_parser.add_argument(
        'reports_dir',
        help='Directory containing scan report JSON files',
    )

    agg_parser.add_argument(
        '-m', '--mapping',
        dest='mapping_file',
        help='Component mapping JSON file (optional)',
    )

    agg_parser.add_argument(
        '-o', '--output',
        default='aggregated_report.json',
        help='Output JSON report file (default: aggregated_report.json)',
    )

    agg_parser.add_argument(
        '--top',
        type=int,
        default=20,
        help='Number of top components to show (default: 20)',
    )

    agg_parser.add_argument(
        '--json-only',
        action='store_true',
        help='Output JSON only, suppress console summary',
    )

    agg_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging',
    )

    agg_parser.add_argument(
        '--log-file',
        help='Write logs to file',
    )


def create_export_parser(subparsers) -> None:
    """Create parser for export command."""
    exp_parser = subparsers.add_parser(
        'export',
        help='Export report to Excel or HTML',
        epilog='''
Examples:
  # Export to Excel
  openssl-scanner export report.json -o report.xlsx

  # Export to self-contained HTML
  openssl-scanner export report.json -o report.html --format html
''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    exp_parser.add_argument(
        'report',
        help='Input JSON report file',
    )

    exp_parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output file path (.xlsx or .html)',
    )

    exp_parser.add_argument(
        '-f', '--format',
        choices=['xlsx', 'html'],
        help='Output format (auto-detected from extension if not specified)',
    )

    exp_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging',
    )

    exp_parser.add_argument(
        '--log-file',
        help='Write logs to file',
    )


def cmd_scan(args) -> int:
    """Execute scan command."""
    logger = logging.getLogger(__name__)

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        logger.error(f"Target not found: {target}")
        return 1

    is_dir_mode = args.scan_dir or os.path.isdir(target)

    search_paths = list(args.lib_paths)
    if args.sysroot:
        sysroot = os.path.abspath(args.sysroot)
        logger.info(f"Scanning sysroot for library directories: {sysroot}")
        sysroot_dirs = discover_lib_dirs(sysroot)
        search_paths = sysroot_dirs + search_paths

    libcrypto = None
    libssl = None

    if args.openssl_lib:
        libcrypto = os.path.abspath(args.openssl_lib)
        if not os.path.isfile(libcrypto):
            logger.error(f"OpenSSL library not found: {libcrypto}")
            return 1
        if args.openssl_ssl:
            libssl = os.path.abspath(args.openssl_ssl)
    else:
        logger.info("Auto-detecting OpenSSL libraries...")
        discovery = OpenSSLDiscovery(additional_paths=search_paths)
        libcrypto, libssl = discovery.discover(
            target,
            is_directory=is_dir_mode,
            recursive=not args.no_recursive
        )
        if not libcrypto:
            logger.warning(
                "No OpenSSL library found via auto-detection. "
                "Falling back to built-in symbol data."
            )
        else:
            logger.info(f"Auto-detected libcrypto: {libcrypto}")
            if libssl:
                logger.info(f"Auto-detected libssl: {libssl}")

    matcher = OpenSSLMatcher()
    if libcrypto:
        try:
            count = matcher.load_openssl_symbols(libcrypto, libssl)
            logger.info(f"Loaded {count} OpenSSL symbols from live library")
        except (FileNotFoundError, ValueError) as e:
            logger.warning(f"Failed to load live OpenSSL symbols: {e}")
            libcrypto = None

    if not matcher.is_loaded():
        count = matcher.load_builtin_symbols()
        logger.info(f"Loaded {count} built-in OpenSSL symbols")

    scanner = Scanner(
        search_paths=search_paths,
        workers=args.jobs,
        matcher=matcher,
    )

    target_dir = os.path.dirname(target)
    scanner.add_search_path(target_dir)

    reporter = Reporter()

    start_time = time.time()

    try:
        if is_dir_mode:
            if not os.path.isdir(target):
                logger.error(f"--scan-dir requires a directory: {target}")
                return 1
            logger.info(f"Scanning directory: {target}")
            result = scanner.scan_directory(
                target,
                recursive=not args.no_recursive
            )
        else:
            logger.info(f"Scanning binary: {target}")
            result = scanner.scan_tree(target)

        elapsed = time.time() - start_time

        json_report = reporter.generate_json(result)
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(json_report)

        if not args.json_only:
            summary = reporter.generate_summary(result)
            print(summary)
            stats = matcher.get_stats()
            print(f"OpenSSL symbols loaded: {stats['symbols_loaded']}")
            print(f"Report saved to: {args.output}")
            print(f"Scan completed in {elapsed:.2f} seconds.")

        return 0

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 130

    except Exception as e:
        logger.exception(f"Scan failed: {e}")
        return 1


def cmd_proc(args) -> int:
    """Execute proc command."""
    logger = logging.getLogger(__name__)

    from .proc_analyzer import ProcAnalyzer

    if not ProcAnalyzer.is_available():
        logger.error("Process scan requires Linux (/proc filesystem)")
        return 1

    analyzer = ProcAnalyzer()

    if args.pid:
        try:
            process_info = analyzer.from_pid(args.pid)
        except FileNotFoundError:
            logger.error("Process %d not found", args.pid)
            return 1
        except PermissionError:
            logger.error("Permission denied reading /proc/%d. Try with sudo.", args.pid)
            return 1
    else:
        try:
            matches = analyzer.resolve_by_name(args.process_name)
        except PermissionError:
            logger.error("Permission denied reading /proc. Try with sudo.")
            return 1

        if not matches:
            logger.error("No process found matching '%s'", args.process_name)
            return 1
        elif len(matches) > 1:
            print(f"Multiple processes match '{args.process_name}':")
            print(f"  {'PID':>8s}  {'NAME':16s}  CMDLINE")
            print(f"  {'---':>8s}  {'---':16s}  ---")
            for pid, name, cmdline in matches:
                cmd_display = cmdline[:60] if cmdline else ''
                print(f"  {pid:>8d}  {name:16s}  {cmd_display}")
            print(f"\nUse --pid to specify which process to scan.")
            return 1
        else:
            pid = matches[0][0]
            try:
                process_info = analyzer.from_pid(pid)
            except (FileNotFoundError, PermissionError) as e:
                logger.error("Cannot access process %d: %s", pid, e)
                return 1

    if not args.include_deleted:
        process_info.mapped_libraries = [
            lib for lib in process_info.mapped_libraries
            if not lib.deleted
        ]

    logger.info("Process: %s (PID %d)", process_info.name, process_info.pid)
    logger.info("Executable: %s", process_info.exe_path)
    logger.info("Mapped libraries: %d", len(process_info.mapped_libraries))

    search_paths = list(args.lib_paths)
    libcrypto = None
    libssl = None

    if args.openssl_lib:
        libcrypto = os.path.abspath(args.openssl_lib)
        if not os.path.isfile(libcrypto):
            logger.error("OpenSSL library not found: %s", libcrypto)
            return 1
        if args.openssl_ssl:
            libssl = os.path.abspath(args.openssl_ssl)
    else:
        logger.info("Auto-detecting OpenSSL from mapped libraries...")
        lib_paths = [lib.path for lib in process_info.mapped_libraries]
        discovery = OpenSSLDiscovery(additional_paths=search_paths)
        libcrypto, libssl = discovery.discover_from_libraries(lib_paths)
        if not libcrypto:
            logger.warning(
                "No OpenSSL library found in mapped libraries. "
                "Falling back to built-in symbol data."
            )
        else:
            logger.info("Auto-detected libcrypto: %s", libcrypto)
            if libssl:
                logger.info("Auto-detected libssl: %s", libssl)

    matcher = OpenSSLMatcher()
    if libcrypto:
        try:
            count = matcher.load_openssl_symbols(libcrypto, libssl)
            logger.info("Loaded %d OpenSSL symbols from live library", count)
        except (FileNotFoundError, ValueError) as e:
            logger.warning("Failed to load live OpenSSL symbols: %s", e)
            libcrypto = None

    if not matcher.is_loaded():
        count = matcher.load_builtin_symbols()
        logger.info("Loaded %d built-in OpenSSL symbols", count)

    scanner = Scanner(
        search_paths=search_paths,
        workers=args.jobs,
        matcher=matcher,
    )

    dep_tree = None
    if process_info.exe_path and os.path.isfile(process_info.exe_path):
        exe_dir = os.path.dirname(process_info.exe_path)
        scanner.add_search_path(exe_dir)
        logger.info("Building dependency tree from executable for hierarchy enrichment...")
        try:
            dep_tree = scanner._resolver.build_dependency_tree(process_info.exe_path)
        except Exception as e:
            logger.warning("Could not build dependency tree: %s", e)

    reporter = Reporter()

    start_time = time.time()

    try:
        result = scanner.scan_process(process_info, dependency_tree=dep_tree)

        elapsed = time.time() - start_time

        json_report = reporter.generate_json(result)
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(json_report)

        if not args.json_only:
            summary = reporter.generate_summary(result)
            print(summary)
            stats = matcher.get_stats()
            print(f"OpenSSL symbols loaded: {stats['symbols_loaded']}")
            print(f"Report saved to: {args.output}")
            print(f"Scan completed in {elapsed:.2f} seconds.")

        return 0

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 130

    except Exception as e:
        logger.exception("Scan failed: %s", e)
        return 1


def cmd_hap(args) -> int:
    """Execute hap command."""
    logger = logging.getLogger(__name__)

    from .hap_extractor import HapExtractor

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        logger.error("Target not found: %s", target)
        return 1

    extractor = HapExtractor()

    if os.path.isdir(target):
        packages = extractor.find_packages(target)
        if not packages:
            logger.error("No HAP/HAR/HSP/APP/ZIP packages found in: %s", target)
            return 1
        logger.info("Found %d packages in %s", len(packages), target)
    else:
        packages = [target]

    reporter = Reporter()
    all_results = []
    scanned_packages = []
    start_time = time.time()
    total_packages = len(packages)

    output_path = os.path.abspath(args.output)
    output_ext = os.path.splitext(output_path)[1].lower()
    per_package = (not output_ext) or os.path.isdir(output_path)

    if per_package:
        os.makedirs(output_path, exist_ok=True)
        fmt_ext = '.json' if args.json_only else '.xlsx'
        out_names = _resolve_hap_output_names(packages, output_path, fmt_ext)

    try:
        for pkg_idx, pkg_path in enumerate(packages, 1):
            logger.info("Extracting: %s", pkg_path)
            try:
                extract_result = extractor.extract(pkg_path, abi=args.abi)
            except (ValueError, zipfile.BadZipFile) as e:
                logger.error("Failed to extract %s: %s", pkg_path, e)
                continue

            if not extract_result.so_files:
                logger.warning("No native libraries found in %s", pkg_path)
                if not args.keep_extracted:
                    extractor.cleanup(extract_result)
                continue

            logger.info(
                "Package: %s | ABI: %s | Native libs: %d",
                extract_result.metadata.bundle_name or os.path.basename(pkg_path),
                extract_result.metadata.abis_found,
                len(extract_result.so_files)
            )

            matcher = OpenSSLMatcher()
            count = matcher.load_builtin_symbols()
            logger.info("Loaded %d built-in OpenSSL symbols", count)

            removed = 0
            for dirpath, _dirnames, filenames in os.walk(extract_result.extract_dir):
                for fname in filenames:
                    if matcher.is_openssl_library(fname):
                        fpath = os.path.join(dirpath, fname)
                        os.remove(fpath)
                        removed += 1
                        logger.debug("Excluded OpenSSL lib: %s", fpath)
            if removed:
                logger.info("Excluded %d OpenSSL lib file(s) from scan", removed)

            scanner = Scanner(
                search_paths=[extract_result.extract_dir],
                workers=args.jobs,
                matcher=matcher,
            )

            result = scanner.scan_directory(extract_result.extract_dir, recursive=True)
            result.report_type = 'package'

            meta = extract_result.metadata
            result.package_info = {
                'package_path': meta.package_path,
                'package_type': meta.package_type,
                'bundle_name': meta.bundle_name,
                'module_name': meta.module_name,
                'module_type': meta.module_type,
                'version_name': meta.version_name,
                'version_code': meta.version_code,
                'min_api_version': meta.min_api_version,
                'device_types': meta.device_types,
                'scanned_abi': meta.abis_found,
                'abis_available': meta.abis_found,
                'native_libs_count': len(extract_result.so_files),
                'bundled_openssl': removed > 0 or extract_result.openssl_lib is not None,
            }

            all_results.append(result)
            scanned_packages.append(pkg_path)

            if not args.keep_extracted:
                extractor.cleanup(extract_result)

            pkg_name = meta.bundle_name or os.path.basename(pkg_path)
            sym_count = len(result.all_unique_symbols)
            file_count = result.files_with_openssl

            if per_package:
                _hap_write_single_report(
                    result, pkg_path, out_names[pkg_path], reporter, args.json_only
                )
                out_name = os.path.basename(out_names[pkg_path])
                print(f"[{pkg_idx}/{total_packages}] {pkg_name} -> {out_name}"
                      f" ({sym_count} symbols, {file_count} files)",
                      flush=True)
            else:
                if not args.json_only:
                    print(f"[{pkg_idx}/{total_packages}] {pkg_name}"
                          f" | {sym_count} OpenSSL symbols | {file_count} files",
                          flush=True)

        elapsed = time.time() - start_time

        if not all_results:
            logger.error("No packages could be scanned successfully")
            return 1

        if per_package:
            if not args.json_only:
                print(f"\nBatch complete: {len(all_results)} packages scanned"
                      f" in {elapsed:.2f}s -> {output_path}/")
            return 0

        if len(all_results) == 1:
            final_result = all_results[0]
        else:
            final_result = all_results[0]
            final_result.report_type = 'package_batch'
            final_result.package_info['batch'] = [
                r.package_info for r in all_results[1:]
            ]

        json_report = reporter.generate_json(final_result)
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        if output_ext == '.json' or args.json_only:
            json_out = output_path if output_ext == '.json' \
                else os.path.splitext(output_path)[0] + '.json'
            with open(json_out, 'w', encoding='utf-8') as f:
                f.write(json_report)
        else:
            json_path = os.path.splitext(output_path)[0] + '.json'
            with open(json_path, 'w', encoding='utf-8') as f:
                f.write(json_report)
            from .exporter import Exporter
            Exporter().export(json_path, output_path)

        if not args.json_only:
            print(f"\nReport saved to: {output_path}")
            if output_ext != '.json':
                json_path = os.path.splitext(output_path)[0] + '.json'
                print(f"JSON data:  {json_path}")
            print(f"Scan completed in {elapsed:.2f} seconds.")

        return 0

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 130

    except Exception as e:
        logger.exception("Scan failed: %s", e)
        return 1


def _resolve_hap_output_names(packages, output_dir, ext):
    """Map package paths to unique output file paths."""
    used = set()
    result = {}
    for pkg in packages:
        base = os.path.splitext(os.path.basename(pkg))[0]
        candidate = base
        counter = 2
        while candidate in used:
            candidate = f"{base}_{counter}"
            counter += 1
        used.add(candidate)
        result[pkg] = os.path.join(output_dir, candidate + ext)
    return result


def _hap_write_single_report(result, pkg_path, out_path, reporter, json_only):
    """Write a single package report immediately after scanning."""
    json_report = reporter.generate_json(result)

    json_path = os.path.splitext(out_path)[0] + '.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        f.write(json_report)

    if not json_only:
        from .exporter import Exporter
        Exporter().export(json_path, out_path)


def _resolve_output_names(targets, output_arg, ext):
    """Resolve per-target output file paths, handling basename conflicts."""
    basenames = [os.path.basename(t.rstrip('/')) for t in targets]
    seen = {}
    for i, name in enumerate(basenames):
        if name in seen:
            seen[name].append(i)
        else:
            seen[name] = [i]

    names = list(basenames)
    for name, indices in seen.items():
        if len(indices) > 1:
            for idx in indices:
                parent = os.path.basename(os.path.dirname(targets[idx]))
                names[idx] = f"{parent}_{name}"

    used = set()
    for i, name in enumerate(names):
        if name not in used:
            used.add(name)
            continue
        counter = 1
        candidate = f"{name}_{counter}"
        while candidate in used:
            counter += 1
            candidate = f"{name}_{counter}"
        names[i] = candidate
        used.add(candidate)

    output_dir = os.path.abspath(output_arg)
    return {targets[i]: os.path.join(output_dir, f"{names[i]}{ext}")
            for i in range(len(targets))}


def _scan_single_target(analyzer, target, args):
    """Scan a single target (file or directory), return SourceScanResult."""
    if os.path.isfile(target):
        call_sites = analyzer.scan_file(target)
        scan_time = time.strftime('%Y-%m-%dT%H:%M:%S')
        return analyzer._build_result(target, scan_time, 1, call_sites, [])
    else:
        return analyzer.scan_directory(
            target,
            recursive=not args.no_recursive,
            workers=args.jobs,
        )


def _export_result(result, output_path):
    """Export scan result based on file extension.

    XLSX output automatically generates a companion JSON file with the
    same base name, since JSON contains meta/errors not present in XLSX.
    """
    from .source_exporter import SourceExcelExporter, SourceJsonExporter

    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    ext = os.path.splitext(output_path)[1].lower()
    if ext == '.json':
        SourceJsonExporter().export(result, output_path)
    else:
        SourceExcelExporter().export(result, output_path)
        json_path = os.path.splitext(output_path)[0] + '.json'
        SourceJsonExporter().export(result, json_path)


def _print_source_summary(result, output_path, elapsed, prefix=""):
    """Print console summary for a single source scan result."""
    print(f"\n  {prefix}Source Code OpenSSL Call Site Analysis")
    print(f"  {'=' * 40}")
    print(f"  Target:          {result.target}")
    print(f"  Files scanned:   {result.total_files_scanned}")
    print(f"  Files with calls:{result.files_with_calls}")
    print(f"  Total call sites:{result.total_call_sites}")
    print(f"  Unique symbols:  {len(result.unique_symbols)}")
    if result.symbols_by_category:
        print(f"  Categories:")
        for cat, syms in sorted(result.symbols_by_category.items()):
            print(f"    {cat:20s} {len(syms)} symbols")
    if result.errors:
        print(f"  Errors:          {len(result.errors)}")
    print(f"\n  Report saved to: {output_path}")
    print(f"  Completed in {elapsed:.2f} seconds.")


def cmd_source(args) -> int:
    """Execute source command."""
    logger = logging.getLogger(__name__)

    try:
        from .source_analyzer import SourceAnalyzer
    except ImportError as e:
        logger.error(
            "Source scanning requires tree-sitter. "
            "Install with: pip install -e '.[source]'\n%s", e
        )
        return 1

    raw_targets = list(args.target or [])

    if args.from_file:
        fpath = os.path.abspath(args.from_file)
        if not os.path.isfile(fpath):
            logger.error("Path list file not found: %s", fpath)
            return 1
        with open(fpath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    raw_targets.append(line)
        logger.info("Read %d paths from %s", len(raw_targets) - len(args.target or []), fpath)

    if not raw_targets:
        logger.error("No targets specified. Provide paths or use -f/--from-file.")
        return 1

    targets = [os.path.abspath(t) for t in raw_targets]
    for t in targets:
        if not os.path.exists(t):
            logger.error("Target not found: %s", t)
            return 1

    matcher = OpenSSLMatcher()
    try:
        count = matcher.load_combined_symbols()
        logger.info("Loaded %d combined OpenSSL identifiers", count)
    except FileNotFoundError as e:
        logger.error(
            "Built-in symbol data not found: %s\n"
            "Run 'openssl-scanner update-data' to generate.", e
        )
        return 1

    symbols = matcher.get_combined_set()
    macros = matcher._openssl_macros or set()
    from .constants import SYMBOL_CATEGORIES
    analyzer = SourceAnalyzer(symbols, SYMBOL_CATEGORIES, macro_symbols=macros)

    multi = len(targets) > 1
    output_arg = args.output

    if multi:
        out_ext = os.path.splitext(output_arg)[1].lower()
        if out_ext in ('.xlsx', '.json'):
            logger.error(
                "Multiple targets require an output directory, not a file.\n"
                "  Use: -o /path/to/output_dir/")
            return 1
        fmt_ext = '.json' if args.json_only else '.xlsx'
        output_map = _resolve_output_names(targets, output_arg, fmt_ext)
        os.makedirs(os.path.abspath(output_arg), exist_ok=True)

    total_start = time.time()

    try:
        if not multi:
            target = targets[0]
            start = time.time()
            result = _scan_single_target(analyzer, target, args)
            elapsed = time.time() - start

            raw_out = os.path.abspath(output_arg)
            _, o_ext = os.path.splitext(raw_out)
            if (not o_ext) or os.path.isdir(raw_out):
                os.makedirs(raw_out, exist_ok=True)
                base = os.path.basename(target.rstrip('/'))
                fmt_ext = '.json' if args.json_only else '.xlsx'
                output_path = os.path.join(raw_out, base + fmt_ext)
            else:
                output_path = raw_out
            _export_result(result, output_path)

            if not args.json_only:
                _print_source_summary(result, output_path, elapsed)
        else:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            if not args.json_only:
                print(f"\n  Scanning {len(targets)} targets in parallel "
                      f"({args.jobs} workers each)...")

            def _scan_and_export(target):
                start = time.time()
                result = _scan_single_target(analyzer, target, args)
                output_path = output_map[target]
                _export_result(result, output_path)
                elapsed = time.time() - start
                return target, result, output_path, elapsed

            results_ordered = [None] * len(targets)
            target_to_idx = {t: i for i, t in enumerate(targets)}

            max_w = min(len(targets), os.cpu_count() or 4)
            with ThreadPoolExecutor(max_workers=max_w) as pool:
                futures = {
                    pool.submit(_scan_and_export, t): t
                    for t in targets
                }
                for fut in as_completed(futures):
                    target, result, output_path, elapsed = fut.result()
                    idx = target_to_idx[target]
                    results_ordered[idx] = (target, result, output_path,
                                            elapsed)

            total_files = 0
            total_calls = 0
            for idx, (target, result, output_path, elapsed) in enumerate(
                    results_ordered, 1):
                total_files += result.total_files_scanned
                total_calls += result.total_call_sites
                if not args.json_only:
                    _print_source_summary(
                        result, output_path, elapsed,
                        prefix=f"[{idx}/{len(targets)}] ",
                    )

            total_elapsed = time.time() - total_start
            if not args.json_only:
                print(f"\n  {'=' * 40}")
                print(f"  Total: {len(targets)} targets, "
                      f"{total_files} files, "
                      f"{total_calls} call sites, "
                      f"{total_elapsed:.2f}s")

        return 0

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 130

    except Exception as e:
        logger.exception("Source scan failed: %s", e)
        return 1


def create_update_data_parser(subparsers) -> None:
    """Create parser for update-data command."""
    parser = subparsers.add_parser(
        'update-data',
        help='Update built-in OpenSSL symbol and macro data',
        epilog='''
Examples:
  # Update both symbols and macros from OpenSSL build
  openssl-scanner update-data --openssl-lib /path/to/libcrypto.so \\
      --header-dir /path/to/openssl-3.0.9/include/openssl

  # Update symbols only (from compiled library)
  openssl-scanner update-data --openssl-lib /path/to/libcrypto.so

  # Update macros only (from header files)
  openssl-scanner update-data --header-dir /usr/include/openssl

  # Specify version explicitly
  openssl-scanner update-data --openssl-lib /path/to/libcrypto.so \\
      --header-dir /path/to/include/openssl --ossl-version 3.0.9
''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '--openssl-lib',
        dest='openssl_lib',
        help='Path to libcrypto.so (updates data/openssl_symbols.json)',
    )

    parser.add_argument(
        '--openssl-ssl',
        dest='openssl_ssl',
        help='Path to libssl.so (optional, used with --openssl-lib)',
    )

    parser.add_argument(
        '--header-dir',
        dest='header_dir',
        help='Path to OpenSSL include/openssl/ directory (updates data/openssl_macros.json)',
    )

    parser.add_argument(
        '--ossl-version',
        help='OpenSSL version string (auto-detected if not specified)',
    )

    parser.add_argument(
        '-o', '--output-dir',
        dest='output_dir',
        help='Output directory (default: built-in data/ directory)',
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging',
    )

    parser.add_argument(
        '--log-file',
        help='Write logs to file',
    )


def _probe_rg_one_dir(rg, scan_dir, symbols_file, source_globs, root,
                      extra_rg_args=None):
    """Run rg on a single directory with Aho-Corasick exact matching.

    Uses ``rg -Fw -f symbols_file`` for O(text_length) multi-pattern match
    regardless of symbol count.  No Python file I/O needed.

    Returns:
        (matched_dirs, first_match, candidate_count, dir_name)
    """
    import subprocess

    glob_args = []
    for g in source_globs:
        glob_args.extend(['--glob', g])

    cmd = [rg, '-l', '--no-heading', '--no-messages',
           '-Fw', '-f', symbols_file]
    if extra_rg_args:
        cmd.extend(extra_rg_args)
    cmd.extend(glob_args + [scan_dir])

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return set(), {}, 0, os.path.basename(scan_dir)

    if result.returncode not in (0, 1):
        return set(), {}, 0, os.path.basename(scan_dir)

    matched_files = [f for f in result.stdout.strip().splitlines() if f]
    if not matched_files:
        return set(), {}, 0, os.path.basename(scan_dir)

    matched_dirs = set()
    first_match = {}
    for fpath in matched_files:
        dirpath = os.path.dirname(fpath)
        if dirpath not in first_match:
            first_match[dirpath] = os.path.relpath(fpath, root)
        matched_dirs.add(dirpath)

    return matched_dirs, first_match, len(matched_files), \
        os.path.basename(scan_dir)


def _probe_phase1_rg(root, ossl_set, source_globs, logger):
    """Phase 1 via ripgrep: parallel per-directory Aho-Corasick search.

    Writes all OpenSSL identifiers to a temp file, then launches one rg
    process per top-level subdirectory in parallel.  Each rg uses
    ``-Fw -f symbols.txt`` for exact whole-word matching via Aho-Corasick.

    Returns:
        (matched_dirs, first_match, file_count, engine_name) or None on failure.
    """
    import tempfile
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from ._vendor.rg import get_rg_path

    rg = get_rg_path()
    if not rg:
        return None

    try:
        entries = os.listdir(root)
    except PermissionError:
        return None

    subdirs = sorted(
        os.path.join(root, e) for e in entries
        if not e.startswith('.') and os.path.isdir(os.path.join(root, e))
    )

    scan_targets = list(subdirs)

    has_root_sources = any(
        os.path.splitext(e)[1].lower() in {'.c', '.h', '.cpp', '.hpp',
                                            '.cc', '.cxx', '.rs'}
        for e in entries if os.path.isfile(os.path.join(root, e))
    )
    if has_root_sources:
        scan_targets.append(root)

    if not scan_targets:
        return set(), {}, 0, 'rg'

    symbols_fd, symbols_path = tempfile.mkstemp(
        prefix='ossl_symbols_', suffix='.txt')
    try:
        with os.fdopen(symbols_fd, 'w') as f:
            for sym in sorted(ossl_set):
                f.write(sym + '\n')
        logger.debug("Wrote %d symbols to %s", len(ossl_set), symbols_path)

        workers = min(len(scan_targets), os.cpu_count() or 4, 32)
        logger.info("rg parallel scan: %d targets, %d workers",
                    len(scan_targets), workers)

        all_matched = set()
        all_first = {}
        total_files = 0
        completed = 0

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for target in scan_targets:
                if target == root:
                    fut = pool.submit(
                        _probe_rg_one_dir, rg, root, symbols_path,
                        source_globs, root,
                        extra_rg_args=['--max-depth', '1'])
                else:
                    fut = pool.submit(
                        _probe_rg_one_dir, rg, target, symbols_path,
                        source_globs, root)
                futures[fut] = target

            for fut in as_completed(futures):
                completed += 1
                matched, first, count, dirname = fut.result()
                total_files += count
                all_matched.update(matched)
                all_first.update(first)
                if matched:
                    logger.debug("[%d/%d] %s: %d dirs, %d files",
                                 completed, len(futures), dirname,
                                 len(matched), count)

    finally:
        os.unlink(symbols_path)

    return all_matched, all_first, total_files, 'rg'


def _probe_phase2_consolidate(root, matched_dirs):
    """Phase 2: consolidate leaf directories into project roots.

    Uses subtree-fork heuristic: when >=2 child subtrees (or direct files
    + child subtree) contain OpenSSL matches, the directory is a boundary.
    Single-child chains are drilled through.
    """
    dirs_with_subtree_match = set(matched_dirs)
    for md in matched_dirs:
        parent = md
        while True:
            parent = os.path.dirname(parent)
            if parent == root:
                dirs_with_subtree_match.add(root)
                break
            if len(parent) < len(root):
                break
            dirs_with_subtree_match.add(parent)

    def _child_dirs(dir_path):
        try:
            return sorted(
                os.path.join(dir_path, e) for e in os.listdir(dir_path)
                if not e.startswith('.')
                and os.path.isdir(os.path.join(dir_path, e))
            )
        except PermissionError:
            return []

    def _find_roots(dir_path, is_probe_root=False):
        children_with_match = [
            c for c in _child_dirs(dir_path)
            if c in dirs_with_subtree_match
        ]
        has_direct = dir_path in matched_dirs

        if not children_with_match:
            return [dir_path] if has_direct else []

        match_sources = len(children_with_match) + (1 if has_direct else 0)

        if is_probe_root:
            results = []
            for child in children_with_match:
                results.extend(_find_roots(child))
            if has_direct:
                results.append(dir_path)
            return results

        if match_sources >= 2:
            return [dir_path]

        return _find_roots(children_with_match[0])

    return sorted(_find_roots(root, is_probe_root=True))


def cmd_source_probe(args) -> int:
    """Execute source-probe command.

    Phase 1: Discover source files containing OpenSSL identifiers via
             parallel per-directory ``rg -Fw -f symbols.txt``
             (Aho-Corasick exact match, no Python file I/O).
    Phase 2: Consolidate matched directories via subtree-fork heuristic.
    Output:  one directory path per line, compatible with ``source -f``.
    """
    import datetime

    logger = logging.getLogger(__name__)

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        logger.error("Root directory not found: %s", root)
        return 1

    matcher = OpenSSLMatcher()
    try:
        matcher.load_combined_symbols()
        ossl_set = matcher.get_combined_set()
        logger.info("Loaded %d OpenSSL identifiers for probe", len(ossl_set))
    except FileNotFoundError as e:
        logger.error(
            "Built-in symbol data not found: %s\n"
            "Run 'openssl-scanner update-data' to generate.", e
        )
        return 1

    start_time = time.time()

    result = _probe_phase1_rg(root, ossl_set, SOURCE_GLOBS, logger)

    if result is None:
        logger.error("rg not available. Run 'openssl-scanner vendor-rg' to install.")
        return 1

    matched_dirs, first_match, file_count, engine = result

    if not matched_dirs:
        elapsed = time.time() - start_time
        print(f"# source-probe: 0 directories contain OpenSSL usage")
        print(f"# root: {root}")
        print(f"# engine: {engine}")
        print(f"# files checked: {file_count}")
        print(f"# elapsed: {elapsed:.2f}s")
        return 0

    report_dirs = _probe_phase2_consolidate(root, matched_dirs)

    elapsed = time.time() - start_time

    if args.verbose:
        for md in sorted(matched_dirs):
            rel = os.path.relpath(md, root)
            sample = first_match.get(md, '')
            print(f"  + {rel}/  ({sample})", file=sys.stderr)
        print(f"  ---", file=sys.stderr)
        print(f"  {len(matched_dirs)} leaf dirs -> "
              f"{len(report_dirs)} project dirs  [{engine}]",
              file=sys.stderr)

    print(f"# source-probe: {len(report_dirs)} directories "
          f"contain OpenSSL usage")
    print(f"# root: {root}")
    print(f"# engine: {engine}")
    print(f"# files checked: {file_count}")
    print(f"# leaf directories with matches: {len(matched_dirs)}")
    print(f"# elapsed: {elapsed:.2f}s")
    print(f"# generated: "
          f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}")

    for d in report_dirs:
        print(d)

    return 0


def cmd_source_merge(args) -> int:
    """Execute source-merge command."""
    logger = logging.getLogger(__name__)

    from .source_exporter import SourceMergeExporter

    input_paths = [os.path.abspath(p) for p in args.inputs]
    for p in input_paths:
        if not os.path.isfile(p):
            logger.error("Input file not found: %s", p)
            return 1
        if not p.lower().endswith('.xlsx'):
            logger.error("Not an XLSX file: %s", p)
            return 1

    output_path = os.path.abspath(args.output)
    if not output_path.lower().endswith('.xlsx'):
        output_path += '.xlsx'

    try:
        merger = SourceMergeExporter()
        result = merger.merge(input_paths, output_path)

        stats = result['sheets']
        total_calls = sum(s['call_sites'] for s in stats)
        total_syms = result['total_symbols']

        print(f"\n  Source Report Merge")
        print(f"  {'=' * 40}")

        for s in stats:
            print(f"\n  {s['project']}")
            print(f"    Call sites:    {s['call_sites']}")
            print(f"    Unique symbols:{s['unique_symbols']}")
            print(f"    Top category:  {s['top_category']} "
                  f"({s['top_cat_symbols']} symbols)")

        print(f"\n  {'=' * 40}")
        print(f"  Merged {len(stats)} reports: "
              f"{total_calls} call sites, "
              f"{total_syms} unique symbols")
        print(f"  Output: {output_path}")

        return 0

    except Exception as e:
        logger.exception("Source merge failed: %s", e)
        return 1


def create_combo_scan_parser(subparsers) -> None:
    """Create parser for combo-scan command."""
    parser = subparsers.add_parser(
        'combo-scan',
        help='Probe, scan, and merge source code OpenSSL analysis in one step',
        epilog='''
Examples:
  # Scan all projects, output merged XLSX
  openssl-scanner combo-scan /path/to/opensource -o report.xlsx

  # All results to a directory (merged + per-project)
  openssl-scanner combo-scan /path/to/opensource -o /tmp/scan_results/

  # JSON output only
  openssl-scanner combo-scan /path/to/opensource -o report.json --json-only

Pipeline:
  1. Probe: discover project directories with OpenSSL usage (rg Aho-Corasick)
  2. Scan:  parallel tree-sitter AST analysis per project
  3. Merge: combine into multi-sheet XLSX report
''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        'root',
        help='Root directory to probe and scan',
    )

    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output path: file (.xlsx/.json) for merged only, '
             'or directory for all results (merged + per-project)',
    )

    parser.add_argument(
        '-j', '--jobs',
        type=int,
        default=os.cpu_count() or 4,
        help=f'Workers per project (default: {os.cpu_count() or 4})',
    )

    parser.add_argument(
        '--no-recursive',
        action='store_true',
        help='Do not recurse into subdirs when scanning projects',
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging',
    )

    parser.add_argument(
        '--json-only',
        action='store_true',
        help='Output JSON only, suppress console summary',
    )

    parser.add_argument(
        '--exclude',
        nargs='+',
        metavar='NAME',
        help='Exclude project directories matching these names (substring match)',
    )

    parser.add_argument(
        '--log-file',
        help='Write logs to file',
    )


def cmd_combo_scan(args) -> int:
    """Execute combo-scan: probe + scan + merge in one step."""
    logger = logging.getLogger(__name__)

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        logger.error("Root directory not found: %s", root)
        return 1

    matcher = OpenSSLMatcher()
    try:
        count = matcher.load_combined_symbols()
        logger.info("Loaded %d combined OpenSSL identifiers", count)
    except FileNotFoundError as e:
        logger.error(
            "Built-in symbol data not found: %s\n"
            "Run 'openssl-scanner update-data' to generate.", e
        )
        return 1

    ossl_set = matcher.get_combined_set()
    total_start = time.time()

    if not args.json_only:
        print(f"\n  Phase 1: Probing {root} ...")

    probe_result = _probe_phase1_rg(root, ossl_set, SOURCE_GLOBS, logger)
    if probe_result is None:
        logger.error("rg not available. Run 'openssl-scanner vendor-rg' to install.")
        return 1

    matched_dirs, first_match, file_count, engine = probe_result
    if not matched_dirs:
        if not args.json_only:
            print(f"  No OpenSSL usage found under {root}")
        return 0

    project_dirs = _probe_phase2_consolidate(root, matched_dirs)

    excluded = 0
    if args.exclude:
        before = len(project_dirs)
        project_dirs = [
            d for d in project_dirs
            if not any(pat in os.path.basename(d) or pat in os.path.relpath(d, root)
                       for pat in args.exclude)
        ]
        excluded = before - len(project_dirs)
        if excluded:
            logger.info("Excluded %d projects by --exclude", excluded)

    probe_elapsed = time.time() - total_start

    if not args.json_only:
        excl_note = (f", {excluded} excluded" if args.exclude and excluded else "")
        print(f"  Found {len(project_dirs)} projects "
              f"({len(matched_dirs)} leaf dirs, "
              f"{file_count} files checked, "
              f"{probe_elapsed:.1f}s{excl_note})")

    if not args.json_only:
        print(f"\n  Phase 2: Scanning {len(project_dirs)} projects "
              f"sequentially ({args.jobs} workers per project) ...")

    names = _resolve_combo_names(project_dirs, root)

    import shutil, tempfile, json as _json, subprocess, sys

    raw_output = os.path.abspath(args.output)
    _, ext = os.path.splitext(raw_output)
    is_dir = (not ext) or os.path.isdir(raw_output)

    if is_dir:
        out_dir = raw_output
        os.makedirs(out_dir, exist_ok=True)
        if args.json_only:
            output_path = os.path.join(out_dir, 'merged.json')
        else:
            output_path = os.path.join(out_dir, 'merged.xlsx')
    else:
        output_path = raw_output
        out_dir = None

    tmp_dir = tempfile.mkdtemp(prefix='combo_scan_')
    json_files = []
    want_xlsx = out_dir and not args.json_only

    pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sub_env = os.environ.copy()
    pp = sub_env.get('PYTHONPATH', '')
    if pkg_dir not in pp.split(os.pathsep):
        sub_env['PYTHONPATH'] = pkg_dir + (os.pathsep + pp if pp else '')

    try:
        for i, d in enumerate(project_dirs):
            start = time.time()

            if want_xlsx:
                tmp_out = os.path.join(tmp_dir, names[i] + '.xlsx')
            else:
                tmp_out = os.path.join(tmp_dir, names[i] + '.json')

            cmd = [
                sys.executable, '-m', 'openssl_scanner', 'source',
                d, '-o', tmp_out, '-j', str(args.jobs),
            ]
            if not want_xlsx:
                cmd.append('--json-only')
            if args.no_recursive:
                cmd.append('--no-recursive')

            popen_kw = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=sub_env)
            pgid = None
            if os.name == 'posix':
                popen_kw['start_new_session'] = True
            try:
                proc = subprocess.Popen(cmd, **popen_kw)
                if os.name == 'posix':
                    try:
                        pgid = os.getpgid(proc.pid)
                    except (ProcessLookupError, OSError):
                        pass
                stdout, stderr = proc.communicate(timeout=600)
            except subprocess.TimeoutExpired:
                if os.name == 'posix' and pgid is not None:
                    import signal
                    try:
                        os.killpg(pgid, signal.SIGTERM)
                    except (ProcessLookupError, OSError):
                        proc.kill()
                else:
                    proc.kill()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                elapsed = time.time() - start
                logger.warning("Scan timed out for %s (%.0fs)", names[i], elapsed)
                if not args.json_only:
                    print(f"    [{i+1}/{len(project_dirs)}] "
                          f"{names[i]:30s}  TIMEOUT ({elapsed:.0f}s)", flush=True)
                continue
            elapsed = time.time() - start

            if want_xlsx:
                tmp_json = os.path.splitext(tmp_out)[0] + '.json'
            else:
                tmp_json = tmp_out

            if proc.returncode != 0 or not os.path.isfile(tmp_json):
                err_text = (stderr or stdout or b'unknown error')
                if isinstance(err_text, bytes):
                    err_text = err_text.decode('utf-8', errors='replace')
                err_text = err_text.strip()
                if len(err_text) > 200:
                    err_text = '...' + err_text[-200:]
                logger.warning("Scan failed for %s (rc=%d): %s",
                               names[i], proc.returncode, err_text)
                if not args.json_only:
                    print(f"    [{i+1}/{len(project_dirs)}] "
                          f"{names[i]:30s}  FAILED (rc={proc.returncode})",
                          flush=True)
                continue

            json_files.append(tmp_json)

            if out_dir:
                shutil.copy2(tmp_json, os.path.join(out_dir, names[i] + '.json'))
                if want_xlsx:
                    shutil.copy2(tmp_out, os.path.join(out_dir, names[i] + '.xlsx'))

            if not args.json_only:
                with open(tmp_json, 'r', encoding='utf-8') as f:
                    meta = _json.load(f)
                n_files = meta.get('summary', {}).get('total_files_scanned', 0)
                n_calls = meta.get('summary', {}).get('total_call_sites', 0)
                print(f"    [{i+1}/{len(project_dirs)}] "
                      f"{names[i]:30s}  {n_files:5d} files  "
                      f"{n_calls:5d} calls  {elapsed:.1f}s",
                      flush=True)

        if args.json_only:
            if not output_path.lower().endswith('.json'):
                output_path += '.json'
            merge_stats = _combo_merge_json(json_files, output_path)
        else:
            if json_files:
                print(f"\n  Phase 3: Merging {len(json_files)} reports ...")
            if not output_path.lower().endswith('.xlsx'):
                output_path += '.xlsx'
            from .source_exporter import SourceMergeExporter
            merger = SourceMergeExporter()
            merge_stats = merger.merge_from_json(json_files, output_path)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    total_elapsed = time.time() - total_start

    if not args.json_only:
        stats = merge_stats['sheets']
        total_calls = sum(s['call_sites'] for s in stats)
        total_files = sum(s.get('files_scanned', 0) for s in stats)
        total_syms = merge_stats['total_symbols']

        print(f"\n  Combo Scan Results")
        print(f"  {'=' * 50}")

        for s in stats:
            if s['call_sites'] > 0:
                print(f"  {s['project']:30s}  {s['call_sites']:6d} calls  "
                      f"{s['unique_symbols']:4d} symbols")
            else:
                print(f"  {s['project']:30s}       0 calls")

        print(f"  {'=' * 50}")
        print(f"  Projects: {len(stats)}")
        print(f"  Files:    {total_files}")
        print(f"  Calls:    {total_calls}")
        print(f"  Symbols:  {total_syms}")
        print(f"  Output:   {output_path}")
        if out_dir:
            print(f"  Reports:  {out_dir}/")
        print(f"  Time:     {total_elapsed:.2f}s "
              f"(probe {probe_elapsed:.1f}s + scan+merge "
              f"{total_elapsed - probe_elapsed:.1f}s)")

    return 0


def _resolve_combo_names(project_dirs, root):
    """Generate short unique names for project directories."""
    names = []
    for d in project_dirs:
        rel = os.path.relpath(d, root)
        if rel == '.':
            name = os.path.basename(os.path.abspath(d))
        else:
            name = rel.replace(os.sep, '_').rstrip('_')
        names.append(name)

    seen = {}
    for i, name in enumerate(names):
        if name in seen:
            seen[name].append(i)
        else:
            seen[name] = [i]
    for name, indices in seen.items():
        if len(indices) > 1:
            for idx in indices:
                names[idx] = f"{names[idx]}_{idx}"

    used = set()
    for i, name in enumerate(names):
        if name not in used:
            used.add(name)
            continue
        counter = 1
        candidate = f"{name}_{counter}"
        while candidate in used:
            counter += 1
            candidate = f"{name}_{counter}"
        names[i] = candidate
        used.add(candidate)

    return names


def _combo_merge_json(json_files, output_path):
    """Merge per-project JSON reports into a single combined JSON."""
    import json as _json
    projects = []
    all_symbols = set()
    stats = []

    for path in json_files:
        with open(path, 'r', encoding='utf-8') as f:
            data = _json.load(f)
        name = os.path.splitext(os.path.basename(path))[0]
        summary = data.get('summary', {})
        entry = {
            'project': name,
            'target': data.get('meta', {}).get('target', ''),
            'total_files_scanned': summary.get('total_files_scanned', 0),
            'files_with_calls': summary.get('files_with_calls', 0),
            'total_call_sites': summary.get('total_call_sites', 0),
            'unique_symbols': summary.get('unique_symbols', []),
            'symbols_by_category': summary.get('symbols_by_category', {}),
            'call_sites': data.get('call_sites', []),
        }
        projects.append(entry)

        syms = set()
        for cs in data.get('call_sites', []):
            sym = cs.get('ossl_symbol', '')
            if sym:
                syms.add(sym)
                all_symbols.add(sym)

        cat_syms = {}
        for cs in data.get('call_sites', []):
            cat = cs.get('category', '')
            sym = cs.get('ossl_symbol', '')
            if cat:
                cat_syms.setdefault(cat, set()).add(sym)
        top_cat, top_count = '', 0
        if cat_syms:
            top_cat = max(cat_syms, key=lambda c: len(cat_syms[c]))
            top_count = len(cat_syms[top_cat])

        stats.append({
            'project': name,
            'files_scanned': summary.get('total_files_scanned', 0),
            'call_sites': entry['total_call_sites'],
            'unique_symbols': len(syms),
            'files_with_calls': summary.get('files_with_calls', 0),
            'top_category': top_cat,
            'top_cat_symbols': top_count,
        })

    merged = {
        'meta': {
            'report_type': 'combo_scan',
            'merge_time': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'total_projects': len(projects),
            'total_call_sites': sum(p['total_call_sites'] for p in projects),
            'total_unique_symbols': len(all_symbols),
        },
        'projects': projects,
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        _json.dump(merged, f, indent=2, ensure_ascii=False)

    return {'sheets': stats, 'total_symbols': len(all_symbols)}


def cmd_update_data(args) -> int:
    """Execute update-data command."""
    import json
    logger = logging.getLogger(__name__)

    if not args.openssl_lib and not args.header_dir:
        logger.error("At least one of --openssl-lib or --header-dir is required")
        return 1

    data_dir = args.output_dir
    if data_dir:
        data_dir = os.path.abspath(data_dir)
        os.makedirs(data_dir, exist_ok=True)
    else:
        data_dir = os.path.join(os.path.dirname(__file__), 'data')

    ossl_ver = getattr(args, 'ossl_version', None)
    updated = []

    if args.openssl_lib:
        libcrypto = os.path.abspath(args.openssl_lib)
        if not os.path.isfile(libcrypto):
            logger.error("libcrypto not found: %s", libcrypto)
            return 1

        libssl = None
        if args.openssl_ssl:
            libssl = os.path.abspath(args.openssl_ssl)
            if not os.path.isfile(libssl):
                logger.error("libssl not found: %s", libssl)
                return 1

        from .elf_analyzer import ELFAnalyzer
        analyzer = ELFAnalyzer()
        all_symbols = set()

        for lib_path in [libcrypto, libssl]:
            if not lib_path:
                continue
            symbols = analyzer.get_defined_symbols(lib_path)
            if symbols:
                all_symbols.update(symbols)
                logger.info("Extracted %d symbols from %s", len(symbols), lib_path)

        if not all_symbols:
            logger.error("No symbols extracted from %s", libcrypto)
            return 1

        version = ossl_ver or "unknown"
        if version == "unknown":
            for s in all_symbols:
                if s == 'OpenSSL_version':
                    break
            base = os.path.dirname(libcrypto)
            for part in reversed(base.split(os.sep)):
                import re
                m = re.match(r'[Oo]pen[Ss][Ss][Ll]-?(\d+\.\d+\.\d+\S*)', part)
                if m:
                    version = m.group(1)
                    break

        sym_data = {
            "openssl_version": version,
            "source": os.path.dirname(libcrypto),
            "total_count": len(all_symbols),
            "symbols": sorted(all_symbols),
        }

        sym_path = os.path.join(data_dir, 'openssl_symbols.json')
        with open(sym_path, 'w', encoding='utf-8') as f:
            json.dump(sym_data, f, indent=2)

        updated.append(('symbols', len(all_symbols), sym_path))
        logger.info("Written %d symbols to %s", len(all_symbols), sym_path)

    if args.header_dir:
        header_dir = os.path.abspath(args.header_dir)
        if not os.path.isdir(header_dir):
            logger.error("Header directory not found: %s", header_dir)
            return 1

        h_count = len([f for f in os.listdir(header_dir)
                       if f.endswith('.h') or f.endswith('.h.in')])
        if h_count == 0:
            logger.error("No .h or .h.in files found in %s", header_dir)
            return 1

        logger.info("Extracting macros from %s (%d header files)",
                     header_dir, h_count)

        from .macro_extractor import extract_macros
        try:
            macro_data = extract_macros(header_dir, version=ossl_ver)
        except Exception as e:
            logger.exception("Macro extraction failed: %s", e)
            return 1

        macro_path = os.path.join(data_dir, 'openssl_macros.json')
        with open(macro_path, 'w', encoding='utf-8') as f:
            json.dump(macro_data, f, indent=2)

        updated.append(('macros', macro_data['total_count'], macro_path))
        logger.info("Written %d macros to %s",
                     macro_data['total_count'], macro_path)

    print(f"\nOpenSSL Built-in Data Update")
    print(f"{'=' * 50}")
    for kind, count, path in updated:
        print(f"  {kind:10s} {count:6d} identifiers -> {path}")
    print()

    return 0


def create_vendor_tree_sitter_parser(subparsers) -> None:
    """Create parser for vendor-tree-sitter command."""
    subparsers.add_parser(
        'vendor-tree-sitter',
        help='Rebuild vendored tree-sitter binaries for current platform',
        description=(
            'Rebuild vendored tree-sitter binaries for the current platform. '
            'Pre-bundled binaries cover macOS/Linux on arm64/x86_64 with '
            'Python 3.10-3.14. Use this command only if you need a '
            'different Python version or platform. Requires internet access.'
        ),
    )


def _get_pypi_wheel_url(package: str, py_ver: str,
                        platform_tag: str, abi_tag: str) -> tuple:
    """Find matching wheel from PyPI JSON API. Returns (url, version).

    For abi3 wheels, the wheel may be tagged with an older Python version
    (e.g., cp39-abi3) but is forward-compatible with newer versions.
    """
    import urllib.request
    import json

    api_url = f"https://pypi.org/pypi/{package}/json"
    with urllib.request.urlopen(api_url, timeout=30) as resp:
        data = json.loads(resp.read())

    version = data['info']['version']

    for url_info in data['urls']:
        fn = url_info['filename']
        if not fn.endswith('.whl'):
            continue
        if platform_tag not in fn:
            continue

        if abi_tag == 'abi3':
            if 'abi3' in fn:
                return url_info['url'], version
        else:
            if py_ver in fn and abi_tag in fn:
                return url_info['url'], version

    return '', version


def _detect_platform_tags():
    """Detect PyPI wheel tags for current platform."""
    import platform as plat

    machine = plat.machine().lower()
    py_ver = f"cp{sys.version_info.major}{sys.version_info.minor}"
    py_short = f"cp{sys.version_info.major}{sys.version_info.minor:02d}"

    if sys.platform == 'darwin':
        if machine == 'arm64':
            platform_tag = 'macosx_11_0_arm64'
        else:
            platform_tag = 'macosx_10_9_x86_64'
        core_abi = py_short
    elif sys.platform == 'linux':
        if machine == 'aarch64':
            platform_tag = 'manylinux_2_17_aarch64'
        else:
            platform_tag = 'manylinux_2_17_x86_64'
        core_abi = py_short
    else:
        if machine == 'amd64':
            platform_tag = 'win_amd64'
        else:
            platform_tag = 'win32'
        core_abi = py_short

    return py_ver, py_short, platform_tag, core_abi


def cmd_vendor_tree_sitter(args) -> int:
    """Update vendored tree-sitter binaries for the current platform.

    Downloads from PyPI using only stdlib urllib (no pip required).
    Extracts .so files into _plat/{platform}_{arch}/ subdirectories.
    """
    import urllib.request
    import tempfile
    import zipfile
    import platform as plat

    PACKAGES = {
        'tree-sitter': {
            'pkg_dir': 'tree_sitter',
            'use_abi3': False,
        },
        'tree-sitter-c': {
            'pkg_dir': 'tree_sitter_c',
            'use_abi3': True,
        },
        'tree-sitter-cpp': {
            'pkg_dir': 'tree_sitter_cpp',
            'use_abi3': True,
        },
        'tree-sitter-rust': {
            'pkg_dir': 'tree_sitter_rust',
            'use_abi3': True,
        },
    }

    vendor_dir = os.path.join(os.path.dirname(__file__), '_vendor')
    py_ver, py_short, platform_tag, core_abi = _detect_platform_tags()
    machine = plat.machine().lower()
    plat_key = f"{sys.platform}_{machine}"

    print(f"Platform:  {sys.platform} {machine}")
    print(f"Python:    {sys.version_info.major}.{sys.version_info.minor}")
    print(f"Wheel tag: {py_ver}-{platform_tag}")
    print(f"Plat dir:  _plat/{plat_key}/")
    print(f"Target:    {vendor_dir}")
    print()

    for pkg_name, info in PACKAGES.items():
        pkg_dir = info['pkg_dir']

        if info['use_abi3']:
            abi_tag = 'abi3'
            search_py = 'cp310'
        else:
            abi_tag = py_short
            search_py = py_ver

        print(f"  {pkg_name}...", end=' ', flush=True)

        try:
            url, version = _get_pypi_wheel_url(
                pkg_name, search_py, platform_tag, abi_tag)
        except Exception as e:
            print(f"\n    ERROR: PyPI query failed: {e}")
            return 1

        if not url:
            print(f"\n    ERROR: No wheel for {search_py}-{abi_tag}-{platform_tag}")
            return 1

        print(f"{version}")

        plat_dest = os.path.join(vendor_dir, pkg_dir, '_plat', plat_key)
        os.makedirs(plat_dest, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix='ts_dl_') as tmpdir:
            whl_path = os.path.join(tmpdir, 'package.whl')
            try:
                urllib.request.urlretrieve(url, whl_path)
            except Exception as e:
                print(f"    ERROR: Download failed: {e}")
                return 1

            with zipfile.ZipFile(whl_path) as zf:
                for name in zf.namelist():
                    if (name.startswith(pkg_dir + '/') and
                            name.endswith(('.so', '.pyd', '.dylib'))):
                        basename = os.path.basename(name)
                        with zf.open(name) as src:
                            dst_path = os.path.join(plat_dest, basename)
                            with open(dst_path, 'wb') as dst:
                                dst.write(src.read())
                        print(f"    -> {basename}")

    print()
    print("Verifying vendored packages...")
    pkg_names = [info['pkg_dir'] for info in PACKAGES.values()]
    try:
        old_path = sys.path[:]
        sys.path.insert(0, vendor_dir)

        for mod_name in pkg_names:
            if mod_name in sys.modules:
                del sys.modules[mod_name]
            sub = mod_name + '._binding'
            if sub in sys.modules:
                del sys.modules[sub]

        import importlib
        for mod_name in pkg_names:
            mod = importlib.import_module(mod_name)
            assert os.path.abspath(mod.__file__).startswith(
                os.path.abspath(vendor_dir))
            print(f"  {mod_name:20s} OK")

        sys.path[:] = old_path
    except Exception as e:
        print(f"  Verification failed: {e}")
        return 1

    print()
    print("Done. Source scanning now works without pip install.")
    return 0


def cmd_vendor_rg(args) -> int:
    """Download and vendor ripgrep binary for the current platform."""
    import json
    import platform as plat
    import tarfile
    import tempfile
    import urllib.request

    RG_TARGETS = {
        'darwin_arm64':   'aarch64-apple-darwin',
        'darwin_x86_64':  'x86_64-apple-darwin',
        'linux_x86_64':   'x86_64-unknown-linux-musl',
        'linux_aarch64':  'aarch64-unknown-linux-gnu',
    }

    machine = plat.machine().lower()
    if machine == 'amd64':
        machine = 'x86_64'
    plat_key = f"{sys.platform}_{machine}"

    target = RG_TARGETS.get(plat_key)
    if not target:
        print(f"Unsupported platform: {plat_key}")
        print(f"Supported: {', '.join(sorted(RG_TARGETS))}")
        return 1

    vendor_dir = os.path.join(
        os.path.dirname(__file__), '_vendor', 'rg', '_plat', plat_key)
    os.makedirs(vendor_dir, exist_ok=True)

    print(f"Platform:   {plat_key}")
    print(f"Target:     {target}")
    print(f"Vendor dir: {vendor_dir}")

    version = args.rg_version
    if not version:
        print("Fetching latest version from GitHub...", flush=True)
        api_url = ("https://api.github.com/repos/"
                   "BurntSushi/ripgrep/releases/latest")
        try:
            req = urllib.request.Request(api_url)
            req.add_header('Accept', 'application/vnd.github+json')
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            version = data['tag_name']
        except Exception as e:
            print(f"Failed to query GitHub API: {e}")
            return 1

    print(f"Version:    {version}")

    archive_name = f"ripgrep-{version}-{target}.tar.gz"
    url = (f"https://github.com/BurntSushi/ripgrep/releases/"
           f"download/{version}/{archive_name}")

    print(f"Downloading {archive_name}...", flush=True)

    with tempfile.TemporaryDirectory(prefix='rg_dl_') as tmpdir:
        archive_path = os.path.join(tmpdir, archive_name)
        try:
            urllib.request.urlretrieve(url, archive_path)
        except Exception as e:
            print(f"Download failed: {e}")
            print(f"URL: {url}")
            return 1

        with tarfile.open(archive_path, 'r:gz') as tf:
            rg_found = False
            for member in tf.getmembers():
                if os.path.basename(member.name) == 'rg' and member.isfile():
                    member.name = 'rg'
                    tf.extract(member, vendor_dir)
                    rg_found = True
                    break

            if not rg_found:
                print("ERROR: 'rg' binary not found in archive")
                return 1

    rg_path = os.path.join(vendor_dir, 'rg')
    os.chmod(rg_path, 0o755)

    import subprocess
    try:
        ver_out = subprocess.run(
            [rg_path, '--version'], capture_output=True, text=True, timeout=5)
        print(f"Installed:  {ver_out.stdout.strip()}")
    except Exception as e:
        print(f"WARNING: binary verification failed: {e}")

    print(f"\nDone. source-probe will now use vendored rg.")
    return 0


def cmd_aggregate(args) -> int:
    """Execute aggregate command."""
    logger = logging.getLogger(__name__)

    reports_dir = os.path.abspath(args.reports_dir)
    if not os.path.isdir(reports_dir):
        logger.error(f"Reports directory not found: {reports_dir}")
        return 1

    mapping_file = None
    if args.mapping_file:
        mapping_file = os.path.abspath(args.mapping_file)
        if not os.path.isfile(mapping_file):
            logger.error(f"Mapping file not found: {mapping_file}")
            return 1

    start_time = time.time()

    try:
        aggregator = Aggregator(mapping_file=mapping_file)
        result = aggregator.aggregate(reports_dir)

        elapsed = time.time() - start_time

        reporter = AggregatedReporter()
        json_report = reporter.generate_json(result)

        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(json_report)

        if not args.json_only:
            summary = reporter.generate_summary(result, top_n=args.top)
            print(summary)
            print(f"Report saved to: {args.output}")
            print(f"Aggregation completed in {elapsed:.2f} seconds.")

        return 0

    except KeyboardInterrupt:
        logger.info("Aggregation interrupted by user")
        return 130

    except Exception as e:
        logger.exception(f"Aggregation failed: {e}")
        return 1


def cmd_export(args) -> int:
    """Execute export command."""
    logger = logging.getLogger(__name__)

    report_path = os.path.abspath(args.report)
    if not os.path.isfile(report_path):
        logger.error(f"Report file not found: {report_path}")
        return 1

    output_path = os.path.abspath(args.output)

    start_time = time.time()

    try:
        exporter = Exporter()
        exporter.export(report_path, output_path, format=args.format)

        elapsed = time.time() - start_time
        print(f"Export completed: {output_path}")
        print(f"Export completed in {elapsed:.2f} seconds.")

        return 0

    except ImportError as e:
        logger.error(f"Missing dependency: {e}")
        return 1

    except KeyboardInterrupt:
        logger.info("Export interrupted by user")
        return 130

    except Exception as e:
        logger.exception(f"Export failed: {e}")
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point."""
    parser = create_parser()

    if argv is None:
        argv = sys.argv[1:]

    if not argv or (len(argv) == 1 and argv[0] in ['-h', '--help']):
        parser.print_help()
        return 0

    if argv and argv[0] not in ['scan', 'proc', 'hap', 'source', 'source-merge', 'source-probe', 'combo-scan', 'vendor-rg', 'update-data', 'vendor-tree-sitter', 'aggregate', 'export', '-h', '--help', '--version']:
        argv = ['scan'] + argv

    args = parser.parse_args(argv)

    if hasattr(args, 'verbose'):
        log_file = getattr(args, 'log_file', None)
        setup_logging(args.verbose, log_file)

    if args.command == 'scan':
        return cmd_scan(args)
    elif args.command == 'proc':
        return cmd_proc(args)
    elif args.command == 'hap':
        return cmd_hap(args)
    elif args.command == 'source':
        return cmd_source(args)
    elif args.command == 'source-merge':
        return cmd_source_merge(args)
    elif args.command == 'source-probe':
        return cmd_source_probe(args)
    elif args.command == 'combo-scan':
        return cmd_combo_scan(args)
    elif args.command == 'vendor-rg':
        return cmd_vendor_rg(args)
    elif args.command == 'update-data':
        return cmd_update_data(args)
    elif args.command == 'vendor-tree-sitter':
        return cmd_vendor_tree_sitter(args)
    elif args.command == 'aggregate':
        return cmd_aggregate(args)
    elif args.command == 'export':
        return cmd_export(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
