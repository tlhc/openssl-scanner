"""
Command-line interface for OpenSSL Symbol Dependency Scanner.

Usage:
    openssl-scanner scan /path/to/binary
    openssl-scanner scan /path/to/directory --scan-dir
    openssl-scanner aggregate /path/to/reports/ -o aggregated.json
"""

import argparse
import logging
import os
import sys
import time
from typing import List, Optional

from . import __version__
from .scanner import Scanner
from .reporter import Reporter
from .openssl_matcher import OpenSSLMatcher
from .openssl_discovery import OpenSSLDiscovery
from .aggregator import Aggregator, AggregatedReporter
from .exporter import Exporter
from .dependency_resolver import discover_lib_dirs


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
            logger.error("No OpenSSL library found. Use --openssl-lib to specify manually.")
            return 1
        logger.info(f"Auto-detected libcrypto: {libcrypto}")
        if libssl:
            logger.info(f"Auto-detected libssl: {libssl}")

    matcher = OpenSSLMatcher()
    try:
        count = matcher.load_openssl_symbols(libcrypto, libssl)
        logger.info(f"Loaded {count} OpenSSL symbols")
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"Failed to load OpenSSL symbols: {e}")
        return 1

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
            logger.error(
                "No OpenSSL library found in mapped libraries. "
                "Use --openssl-lib to specify manually."
            )
            return 1
        logger.info("Auto-detected libcrypto: %s", libcrypto)
        if libssl:
            logger.info("Auto-detected libssl: %s", libssl)

    matcher = OpenSSLMatcher()
    try:
        count = matcher.load_openssl_symbols(libcrypto, libssl)
        logger.info("Loaded %d OpenSSL symbols", count)
    except (FileNotFoundError, ValueError) as e:
        logger.error("Failed to load OpenSSL symbols: %s", e)
        return 1

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

    if argv and argv[0] not in ['scan', 'proc', 'aggregate', 'export', '-h', '--help', '--version']:
        argv = ['scan'] + argv

    args = parser.parse_args(argv)

    if hasattr(args, 'verbose'):
        log_file = getattr(args, 'log_file', None)
        setup_logging(args.verbose, log_file)

    if args.command == 'scan':
        return cmd_scan(args)
    elif args.command == 'proc':
        return cmd_proc(args)
    elif args.command == 'aggregate':
        return cmd_aggregate(args)
    elif args.command == 'export':
        return cmd_export(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
