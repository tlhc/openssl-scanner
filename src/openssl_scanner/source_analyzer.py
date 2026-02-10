"""
Source code analyzer for OpenSSL API call site detection.

Uses tree-sitter AST parsing for C/C++/Rust source files.
No regex/text fallback - AST only.
"""

import logging
import os
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import __version__
from .constants import SYMBOL_CATEGORIES

logger = logging.getLogger(__name__)

LANG_EXTENSIONS: Dict[str, str] = {
    '.c': 'c',
    '.h': 'c',
    '.cpp': 'cpp',
    '.hpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.hxx': 'cpp',
    '.rs': 'rust',
}


@dataclass
class CallSite:
    file_path: str
    file_name: str
    caller_function: str
    line_number: int
    column: int
    ossl_symbol: str
    category: str
    call_args: str
    language: str


@dataclass
class SourceScanResult:
    target: str
    scan_time: str
    tool_version: str
    total_files_scanned: int
    files_with_calls: int
    total_call_sites: int
    unique_symbols: List[str]
    symbols_by_category: Dict[str, List[str]]
    call_sites: List[CallSite]
    errors: List[Dict[str, str]] = field(default_factory=list)


def _categorize_symbol(symbol: str,
                       categories: Dict[str, List[str]],
                       macro_symbols: Optional[Set[str]] = None) -> str:
    for category, prefixes in categories.items():
        for prefix in prefixes:
            if symbol.startswith(prefix):
                return category
    if macro_symbols and symbol in macro_symbols:
        return "macro"
    return "other"


def _init_parser(lang: str):
    """Initialize tree-sitter parser for a language."""
    from tree_sitter import Language, Parser

    if lang == 'c':
        import tree_sitter_c
        language = Language(tree_sitter_c.language())
    elif lang == 'cpp':
        import tree_sitter_cpp
        language = Language(tree_sitter_cpp.language())
    elif lang == 'rust':
        import tree_sitter_rust
        language = Language(tree_sitter_rust.language())
    else:
        raise ValueError(f"Unsupported language: {lang}")

    parser = Parser(language)
    return parser, language


def _find_enclosing_function_c(node) -> str:
    """Walk parent nodes to find enclosing C/C++ function."""
    current = node.parent
    while current:
        if current.type == 'function_definition':
            decl = current.child_by_field_name('declarator')
            if decl:
                return _extract_c_func_name(decl)
            return '<unknown>'
        current = current.parent
    return '<file_scope>'


def _extract_c_func_name(declarator_node) -> str:
    """Extract function name from a C/C++ declarator node."""
    node = declarator_node
    while node:
        if node.type == 'function_declarator':
            name_node = node.child_by_field_name('declarator')
            if name_node:
                if name_node.type == 'identifier':
                    return name_node.text.decode()
                if name_node.type == 'qualified_identifier':
                    return name_node.text.decode()
                return _extract_c_func_name(name_node)
            break
        elif node.type == 'pointer_declarator':
            for child in node.children:
                if child.type == 'function_declarator':
                    return _extract_c_func_name(child)
            pointee = node.child_by_field_name('declarator')
            if pointee:
                return _extract_c_func_name(pointee)
            break
        elif node.type == 'identifier':
            return node.text.decode()
        elif node.type == 'qualified_identifier':
            return node.text.decode()
        else:
            break
    return '<unknown>'


def _find_enclosing_function_rust(node) -> str:
    """Walk parent nodes to find enclosing Rust function."""
    current = node.parent
    while current:
        if current.type == 'function_item':
            name = current.child_by_field_name('name')
            if name:
                return name.text.decode()
            return '<unknown>'
        current = current.parent
    return '<file_scope>'


def _normalize_args(text: str) -> str:
    """Normalize multi-line argument text to single line."""
    result = ' '.join(text.split())
    return result


MAX_FILE_SIZE = 50 * 1024  # 50 KB — data blobs above this are skipped

_DATA_BLOB_PREFIXES = (
    b'0x', b' 0x', b'\t0x', b'\n0x',
)


def _is_data_blob(source: bytes) -> bool:
    """Detect files that are raw hex data arrays (e.g., embedded JPEG/PNG).

    These cause pathological tree-sitter parse times due to error recovery
    on non-C content.  A quick heuristic: if the first non-empty line starts
    with hex literals and there are no C keywords in the first 512 bytes,
    it is almost certainly a data blob.
    """
    head = source[:512]
    stripped = head.lstrip()
    if not stripped:
        return False
    if not any(stripped.startswith(p) for p in _DATA_BLOB_PREFIXES):
        return False
    c_keywords = (b'#include', b'#define', b'#ifndef', b'#pragma',
                  b'typedef', b'struct', b'enum', b'extern',
                  b'static', b'const ', b'void ', b'int ', b'char ')
    return not any(kw in head for kw in c_keywords)


def _scan_file_ast(file_path: str, lang: str,
                   openssl_symbols: Set[str],
                   categories: Dict[str, List[str]],
                   macro_symbols: Optional[Set[str]] = None) -> Tuple[List[CallSite], Optional[str]]:
    """
    Parse a single source file with tree-sitter and extract OpenSSL call sites.

    Returns:
        (call_sites, error_message)
    """
    from tree_sitter import Query, QueryCursor

    try:
        with open(file_path, 'rb') as f:
            source = f.read()
    except (OSError, IOError) as e:
        return [], str(e)

    try:
        source.decode('utf-8')
    except UnicodeDecodeError:
        return [], f"Not a text file: {file_path}"

    if len(source) > MAX_FILE_SIZE and _is_data_blob(source):
        logger.debug("Skipping data blob: %s (%d bytes)", file_path, len(source))
        return [], None

    try:
        parser, language = _init_parser(lang)
    except ImportError as e:
        return [], f"tree-sitter language not installed: {e}"

    tree = parser.parse(source)
    if tree.root_node.has_error:
        logger.debug("Parse errors in %s (partial results may be extracted)", file_path)

    call_sites: List[CallSite] = []
    file_name = os.path.basename(file_path)

    if lang in ('c', 'cpp'):
        query = Query(
            language,
            '(call_expression function: (identifier) @call_name '
            'arguments: (argument_list) @call_args)'
        )
        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)

        for _, captured in matches:
            name_node = captured['call_name'][0]
            args_node = captured['call_args'][0]
            symbol = name_node.text.decode()

            if symbol not in openssl_symbols:
                continue

            caller = _find_enclosing_function_c(name_node)
            category = _categorize_symbol(symbol, categories, macro_symbols)
            args_text = _normalize_args(args_node.text.decode())

            call_sites.append(CallSite(
                file_path=file_path,
                file_name=file_name,
                caller_function=caller,
                line_number=name_node.start_point[0] + 1,
                column=name_node.start_point[1],
                ossl_symbol=symbol,
                category=category,
                call_args=args_text,
                language=lang,
            ))

    elif lang == 'rust':
        q_direct = Query(
            language,
            '(call_expression function: (identifier) @call_name '
            'arguments: (arguments) @call_args)'
        )
        c_direct = QueryCursor(q_direct)
        for _, captured in c_direct.matches(tree.root_node):
            name_node = captured['call_name'][0]
            args_node = captured['call_args'][0]
            symbol = name_node.text.decode()

            if symbol not in openssl_symbols:
                continue

            caller = _find_enclosing_function_rust(name_node)
            category = _categorize_symbol(symbol, categories, macro_symbols)
            args_text = _normalize_args(args_node.text.decode())

            call_sites.append(CallSite(
                file_path=file_path,
                file_name=file_name,
                caller_function=caller,
                line_number=name_node.start_point[0] + 1,
                column=name_node.start_point[1],
                ossl_symbol=symbol,
                category=category,
                call_args=args_text,
                language=lang,
            ))

        q_scoped = Query(
            language,
            '(call_expression function: (scoped_identifier) @call_path '
            'arguments: (arguments) @call_args)'
        )
        c_scoped = QueryCursor(q_scoped)
        for _, captured in c_scoped.matches(tree.root_node):
            path_node = captured['call_path'][0]
            args_node = captured['call_args'][0]

            name_field = path_node.child_by_field_name('name')
            symbol = name_field.text.decode() if name_field else path_node.text.decode()

            if symbol not in openssl_symbols:
                continue

            caller = _find_enclosing_function_rust(path_node)
            category = _categorize_symbol(symbol, categories, macro_symbols)
            args_text = _normalize_args(args_node.text.decode())

            call_sites.append(CallSite(
                file_path=file_path,
                file_name=file_name,
                caller_function=caller,
                line_number=path_node.start_point[0] + 1,
                column=path_node.start_point[1],
                ossl_symbol=symbol,
                category=category,
                call_args=args_text,
                language=lang,
            ))

        call_sites.sort(key=lambda cs: cs.line_number)

    return call_sites, None


_worker_symbols = None
_worker_categories = None
_worker_macros = None


def _source_worker_init(symbols, categories, macros):
    """Per-process initializer: load symbols once instead of per-file."""
    global _worker_symbols, _worker_categories, _worker_macros
    _worker_symbols = symbols
    _worker_categories = categories
    _worker_macros = macros


def _source_scan_worker(file_path):
    """Module-level worker for ProcessPoolExecutor (pickle-compatible)."""
    ext = os.path.splitext(file_path)[1].lower()
    lang = LANG_EXTENSIONS.get(ext)
    if not lang:
        return file_path, [], f"Unsupported extension: {ext}"
    sites, error = _scan_file_ast(
        file_path, lang, _worker_symbols, _worker_categories, _worker_macros)
    return file_path, sites, error


class SourceAnalyzer:
    """Analyze source code for OpenSSL API call sites using tree-sitter AST."""

    def __init__(self, openssl_symbols: Set[str],
                 categories: Optional[Dict[str, List[str]]] = None,
                 macro_symbols: Optional[Set[str]] = None):
        self._symbols = openssl_symbols
        self._categories = categories or SYMBOL_CATEGORIES
        self._macros = macro_symbols

    def scan_file(self, file_path: str) -> List[CallSite]:
        """
        Scan a single source file for OpenSSL call sites.

        Args:
            file_path: Path to C/C++/Rust source file

        Returns:
            List of CallSite objects found
        """
        file_path = os.path.abspath(file_path)
        ext = os.path.splitext(file_path)[1].lower()
        lang = LANG_EXTENSIONS.get(ext)
        if not lang:
            logger.warning("Unsupported file extension: %s", file_path)
            return []

        sites, error = _scan_file_ast(
            file_path, lang, self._symbols, self._categories, self._macros
        )
        if error:
            logger.warning("Error scanning %s: %s", file_path, error)
        return sites

    def scan_directory(self, dir_path: str,
                       recursive: bool = True,
                       workers: int = 4) -> SourceScanResult:
        """
        Scan a directory of source files for OpenSSL call sites.

        Args:
            dir_path: Directory to scan
            recursive: Scan subdirectories
            workers: Number of parallel workers

        Returns:
            SourceScanResult with all findings
        """
        dir_path = os.path.abspath(dir_path)
        source_files = self._collect_source_files(dir_path, recursive)
        logger.info("Found %d source files in %s", len(source_files), dir_path)

        all_sites: List[CallSite] = []
        errors: List[Dict[str, str]] = []
        scan_time = time.strftime('%Y-%m-%dT%H:%M:%S')

        if not source_files:
            return self._build_result(dir_path, scan_time, 0, all_sites, errors)

        effective_workers = min(workers, len(source_files))
        logger.info("Scanning with %d workers (requested: %d, files: %d)",
                     effective_workers, workers, len(source_files))
        if effective_workers <= 1:
            global _worker_symbols, _worker_categories, _worker_macros
            _worker_symbols = self._symbols
            _worker_categories = self._categories
            _worker_macros = self._macros
            for fp in source_files:
                fp, sites, error = _source_scan_worker(fp)
                if error:
                    errors.append({'file': fp, 'error': error})
                all_sites.extend(sites)
        else:
            chunksize = max(1, len(source_files) // (effective_workers * 4))
            with ProcessPoolExecutor(
                max_workers=effective_workers,
                initializer=_source_worker_init,
                initargs=(self._symbols, self._categories, self._macros),
            ) as executor:
                for fp, sites, error in executor.map(
                    _source_scan_worker, source_files, chunksize=chunksize
                ):
                    if error:
                        errors.append({'file': fp, 'error': error})
                    all_sites.extend(sites)

        all_sites.sort(key=lambda cs: (cs.file_path, cs.line_number))

        return self._build_result(
            dir_path, scan_time, len(source_files), all_sites, errors
        )

    def _collect_source_files(self, dir_path: str,
                              recursive: bool) -> List[str]:
        """Collect all supported source files."""
        files = []
        if recursive:
            seen_real = set()
            seen_real.add(os.path.realpath(dir_path))
            for root, dirs, filenames in os.walk(dir_path, followlinks=True):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                clean = []
                for d in dirs:
                    real = os.path.realpath(os.path.join(root, d))
                    if real in seen_real:
                        logger.debug("Skipping symlink cycle: %s -> %s",
                                     os.path.join(root, d), real)
                        continue
                    seen_real.add(real)
                    clean.append(d)
                dirs[:] = clean
                for fname in filenames:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in LANG_EXTENSIONS:
                        files.append(os.path.join(root, fname))
        else:
            for fname in os.listdir(dir_path):
                ext = os.path.splitext(fname)[1].lower()
                if ext in LANG_EXTENSIONS:
                    fpath = os.path.join(dir_path, fname)
                    if os.path.isfile(fpath):
                        files.append(fpath)
        return sorted(files)

    def _build_result(self, target: str, scan_time: str,
                      total_scanned: int,
                      call_sites: List[CallSite],
                      errors: List[Dict[str, str]]) -> SourceScanResult:
        """Build SourceScanResult from collected data."""
        unique_syms = sorted(set(cs.ossl_symbol for cs in call_sites))
        files_with_calls = len(set(cs.file_path for cs in call_sites))

        by_category: Dict[str, List[str]] = {}
        for cs in call_sites:
            cat = cs.category
            if cat not in by_category:
                by_category[cat] = []
            if cs.ossl_symbol not in by_category[cat]:
                by_category[cat].append(cs.ossl_symbol)

        return SourceScanResult(
            target=target,
            scan_time=scan_time,
            tool_version=__version__,
            total_files_scanned=total_scanned,
            files_with_calls=files_with_calls,
            total_call_sites=len(call_sites),
            unique_symbols=unique_syms,
            symbols_by_category=by_category,
            call_sites=call_sites,
            errors=errors,
        )
