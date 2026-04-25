"""
Source code analyzer for OpenSSL API call site detection.

Uses tree-sitter AST parsing for C/C++/Rust source files.
Optional parser-diagnostic recovery is gated by CLI/API flag.
"""

import logging
import os
import re
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

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

_C_DIRECT_QUERY = (
    '(call_expression function: (identifier) @call_name '
    'arguments: (argument_list) @call_args)'
)
_RUST_DIRECT_QUERY = (
    '(call_expression function: (identifier) @call_name '
    'arguments: (arguments) @call_args)'
)
_RUST_SCOPED_QUERY = (
    '(call_expression function: (scoped_identifier) @call_path '
    'arguments: (arguments) @call_args)'
)


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
    extraction_source: str = "ast"
    confidence: str = "high"
    parser_diagnostic_class: str = ""


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
    from .openssl_matcher import categorize_symbol
    cat = categorize_symbol(symbol, categories)
    if cat != "other":
        return cat
    if macro_symbols and symbol in macro_symbols:
        return "macro"
    return "other"


def _init_parser(lang: str) -> Tuple[Any, Any]:
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


_LANG_RUNTIME_CACHE: Dict[str, Tuple[Any, ...]] = {}


def _get_lang_runtime(lang: str) -> Tuple[Any, ...]:
    """Get cached parser and compiled queries for a language."""
    runtime = _LANG_RUNTIME_CACHE.get(lang)
    if runtime is not None:
        return runtime

    from tree_sitter import Query

    parser, language = _init_parser(lang)
    if lang in ('c', 'cpp'):
        runtime = (
            parser,
            Query(language, _C_DIRECT_QUERY),
        )
    elif lang == 'rust':
        runtime = (
            parser,
            Query(language, _RUST_DIRECT_QUERY),
            Query(language, _RUST_SCOPED_QUERY),
        )
    else:
        raise ValueError(f"Unsupported language: {lang}")

    _LANG_RUNTIME_CACHE[lang] = runtime
    return runtime


def _find_enclosing_function_c(node: Any) -> str:
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


def _extract_c_func_name(declarator_node: Any) -> str:
    """Extract function name from a C/C++ declarator node."""
    node = declarator_node
    while node:
        if node.type == 'function_declarator':
            name_node = node.child_by_field_name('declarator')
            if name_node:
                if name_node.type == 'identifier':
                    return _decode_ast_text(name_node.text)
                if name_node.type == 'qualified_identifier':
                    return _decode_ast_text(name_node.text)
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
            return _decode_ast_text(node.text)
        elif node.type == 'qualified_identifier':
            return _decode_ast_text(node.text)
        else:
            break
    return '<unknown>'


def _find_enclosing_function_rust(node: Any) -> str:
    """Walk parent nodes to find enclosing Rust function."""
    current = node.parent
    while current:
        if current.type == 'function_item':
            name = current.child_by_field_name('name')
            if name:
                return _decode_ast_text(name.text)
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

_TEXT_WHITESPACE_BYTES = {9, 10, 12, 13}


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


def _decode_ast_text(text: bytes) -> str:
    """Decode source snippets for reporting without rejecting non-UTF-8 text."""
    return text.decode('utf-8', errors='replace')


def _is_probably_text(source: bytes) -> bool:
    """Heuristic text check for source files with permissive encoding support."""
    if not source:
        return True
    if b'\x00' in source:
        return False

    sample = source[:4096]
    bad_controls = sum(
        1 for byte in sample
        if byte < 32 and byte not in _TEXT_WHITESPACE_BYTES
    )
    return bad_controls <= max(1, len(sample) // 100)


def _get_query_cursor_class() -> Optional[Any]:
    """Return QueryCursor class when available, else None for older APIs."""
    try:
        from tree_sitter import QueryCursor
        return QueryCursor
    except (ImportError, AttributeError):
        return None


def _make_query_executor(query: Any) -> Any:
    """Create a query executor compatible with old/new tree-sitter APIs."""
    query_cursor_class = _get_query_cursor_class()
    if query_cursor_class is None:
        return query
    return query_cursor_class(query)


def _walk_tree(node: Any) -> Iterator[Any]:
    """Yield a node and all descendants."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        if current.children:
            stack.extend(reversed(current.children))


def _diagnostic_snippet(node: Any) -> str:
    text = _decode_ast_text((node.text or b'')[:160])
    return ' '.join(text.split())


def _classify_parser_diagnostic(snippet: str, missing: bool) -> str:
    text = snippet.strip()
    if missing:
        return 'missing-token'
    if text.startswith('#') or '#if' in text or '#ifdef' in text or '#endif' in text:
        return 'preprocessor-fragment'
    if '\\' in text:
        return 'macro-continuation-fragment'
    if text.count('(') > text.count(')'):
        return 'unclosed-call-or-parameter-list'
    if text.count('{') > text.count('}'):
        return 'unclosed-compound-block'
    if text.count('[') > text.count(']'):
        return 'unclosed-index-or-attribute'
    if any(token in text for token in (
        'class ', 'struct ', 'enum ', 'typedef ', 'namespace ',
    )):
        return 'declaration-fragment'
    if text.endswith((',', '=', '&&', '||')):
        return 'incomplete-expression'
    return 'syntax-recovery'


def _collect_parser_diagnostics(root_node: Any,
                                limit: int = 5) -> List[Dict[str, Any]]:
    diagnostics: List[Dict[str, Any]] = []
    for node in _walk_tree(root_node):
        is_recovery = getattr(node, 'is_error', False) or node.type == 'ERROR'
        is_missing = getattr(node, 'is_missing', False)
        if not (is_recovery or is_missing):
            continue
        snippet = _diagnostic_snippet(node)
        diagnostics.append({
            'line': int(node.start_point[0]) + 1,
            'column': int(node.start_point[1]) + 1,
            'end_line': int(node.end_point[0]) + 1,
            'end_column': int(node.end_point[1]) + 1,
            'node': 'missing' if is_missing else 'recovery',
            'class': _classify_parser_diagnostic(snippet, bool(is_missing)),
            'snippet': snippet,
        })
        if len(diagnostics) >= limit:
            break
    return diagnostics


def _diagnostic_window(source: bytes,
                       diagnostic: Dict[str, Any],
                       context_lines: int = 3,
                       max_lines: int = 80) -> Tuple[str, int]:
    lines = source.decode('utf-8', errors='replace').splitlines()
    start_line = max(1, int(diagnostic['line']) - context_lines)
    end_line = min(len(lines), int(diagnostic['end_line']) + context_lines)
    if end_line - start_line + 1 > max_lines:
        end_line = start_line + max_lines - 1
    return '\n'.join(lines[start_line - 1:end_line]), start_line


def _recover_parser_diagnostic_call_sites(file_path: str,
                                          file_name: str,
                                          lang: str,
                                          source: bytes,
                                          diagnostics: List[Dict[str, Any]],
                                          openssl_symbols: Set[str],
                                          categories: Dict[str, List[str]],
                                          macro_symbols: Optional[Set[str]],
                                          existing_sites: List[CallSite]
                                          ) -> List[CallSite]:
    existing = {
        (site.ossl_symbol, site.line_number)
        for site in existing_sites
    }
    recovered: List[CallSite] = []
    recovered_keys = set()
    symbols = sorted(openssl_symbols, key=len, reverse=True)

    for item in diagnostics:
        window, window_start = _diagnostic_window(source, item)
        if not window:
            continue
        for symbol in symbols:
            pattern = rf'(?<![A-Za-z0-9_]){re.escape(symbol)}(?![A-Za-z0-9_])'
            match = re.search(pattern, window)
            if not match:
                continue
            line = window_start + window[:match.start()].count('\n')
            key = (symbol, line)
            if key in existing or key in recovered_keys:
                continue
            recovered_keys.add(key)
            recovered.append(CallSite(
                file_path=file_path,
                file_name=file_name,
                caller_function='<parser_diagnostic>',
                line_number=line,
                column=max(
                    0,
                    match.start() - window.rfind('\n', 0, match.start()) - 1,
                ),
                ossl_symbol=symbol,
                category=_categorize_symbol(symbol, categories, macro_symbols),
                call_args=_normalize_args(window),
                language=lang,
                extraction_source='parser-diagnostic-text',
                confidence='fallback',
                parser_diagnostic_class=str(item.get('class', '')),
            ))

    return recovered


def _collect_local_function_names(root_node: Any, lang: str) -> Set[str]:
    """Collect function names defined in the current source file."""
    local_functions: Set[str] = set()

    if lang in ('c', 'cpp'):
        for node in _walk_tree(root_node):
            if node.type != 'function_definition':
                continue
            declarator = node.child_by_field_name('declarator')
            if not declarator:
                continue
            func_name = _extract_c_func_name(declarator)
            if func_name and func_name != '<unknown>':
                local_functions.add(func_name)
        return local_functions

    if lang == 'rust':
        for node in _walk_tree(root_node):
            if node.type != 'function_item':
                continue
            name_node = node.child_by_field_name('name')
            if not name_node:
                continue
            local_functions.add(_decode_ast_text(name_node.text))

    return local_functions


def _scan_file_ast(file_path: str, lang: str,
                   openssl_symbols: Set[str],
                   categories: Dict[str, List[str]],
                   macro_symbols: Optional[Set[str]] = None,
                   recover_parser_diagnostics: bool = False
                   ) -> Tuple[List[CallSite], Optional[str]]:
    """
    Parse a single source file with tree-sitter and extract OpenSSL call sites.

    Returns:
        (call_sites, error_message)
    """
    try:
        with open(file_path, 'rb') as f:
            source = f.read()
    except OSError as e:
        return [], str(e)

    if not _is_probably_text(source):
        return [], f"Not a text file: {file_path}"

    if len(source) > MAX_FILE_SIZE and _is_data_blob(source):
        logger.debug("Skipping data blob: %s (%d bytes)", file_path, len(source))
        return [], None

    try:
        runtime = _get_lang_runtime(lang)
    except (ImportError, ValueError) as e:
        return [], f"tree-sitter language not installed: {e}"

    parser = runtime[0]
    tree = parser.parse(source)
    diagnostics: List[Dict[str, Any]] = []
    if tree.root_node.has_error:
        diagnostics = _collect_parser_diagnostics(
            tree.root_node,
            limit=50 if recover_parser_diagnostics else 5,
        )
        visible_diagnostics = diagnostics[:5]
        logger.debug("Parser diagnostics in %s (%d shown)",
                     file_path, len(visible_diagnostics))
        for item in visible_diagnostics:
            logger.debug(
                "  %s:%d:%d-%d:%d node=%s class=%s snippet=%r",
                file_path,
                item['line'], item['column'],
                item['end_line'], item['end_column'],
                item['node'], item['class'], item['snippet'],
            )

    call_sites: List[CallSite] = []
    file_name = os.path.basename(file_path)
    local_functions = _collect_local_function_names(tree.root_node, lang)

    if lang in ('c', 'cpp'):
        cursor = _make_query_executor(runtime[1])
        matches = cursor.matches(tree.root_node)

        for _, captured in matches:
            name_node = captured['call_name'][0]
            args_node = captured['call_args'][0]
            symbol = _decode_ast_text(name_node.text)

            if symbol not in openssl_symbols:
                continue
            if symbol in local_functions:
                continue

            caller = _find_enclosing_function_c(name_node)
            category = _categorize_symbol(symbol, categories, macro_symbols)
            args_text = _normalize_args(_decode_ast_text(args_node.text))

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
        c_direct = _make_query_executor(runtime[1])
        for _, captured in c_direct.matches(tree.root_node):
            name_node = captured['call_name'][0]
            args_node = captured['call_args'][0]
            symbol = _decode_ast_text(name_node.text)

            if symbol not in openssl_symbols:
                continue
            if symbol in local_functions:
                continue

            caller = _find_enclosing_function_rust(name_node)
            category = _categorize_symbol(symbol, categories, macro_symbols)
            args_text = _normalize_args(_decode_ast_text(args_node.text))

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

        c_scoped = _make_query_executor(runtime[2])
        for _, captured in c_scoped.matches(tree.root_node):
            path_node = captured['call_path'][0]
            args_node = captured['call_args'][0]

            name_field = path_node.child_by_field_name('name')
            symbol = (_decode_ast_text(name_field.text)
                      if name_field else _decode_ast_text(path_node.text))

            if symbol not in openssl_symbols:
                continue

            caller = _find_enclosing_function_rust(path_node)
            category = _categorize_symbol(symbol, categories, macro_symbols)
            args_text = _normalize_args(_decode_ast_text(args_node.text))

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

    if recover_parser_diagnostics and diagnostics:
        call_sites.extend(_recover_parser_diagnostic_call_sites(
            file_path, file_name, lang, source, diagnostics, openssl_symbols,
            categories, macro_symbols, call_sites,
        ))
        call_sites.sort(key=lambda cs: (cs.line_number, cs.column, cs.ossl_symbol))

    return call_sites, None


_worker_symbols = None
_worker_categories = None
_worker_macros = None
_worker_recover_parser_diagnostics = False


def _source_worker_init(symbols, categories, macros,
                        recover_parser_diagnostics: bool = False,
                        log_level: Optional[int] = None,
                        log_file: Optional[str] = None) -> None:
    """Per-process initializer: load symbols once instead of per-file."""
    global _worker_symbols, _worker_categories, _worker_macros
    global _worker_recover_parser_diagnostics, _LANG_RUNTIME_CACHE
    _worker_symbols = symbols
    _worker_categories = categories
    _worker_macros = macros
    _worker_recover_parser_diagnostics = recover_parser_diagnostics
    _LANG_RUNTIME_CACHE = {}
    if log_level is not None:
        handlers: List[logging.Handler] = [logging.StreamHandler()]
        if log_file:
            handlers.append(logging.FileHandler(log_file))
        logging.basicConfig(
            level=log_level,
            handlers=handlers,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            force=True,
        )


def _source_scan_worker(file_path: str) -> Tuple[str, List[CallSite], Optional[str]]:
    """Module-level worker for ProcessPoolExecutor (pickle-compatible)."""
    ext = os.path.splitext(file_path)[1].lower()
    lang = LANG_EXTENSIONS.get(ext)
    if not lang:
        return file_path, [], f"Unsupported extension: {ext}"
    if _worker_symbols is None or _worker_categories is None:
        return file_path, [], "source worker not initialized"
    sites, error = _scan_file_ast(
        file_path, lang, _worker_symbols, _worker_categories, _worker_macros,
        _worker_recover_parser_diagnostics)
    return file_path, sites, error


class SourceAnalyzer:
    """Analyze source code for OpenSSL API call sites using tree-sitter AST."""

    def __init__(self, openssl_symbols: Set[str],
                 categories: Optional[Dict[str, List[str]]] = None,
                 macro_symbols: Optional[Set[str]] = None,
                 recover_parser_diagnostics: bool = False):
        self._symbols = openssl_symbols
        self._categories = categories or SYMBOL_CATEGORIES
        self._macros = macro_symbols
        self._recover_parser_diagnostics = recover_parser_diagnostics

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
            file_path, lang, self._symbols, self._categories, self._macros,
            self._recover_parser_diagnostics,
        )
        if error:
            logger.warning("Error scanning %s: %s", file_path, error)
        return sites

    def scan_directory(self, dir_path: str,
                       recursive: bool = True,
                       workers: int = 4,
                       log_level: Optional[int] = None,
                       log_file: Optional[str] = None) -> SourceScanResult:
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
            global _worker_recover_parser_diagnostics
            _worker_recover_parser_diagnostics = self._recover_parser_diagnostics
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
                initargs=(
                    self._symbols, self._categories, self._macros,
                    self._recover_parser_diagnostics, log_level, log_file,
                ),
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
        unique_syms = sorted({cs.ossl_symbol for cs in call_sites})
        files_with_calls = len({cs.file_path for cs in call_sites})

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
