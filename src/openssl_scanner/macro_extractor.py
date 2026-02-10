"""
Extract function-like macros from OpenSSL header files.

Handles five categories:
  1. Explicit #define function-like macros
  2. Alias macros (#define OLD NEW, no parens)
  3. Static inline functions in headers
  4. sk_TYPE_* stack template macros
  5. lh_TYPE_* lhash template macros
"""

import json
import logging
import os
import re
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

SK_FUNC_SUFFIXES = [
    "num", "value", "new", "new_null", "new_reserve", "reserve",
    "free", "zero", "delete", "delete_ptr", "push", "unshift",
    "pop", "shift", "pop_free", "insert", "set", "find",
    "find_ex", "find_all", "sort", "is_sorted", "dup",
    "deep_copy", "set_cmp_func",
]

LH_FUNC_SUFFIXES = [
    "new", "free", "flush", "insert", "delete", "retrieve",
    "error", "num_items", "node_stats_bio", "node_usage_stats_bio",
    "stats_bio", "get_down_load", "set_down_load", "doall",
]

OSSL_PREFIXES = (
    'SSL_', 'TLS_', 'DTLS_', 'EVP_', 'BIO_', 'X509_', 'ASN1_',
    'OPENSSL_', 'CRYPTO_', 'RSA_', 'EC_', 'ECDSA_', 'ECDH_', 'DH_',
    'DSA_', 'BN_', 'ERR_', 'PEM_', 'PKCS', 'DES_', 'AES_', 'HMAC_',
    'MD5_', 'SHA', 'RAND_', 'OSSL_', 'OBJ_', 'NCONF_', 'GENERAL_',
    'OCSP_', 'CMS_', 'CT_', 'TS_', 'SMIME_', 'COMP_', 'ENGINE_',
    'UI_', 'CONF_', 'ASYNC_',
)

_SKIP_MACROS = {
    "STACK_OF", "LHASH_OF",
    "SKM_DEFINE_STACK_OF", "SKM_DEFINE_STACK_OF_INTERNAL",
    "DEFINE_STACK_OF", "DEFINE_STACK_OF_CONST",
    "DEFINE_SPECIAL_STACK_OF", "DEFINE_SPECIAL_STACK_OF_CONST",
    "DEFINE_LHASH_OF", "DEFINE_LHASH_OF_INTERNAL",
    "IMPLEMENT_LHASH_DOALL_ARG", "IMPLEMENT_LHASH_DOALL_ARG_CONST",
    "int_implement_lhash_doall",
    "DECLARE_LHASH_HASH_FN", "IMPLEMENT_LHASH_HASH_FN",
    "DECLARE_LHASH_COMP_FN", "IMPLEMENT_LHASH_COMP_FN",
    "DECLARE_LHASH_DOALL_ARG_FN", "IMPLEMENT_LHASH_DOALL_ARG_FN",
    "LHASH_HASH_FN", "LHASH_COMP_FN", "LHASH_DOALL_ARG_FN",
    "LH_LOAD_MULT",
}

_RE_FUNC_MACRO = re.compile(
    r'^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(',
    re.MULTILINE
)

_RE_ALIAS_MACRO = re.compile(
    r'^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+'
    r'([A-Za-z_][A-Za-z0-9_]*)\s*$',
    re.MULTILINE
)

_RE_INLINE_FUNC = re.compile(
    r'static\s+(?:ossl_unused\s+)?ossl_inline\s+'
    r'\w[\w\s*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(',
    re.MULTILINE
)

_RE_PERL_STACK = re.compile(
    r'generate_(?:const_)?stack_macros\(\s*"([^"]+)"\s*\)'
)

_RE_PERL_LHASH = re.compile(
    r'generate_lhash_macros\(\s*"([^"]+)"\s*\)'
)

_RE_C_STACK_OF = re.compile(
    r'DEFINE_(?:SPECIAL_)?STACK_OF(?:_CONST)?\s*\(\s*'
    r'([A-Za-z_][A-Za-z0-9_]*)'
)

_RE_C_LHASH_OF = re.compile(
    r'DEFINE_LHASH_OF(?:_INTERNAL)?\s*\(\s*'
    r'([A-Za-z_][A-Za-z0-9_]*)'
)


def extract_macros(header_dir: str,
                   version: Optional[str] = None) -> Dict:
    """
    Extract all OpenSSL function-like macros from a header directory.

    Args:
        header_dir: Path to OpenSSL include/openssl/ directory
        version: OpenSSL version string (auto-detected if not provided)

    Returns:
        Dict with macro data suitable for JSON serialization
    """
    headers = _read_headers(header_dir)
    logger.info("Read %d header files from %s", len(headers), header_dir)

    explicit = _extract_explicit_macros(headers)
    aliases = _extract_alias_macros(headers)
    inlines = _extract_inline_functions(headers)
    sk_types = _extract_stack_types(headers)
    lh_types = _extract_lhash_types(headers)

    sk_macros = _generate_sk_names(sk_types)
    lh_macros = _generate_lh_names(lh_types)

    all_names: Set[str] = set()
    all_names.update(explicit)
    all_names.update(aliases)
    all_names.update(inlines)
    all_names.update(sk_macros)
    all_names.update(lh_macros)

    logger.info(
        "Extracted %d macros: %d explicit, %d alias, %d inline, "
        "%d sk_template (%d types), %d lh_template (%d types)",
        len(all_names), len(explicit), len(aliases), len(inlines),
        len(sk_macros), len(sk_types), len(lh_macros), len(lh_types),
    )

    detected_ver = version or _detect_version(headers, header_dir)

    return {
        "openssl_version": detected_ver,
        "source": header_dir,
        "total_count": len(all_names),
        "categories": {
            "explicit_define": len(explicit),
            "alias_define": len(aliases),
            "inline_function": len(inlines),
            "sk_template": len(sk_macros),
            "lh_template": len(lh_macros),
        },
        "stack_of_types": sorted(sk_types),
        "lhash_of_types": sorted(lh_types),
        "macros": sorted(all_names),
    }


def _detect_version(headers: Dict[str, str],
                    header_dir: str = '') -> str:
    for fname in ('opensslv.h', 'opensslv.h.in'):
        content = headers.get(fname, '')
        m = re.search(
            r'OPENSSL_VERSION_STR\s+"(\d+\.\d+[^"]*)"', content
        )
        if m:
            return m.group(1)
        m = re.search(
            r'OPENSSL_VERSION_TEXT\s+"OpenSSL\s+(\d+\.\d+[^\s"]*)', content
        )
        if m:
            return m.group(1)

    if header_dir:
        path = os.path.normpath(header_dir)
        for part in reversed(path.split(os.sep)):
            m = re.match(r'[Oo]pen[Ss][Ss][Ll]-?(\d+\.\d+\.\d+\S*)', part)
            if m:
                return m.group(1)

    return "unknown"


def _read_headers(header_dir: str) -> Dict[str, str]:
    headers = {}
    for fname in sorted(os.listdir(header_dir)):
        if fname.endswith('.h') or fname.endswith('.h.in'):
            fpath = os.path.join(header_dir, fname)
            with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                headers[fname] = f.read()
    return headers


def _extract_explicit_macros(headers: Dict[str, str]) -> Set[str]:
    result: Set[str] = set()
    for content in headers.values():
        for m in _RE_FUNC_MACRO.finditer(content):
            name = m.group(1)
            if name not in _SKIP_MACROS and not name.startswith('_'):
                result.add(name)
    return result


def _extract_alias_macros(headers: Dict[str, str]) -> Set[str]:
    result: Set[str] = set()
    for content in headers.values():
        for m in _RE_ALIAS_MACRO.finditer(content):
            name = m.group(1)
            if name not in _SKIP_MACROS and not name.startswith('_'):
                if any(name.startswith(p) for p in OSSL_PREFIXES):
                    result.add(name)
    return result


def _extract_inline_functions(headers: Dict[str, str]) -> Set[str]:
    result: Set[str] = set()
    for content in headers.values():
        for m in _RE_INLINE_FUNC.finditer(content):
            name = m.group(1)
            if name.startswith('ossl_check_'):
                continue
            if any(name.startswith(p) for p in OSSL_PREFIXES):
                result.add(name)
    return result


def _extract_stack_types(headers: Dict[str, str]) -> List[str]:
    types: Set[str] = set()
    for content in headers.values():
        for m in _RE_PERL_STACK.finditer(content):
            types.add(m.group(1))
        for m in _RE_C_STACK_OF.finditer(content):
            t = m.group(1)
            if t not in ('t', 't1', 't2', 't3'):
                types.add(t)
    return sorted(types)


def _extract_lhash_types(headers: Dict[str, str]) -> List[str]:
    types: Set[str] = set()
    for content in headers.values():
        for m in _RE_PERL_LHASH.finditer(content):
            types.add(m.group(1))
        for m in _RE_C_LHASH_OF.finditer(content):
            t = m.group(1)
            if t != 'type':
                types.add(t)
    return sorted(types)


def _generate_sk_names(types: List[str]) -> Set[str]:
    result: Set[str] = set()
    for t in types:
        for suffix in SK_FUNC_SUFFIXES:
            result.add(f"sk_{t}_{suffix}")
    return result


def _generate_lh_names(types: List[str]) -> Set[str]:
    result: Set[str] = set()
    for t in types:
        for suffix in LH_FUNC_SUFFIXES:
            result.add(f"lh_{t}_{suffix}")
    return result
