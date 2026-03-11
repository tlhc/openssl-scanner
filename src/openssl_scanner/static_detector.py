"""
Static OpenSSL/BoringSSL/LibreSSL detection module.

Detects statically linked SSL libraries by searching for version signatures
and corroborating with symbol string presence to avoid false positives.

Three-signal confidence model:
  Signal A: Version banner with date (high confidence alone)
  Signal B: Corroborating OpenSSL symbol-name strings (>= threshold)
  Signal C: -fvisibility=hidden compiler flag (strong indicator of hidden static)

Also detects OPENSSLDIR/ENGINESDIR compile-time paths as additional evidence.
"""

import re
import mmap
import logging
from dataclasses import dataclass, field
from typing import Optional, List

logger = logging.getLogger(__name__)

_MAX_SCAN_SIZE = 128 * 1024 * 1024
_NUL_PRINTABLE_RE = re.compile(rb'(?<=\x00)[\x20-\x7e]{4,}(?=\x00)')

OPENSSL_STRICT_PATTERN = re.compile(
    rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]*"
    rb"(?:-[a-z0-9.]+)?(?:\+[a-z0-9.]+)?)"
    rb"\s+\d{1,2}\s+[A-Z][a-z]{2}\s+\d{4}"
)

OPENSSL_LOOSE_PATTERN = re.compile(
    rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]*(?:-[a-z0-9.]+)?(?:\+[a-z0-9.]+)?)"
)

BORINGSSL_COMPAT_PATTERN = re.compile(
    rb"OpenSSL\s+\d+\.\d+\.\d+\s+\(compatible;\s*BoringSSL\)"
)
BORINGSSL_BARE_PATTERN = re.compile(rb"BoringSSL")

LIBRESSL_PATTERN = re.compile(
    rb"LibreSSL\s+(\d+\.\d+\.\d+)"
)

FVISIBILITY_HIDDEN_PATTERN = re.compile(rb"-fvisibility=hidden")
OPENSSLDIR_PATTERN = re.compile(rb"OPENSSLDIR:")
ENGINESDIR_PATTERN = re.compile(rb"ENGINESDIR:")

BORINGSSL_SRC_PATTERN = re.compile(rb'boringssl/src/(?:crypto|ssl)/')

_DETECT_KW_RE = re.compile(
    r'OpenSSL|BoringSSL|LibreSSL|boringssl/src/|-fvisibility=hidden|OPENSSLDIR:|ENGINESDIR:'
)

# BoringSSL-unique TLS error reason strings. Verified against:
#   BoringSSL: crypto/err/ssl.errordata (Feb 2026)
#   OpenSSL master/3.5/3.4/3.2/1.1.1w: crypto/err/openssl.txt + include/openssl/sslerr.h
# WRONG_SIGNATURE_TYPE excluded: also in OpenSSL as SSL_R_WRONG_SIGNATURE_TYPE (code 370).
BORINGSSL_UNIQUE_ERRORS = [
    b'ECH_REJECTED',                          # BoringSSL SSL,319 -- OpenSSL uses ECH_REQUIRED (different string)
    b'NO_COMMON_SIGNATURE_ALGORITHMS',        # BoringSSL SSL,253 -- OpenSSL uses NO_SUITABLE_SIGNATURE_ALGORITHM
    b'CHANNEL_ID_NOT_P256',                   # TLS Channel ID: Google extension, never in OpenSSL
    b'CHANNEL_ID_SIGNATURE_INVALID',          # TLS Channel ID: Google extension, never in OpenSSL
    b'ALPS_MISMATCH_ON_EARLY_DATA',           # ALPS extension: BoringSSL/Google only
    b'INVALID_ALPS_CODEPOINT',                # ALPS extension: BoringSSL/Google only
    b'NEGOTIATED_ALPS_WITHOUT_ALPN',          # ALPS extension: BoringSSL/Google only
    b'ECH_SERVER_WOULD_HAVE_NO_RETRY_CONFIGS', # ECH: BoringSSL-specific variant, not in OpenSSL
    b'COULD_NOT_PARSE_HINTS',                 # Split-handshake hints: BoringSSL only
]

_BORING_ERROR_STRS = frozenset(
    e.decode('ascii') for e in BORINGSSL_UNIQUE_ERRORS
)

CORROBORATING_SYMBOLS = None
_CORROBORATING_LOADED = False

_FALLBACK_SYMBOLS = {
    b"SSL_CTX_new",
    b"SSL_connect",
    b"EVP_EncryptInit",
    b"EVP_DigestInit",
    b"BIO_new_socket",
    b"X509_free",
    b"RSA_public_encrypt",
    b"SHA256_Update",
    b"ERR_get_error",
    b"OPENSSL_init_ssl",
    b"RAND_bytes",
    b"EC_KEY_new",
    b"BN_CTX_new",
    b"DH_generate_parameters_ex",
    b"PEM_read_bio_PrivateKey",
    b"HMAC_Init_ex",
}

MIN_CORROBORATING_COUNT = 3
_PROBE_PER_CATEGORY = 2
_MIN_PROBE_LENGTH = 12


@dataclass
class StaticSSLResult:
    """Detection result for statically linked SSL library."""
    detected: bool = False
    library: str = ''
    version: str = ''
    signals: List[str] = field(default_factory=list)
    fvisibility_hidden: bool = False
    found_symbols: List[str] = field(default_factory=list)


@dataclass
class FingerprintResult:
    """Result of .rodata fingerprint-based OpenSSL detection."""
    score: float = 0.0
    confidence: str = ''
    library: str = ''
    category_scores: dict = field(default_factory=dict)
    matched_count: int = 0
    total_candidates: int = 0


def detect_static_openssl(file_path: str) -> Optional[str]:
    """
    Detect statically linked OpenSSL and return the version string.

    Backward-compatible wrapper that returns just the version string.

    Args:
        file_path: Path to the binary file.

    Returns:
        Version string (e.g., "1.1.1t") if detected, None otherwise.
    """
    result = detect_static_ssl(file_path)
    if result.detected:
        return result.version
    return None


def detect_boringssl_weak_symbols(symbol_names):
    """Check for BoringSSL OPENSSL_memory_* weak symbols.

    Args:
        symbol_names: iterable of symbol name strings from .dynsym
    Returns:
        bool: True if BoringSSL weak symbols detected
    """
    BORINGSSL_WEAK = {'OPENSSL_memory_alloc', 'OPENSSL_memory_free', 'OPENSSL_memory_get_size'}
    return len(BORINGSSL_WEAK & set(symbol_names)) >= 2


def detect_static_ssl(file_path: str, *, _raw_data=None,
                      _strings=None) -> StaticSSLResult:
    """
    Detect statically linked SSL library with full signal details.

    Strategy:
    1. Scan for strict OpenSSL banner (version + date) -> high confidence
    2. Scan for BoringSSL/LibreSSL banners
    3. If only loose OpenSSL banner found, require corroboration:
       symbols >= threshold, or -fvisibility=hidden + symbols >= 1,
       or OPENSSLDIR/ENGINESDIR paths + symbols >= 1
    4. Record -fvisibility=hidden presence as a signal

    Args:
        file_path: Path to the binary file.
        _raw_data: Pre-loaded file bytes (skips file open if provided).
        _strings: Pre-extracted printable strings (avoids re-extraction).

    Returns:
        StaticSSLResult with detection details.
    """
    if _raw_data is not None:
        return _scan_data(_raw_data, _strings=_strings)

    try:
        with open(file_path, 'rb') as f:
            file_size = f.seek(0, 2)
            f.seek(0)

            if file_size == 0:
                return StaticSSLResult()

            if file_size > _MAX_SCAN_SIZE:
                try:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        return _scan_data(mm, _strings=_strings)
                except ValueError:
                    return StaticSSLResult()
            else:
                data = f.read()
                return _scan_data(data, _strings=_strings)

    except (IOError, OSError) as e:
        logger.debug("Failed to scan %s for static SSL: %s", file_path, e)
        return StaticSSLResult()


def _classify_ssl_strings(strings):
    """Single-pass classification of pre-extracted strings for SSL detection.

    Iterates the string set once using a compiled alternation regex to
    categorize strings by SSL library keyword. Replaces 9+ individual
    pattern.search() calls on the full raw binary data (each ~90ms on
    346MB) with one pass over the string set (~125ms) plus regex on
    <30 candidates (~0ms).
    """
    openssl = []
    boringssl = []
    libressl = []
    boring_src = 0
    has_fvisibility = False
    has_openssldir = False
    has_enginesdir = False

    for s in strings:
        if 'SSL' not in s and 'ssl' not in s and '-fvisibility' not in s and 'ENGINESDIR' not in s:
            continue
        m = _DETECT_KW_RE.search(s)
        if not m:
            continue
        kw = m.group()
        if kw == 'OpenSSL':
            openssl.append(s)
            if 'BoringSSL' in s:
                boringssl.append(s)
        elif kw == 'BoringSSL':
            boringssl.append(s)
        elif kw == 'LibreSSL':
            libressl.append(s)
        elif kw == 'boringssl/src/':
            if BORINGSSL_SRC_PATTERN.search(s.encode('ascii')):
                boring_src += 1
        elif kw == '-fvisibility=hidden':
            has_fvisibility = True
        elif kw == 'OPENSSLDIR:':
            has_openssldir = True
        elif kw == 'ENGINESDIR:':
            has_enginesdir = True

    boring_errors = len(_BORING_ERROR_STRS & strings)

    return {
        'openssl': openssl,
        'boringssl': boringssl,
        'libressl': libressl,
        'boring_src': boring_src,
        'boring_errors': boring_errors,
        'has_fvisibility': has_fvisibility,
        'has_openssldir': has_openssldir,
        'has_enginesdir': has_enginesdir,
    }


def _scan_data(data, *, _strings=None) -> StaticSSLResult:
    """Scan bytes for SSL library signatures.

    When _strings is provided, classifies the string set in a single pass
    and runs pattern regex only on small candidate lists (~125ms total
    instead of ~1200ms for 9+ pattern scans on 346MB raw data).

    Falls back to direct raw-data scanning when _strings is not available.
    """
    cl = _classify_ssl_strings(_strings) if _strings is not None else None

    def _pat_search(pattern, cl_key):
        if cl is not None:
            for s in cl[cl_key]:
                m = pattern.search(s.encode('ascii'))
                if m:
                    return m
            return None
        return pattern.search(data)

    def _pat_bool(cl_key, pattern):
        if cl is not None:
            return cl[cl_key]
        return bool(pattern.search(data))

    match = _pat_search(OPENSSL_STRICT_PATTERN, 'openssl')
    if match:
        version = match.group(1).decode('ascii')
        has_fvisibility = _pat_bool('has_fvisibility', FVISIBILITY_HIDDEN_PATTERN)
        has_openssldir = _pat_bool('has_openssldir', OPENSSLDIR_PATTERN)
        has_enginesdir = _pat_bool('has_enginesdir', ENGINESDIR_PATTERN)
        sym_count, found_syms = _count_corroborating(data, _strings=_strings)
        signals = ['version_banner_strict']
        if has_fvisibility:
            signals.append('fvisibility_hidden')
        if has_openssldir:
            signals.append('openssldir')
        if has_enginesdir:
            signals.append('enginesdir')
        if sym_count > 0:
            signals.append('corroborating_symbols_%d' % sym_count)
        return StaticSSLResult(
            detected=True, library='OpenSSL', version=version,
            signals=signals, fvisibility_hidden=has_fvisibility,
            found_symbols=found_syms,
        )

    if cl is not None:
        boringssl_src_paths = cl['boring_src']
        boringssl_unique_errors = cl['boring_errors']
        is_boringssl = bool(cl['boringssl'])
    else:
        boringssl_src_paths = len(BORINGSSL_SRC_PATTERN.findall(data))
        boringssl_unique_errors = sum(
            1 for err in BORINGSSL_UNIQUE_ERRORS if err in data)
        is_boringssl = bool(BORINGSSL_COMPAT_PATTERN.search(data)
                            or BORINGSSL_BARE_PATTERN.search(data))

    if boringssl_src_paths >= 3:
        is_boringssl = True
        has_fvisibility = _pat_bool('has_fvisibility', FVISIBILITY_HIDDEN_PATTERN)
        sym_count, found_syms = _count_corroborating(data, _strings=_strings)
        signals = ['boringssl_src_paths']
        if has_fvisibility:
            signals.append('fvisibility_hidden')
        if sym_count > 0:
            signals.append('corroborating_symbols_%d' % sym_count)
        return StaticSSLResult(
            detected=True, library='BoringSSL', version=None,
            signals=signals, fvisibility_hidden=has_fvisibility,
            found_symbols=found_syms,
        )

    if boringssl_unique_errors >= 2:
        is_boringssl = True
        has_fvisibility = _pat_bool('has_fvisibility', FVISIBILITY_HIDDEN_PATTERN)
        sym_count, found_syms = _count_corroborating(data, _strings=_strings)
        signals = ['boringssl_unique_errors']
        if has_fvisibility:
            signals.append('fvisibility_hidden')
        if sym_count > 0:
            signals.append('corroborating_symbols_%d' % sym_count)
        return StaticSSLResult(
            detected=True, library='BoringSSL', version=None,
            signals=signals, fvisibility_hidden=has_fvisibility,
            found_symbols=found_syms,
        )

    libre_match = _pat_search(LIBRESSL_PATTERN, 'libressl')

    loose_match = _pat_search(OPENSSL_LOOSE_PATTERN, 'openssl')

    if not is_boringssl and not libre_match and not loose_match:
        return StaticSSLResult()

    has_fvisibility = _pat_bool('has_fvisibility', FVISIBILITY_HIDDEN_PATTERN)
    has_openssldir = _pat_bool('has_openssldir', OPENSSLDIR_PATTERN)
    has_enginesdir = _pat_bool('has_enginesdir', ENGINESDIR_PATTERN)
    sym_count, found_syms = _count_corroborating(data, _strings=_strings)

    if is_boringssl:
        if sym_count >= MIN_CORROBORATING_COUNT or has_fvisibility:
            signals = ['boringssl_banner']
            if has_fvisibility:
                signals.append('fvisibility_hidden')
            if sym_count > 0:
                signals.append('corroborating_symbols_%d' % sym_count)
            return StaticSSLResult(
                detected=True, library='BoringSSL', version=None,
                signals=signals, fvisibility_hidden=has_fvisibility,
                found_symbols=found_syms,
            )

    if libre_match:
        version = libre_match.group(1).decode('ascii')
        if sym_count >= MIN_CORROBORATING_COUNT or has_fvisibility:
            signals = ['libressl_banner']
            if has_fvisibility:
                signals.append('fvisibility_hidden')
            if sym_count > 0:
                signals.append('corroborating_symbols_%d' % sym_count)
            return StaticSSLResult(
                detected=True, library='LibreSSL', version=version,
                signals=signals, fvisibility_hidden=has_fvisibility,
                found_symbols=found_syms,
            )

    if loose_match:
        version = loose_match.group(1).decode('ascii')

        if sym_count >= MIN_CORROBORATING_COUNT:
            signals = ['version_banner_loose',
                        'corroborating_symbols_%d' % sym_count]
            if has_fvisibility:
                signals.append('fvisibility_hidden')
            if has_openssldir:
                signals.append('openssldir')
            return StaticSSLResult(
                detected=True, library='OpenSSL', version=version,
                signals=signals, fvisibility_hidden=has_fvisibility,
                found_symbols=found_syms,
            )

        if has_fvisibility and sym_count >= 1:
            signals = ['version_banner_loose', 'fvisibility_hidden',
                        'corroborating_symbols_%d' % sym_count]
            if has_openssldir:
                signals.append('openssldir')
            return StaticSSLResult(
                detected=True, library='OpenSSL', version=version,
                signals=signals, fvisibility_hidden=has_fvisibility,
                found_symbols=found_syms,
            )

        if (has_openssldir or has_enginesdir) and sym_count >= 1:
            signals = ['version_banner_loose']
            if has_openssldir:
                signals.append('openssldir')
            if has_enginesdir:
                signals.append('enginesdir')
            signals.append('corroborating_symbols_%d' % sym_count)
            if has_fvisibility:
                signals.append('fvisibility_hidden')
            return StaticSSLResult(
                detected=True, library='OpenSSL', version=version,
                signals=signals, fvisibility_hidden=has_fvisibility,
                found_symbols=found_syms,
            )

    return StaticSSLResult()


def _load_probe_symbols():
    """Load representative probe symbols from built-in data.

    Picks _PROBE_PER_CATEGORY long symbols (>= _MIN_PROBE_LENGTH chars)
    from each category in SYMBOL_CATEGORIES. Falls back to _FALLBACK_SYMBOLS
    if the data files cannot be loaded.
    """
    global CORROBORATING_SYMBOLS, _CORROBORATING_LOADED
    if _CORROBORATING_LOADED:
        return

    try:
        import json
        import os

        from .constants import SYMBOL_CATEGORIES

        data_dir = os.path.join(os.path.dirname(__file__), 'data')
        sym_path = os.path.join(data_dir, 'openssl_symbols.json')

        with open(sym_path) as f:
            data = json.load(f)
        all_symbols = data.get('symbols', [])

        by_cat = {}
        for sym in all_symbols:
            if len(sym) < _MIN_PROBE_LENGTH:
                continue
            for cat, prefixes in SYMBOL_CATEGORIES.items():
                for pfx in prefixes:
                    if sym.startswith(pfx):
                        if cat not in by_cat:
                            by_cat[cat] = []
                        by_cat[cat].append(sym)
                        break
                else:
                    continue
                break

        probe = set()
        for cat in sorted(by_cat.keys()):
            syms = sorted(by_cat[cat])
            for s in syms[:_PROBE_PER_CATEGORY]:
                probe.add(s.encode('ascii'))

        probe.update(_FALLBACK_SYMBOLS)

        if len(probe) >= 10:
            CORROBORATING_SYMBOLS = probe
            logger.debug("Loaded %d probe symbols (%d built-in + %d sentinel) "
                         "from %d categories",
                         len(probe), len(probe) - len(_FALLBACK_SYMBOLS),
                         len(_FALLBACK_SYMBOLS), len(by_cat))
        else:
            CORROBORATING_SYMBOLS = _FALLBACK_SYMBOLS

    except Exception as e:
        logger.debug("Failed to load probe symbols: %s, using fallback", e)
        CORROBORATING_SYMBOLS = _FALLBACK_SYMBOLS

    _CORROBORATING_LOADED = True


def _count_corroborating(data, _strings=None):
    """Count and return corroborating symbol strings present in data.

    Uses regex-based string extraction + set intersection: O(file_size + |symbols|).
    Works on both bytes and mmap.mmap objects.

    If _strings is provided, reuses the pre-extracted string set instead of
    re-scanning the raw data.
    """
    global CORROBORATING_SYMBOLS
    _load_probe_symbols()
    if CORROBORATING_SYMBOLS is None:
        CORROBORATING_SYMBOLS = _FALLBACK_SYMBOLS
    probe_strs = set()
    for sym in CORROBORATING_SYMBOLS:
        probe_strs.add(sym.decode('ascii') if isinstance(sym, bytes) else sym)

    if _strings is not None:
        strings = _strings
    else:
        strings = _extract_printable_strings(data)

    found = sorted(strings & probe_strs)
    return len(found), found


def _extract_printable_strings(data):
    """Extract printable ASCII strings (>=4 chars) from NUL-delimited binary data.

    Matches runs of printable ASCII (0x20-0x7e) bounded by NUL bytes.
    The NUL-boundary requirement prevents false positives from short symbol
    names (e.g. SHA1, RC4) that can appear as byte subsequences in compiled
    code or DWARF data.

    Works on both bytes and mmap.mmap objects.
    """
    return set(s.decode('ascii') for s in _NUL_PRINTABLE_RE.findall(data))


def _read_strings_from_file(file_path):
    """Extract printable strings from a binary file.

    Handles mmap fallback for large files (> _MAX_SCAN_SIZE).

    Returns:
        Set of strings, or None on error.
    """
    try:
        with open(file_path, 'rb') as f:
            file_size = f.seek(0, 2)
            f.seek(0)
            if file_size == 0:
                return None
            if file_size > _MAX_SCAN_SIZE:
                try:
                    with mmap.mmap(f.fileno(), 0,
                                   access=mmap.ACCESS_READ) as data:
                        return _extract_printable_strings(data)
                except ValueError:
                    return None
            else:
                data = f.read()
                return _extract_printable_strings(data)
    except (IOError, OSError):
        return None


def scan_hidden_static_symbols(file_path, openssl_exports, *, _strings=None):
    """Scan binary for all OpenSSL symbol name strings.

    Single-pass extraction: regex-iterate non-NUL chunks, decode printable
    ASCII, then intersect with openssl_exports via hash set lookup.
    Uses mmap for files > _MAX_SCAN_SIZE to avoid excessive memory usage.

    Args:
        file_path: Path to the binary file.
        openssl_exports: Full set of known OpenSSL export names (str).
        _strings: Pre-extracted printable strings (avoids re-reading file).

    Returns:
        Sorted list of OpenSSL symbol names found as strings.
    """
    if _strings is not None:
        strings = _strings
    else:
        strings = _read_strings_from_file(file_path)
    if strings is None:
        return []
    found = strings & set(openssl_exports)
    return sorted(found)


_FINGERPRINT_DATA = None
_FINGERPRINT_LOADED = False


def _load_fingerprint_data():
    """Load fingerprint data from data/openssl_fingerprints.json."""
    global _FINGERPRINT_DATA, _FINGERPRINT_LOADED
    if _FINGERPRINT_LOADED:
        return
    try:
        import json
        import os as _os
        data_dir = _os.path.join(_os.path.dirname(__file__), 'data')
        fp_path = _os.path.join(data_dir, 'openssl_fingerprints.json')
        with open(fp_path) as f:
            raw = json.load(f)
        cats = raw.get('categories', {})
        if not isinstance(cats, dict):
            raise ValueError("categories must be a dict")
        for name, info in cats.items():
            if not isinstance(info.get('strings', []), list):
                raise ValueError("category %s: strings must be a list" % name)
            info['per_point'] = float(info.get('per_point', 0))
            info['max_points'] = float(info.get('max_points', 0))
        _FINGERPRINT_DATA = raw
        logger.debug("Loaded fingerprint data: %d categories", len(cats))
    except Exception as e:
        logger.debug("Failed to load fingerprint data: %s", e)
        _FINGERPRINT_DATA = None
    _FINGERPRINT_LOADED = True


def _infer_library_from_fingerprint(cat_scores):
    """Infer SSL library variant from per-library fingerprint scores.

    Data-driven: each category in the fingerprint JSON may carry a
    'library' tag (e.g. "BoringSSL", "OpenSSL"). The scorer records
    this tag into cat_scores. This function tallies capped scores
    per library and returns the one with the highest total.
    Falls back to 'OpenSSL' when no library-tagged categories matched.
    """
    lib_scores = {}
    for info in cat_scores.values():
        lib = info.get('library')
        if lib:
            lib_scores[lib] = lib_scores.get(lib, 0) + info['capped']
    if not lib_scores:
        return 'OpenSSL'
    return max(lib_scores, key=lib_scores.get)


def score_openssl_fingerprint(file_path, *, _strings=None):
    """Score a binary for OpenSSL-family fingerprint strings in .rodata.

    Extracts NUL-terminated strings from the file and matches against
    the fingerprint database (~130 strings across 7 categories covering
    OpenSSL, BoringSSL, and LibreSSL). Each match earns per-string points,
    capped per category. Total max score is 100.

    Categories use exact match by default. Categories with
    match_mode=substring check if any extracted string contains the
    fingerprint substring (e.g. BoringSSL source paths have a different
    prefix but share the crypto/*.c suffix with OpenSSL).

    Args:
        file_path: Path to the binary file.
        _strings: Pre-extracted printable strings (avoids re-reading file).

    Returns:
        FingerprintResult with score, confidence, and per-category breakdown.
    """
    _load_fingerprint_data()
    if _FINGERPRINT_DATA is None:
        return FingerprintResult()

    categories = _FINGERPRINT_DATA.get('categories', {})
    thresholds = _FINGERPRINT_DATA.get('thresholds', {})
    if not categories:
        return FingerprintResult()

    if _strings is not None:
        strings = _strings
    else:
        strings = _read_strings_from_file(file_path)
    if strings is None:
        return FingerprintResult()

    total_score = 0.0
    total_matched = 0
    total_candidates = 0
    cat_scores = {}

    for cat_name, cat_info in categories.items():
        per_point = cat_info.get('per_point', 0)
        max_points = cat_info.get('max_points', 0)
        cat_strings = cat_info.get('strings', [])
        match_mode = cat_info.get('match_mode', 'exact')
        total_candidates += len(cat_strings)

        matched = 0
        if match_mode == 'substring':
            for s in cat_strings:
                for extracted in strings:
                    if s in extracted:
                        matched += 1
                        break
        else:
            for s in cat_strings:
                if s in strings:
                    matched += 1
        if matched == 0:
            continue

        raw = matched * per_point
        capped = min(raw, max_points)
        entry = {
            'matched': matched,
            'total': len(cat_strings),
            'raw': round(raw, 2),
            'capped': round(capped, 2),
        }
        library_tag = cat_info.get('library')
        if library_tag:
            entry['library'] = library_tag
        cat_scores[cat_name] = entry
        total_score += capped
        total_matched += matched

    total_score = round(total_score, 2)
    high_th = thresholds.get('high', 60)
    medium_th = thresholds.get('medium', 30)
    low_th = thresholds.get('low', 15)

    if total_score >= high_th:
        confidence = 'high'
    elif total_score >= medium_th:
        confidence = 'medium'
    elif total_score >= low_th:
        confidence = 'low'
    else:
        confidence = ''

    library = ''
    if confidence:
        library = _infer_library_from_fingerprint(cat_scores)

    max_possible = _FINGERPRINT_DATA.get('max_score', 100)
    total_score = round(total_score / max_possible * 100, 1)

    return FingerprintResult(
        score=total_score,
        confidence=confidence,
        library=library,
        category_scores=cat_scores,
        matched_count=total_matched,
        total_candidates=total_candidates,
    )
