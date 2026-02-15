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
_NUL_CHUNK_RE = re.compile(rb'[^\x00]{4,}')

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
BORINGSSL_UNIQUE_ERRORS = [b'ECH_REJECTED', b'CHANNEL_ID_NOT_P256', b'WRONG_SIGNATURE_TYPE', b'NO_COMMON_SIGNATURE_ALGORITHMS']

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


def detect_static_ssl(file_path: str) -> StaticSSLResult:
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

    Returns:
        StaticSSLResult with detection details.
    """
    try:
        with open(file_path, 'rb') as f:
            file_size = f.seek(0, 2)
            f.seek(0)

            if file_size == 0:
                return StaticSSLResult()

            if file_size > _MAX_SCAN_SIZE:
                try:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        return _scan_data(mm)
                except ValueError:
                    return StaticSSLResult()
            else:
                data = f.read()
                return _scan_data(data)

    except (IOError, OSError) as e:
        logger.debug("Failed to scan %s for static SSL: %s", file_path, e)
        return StaticSSLResult()


def _scan_data(data) -> StaticSSLResult:
    """Scan bytes for SSL library signatures.

    Reordered for early exit: check cheap banner regexes first, only run
    expensive corroboration if a banner is found.
    """

    match = OPENSSL_STRICT_PATTERN.search(data)
    if match:
        version = match.group(1).decode('ascii')
        has_fvisibility = bool(FVISIBILITY_HIDDEN_PATTERN.search(data))
        has_openssldir = bool(OPENSSLDIR_PATTERN.search(data))
        has_enginesdir = bool(ENGINESDIR_PATTERN.search(data))
        sym_count, found_syms = _count_corroborating(data)
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

    boringssl_src_paths = len(BORINGSSL_SRC_PATTERN.findall(data))
    boringssl_unique_errors = sum(1 for err in BORINGSSL_UNIQUE_ERRORS if err in data)

    is_boringssl = (BORINGSSL_COMPAT_PATTERN.search(data)
                    or BORINGSSL_BARE_PATTERN.search(data))

    if boringssl_src_paths >= 3:
        is_boringssl = True
        has_fvisibility = bool(FVISIBILITY_HIDDEN_PATTERN.search(data))
        sym_count, found_syms = _count_corroborating(data)
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
        has_fvisibility = bool(FVISIBILITY_HIDDEN_PATTERN.search(data))
        sym_count, found_syms = _count_corroborating(data)
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

    libre_match = LIBRESSL_PATTERN.search(data)

    loose_match = OPENSSL_LOOSE_PATTERN.search(data)

    if not is_boringssl and not libre_match and not loose_match:
        return StaticSSLResult()

    has_fvisibility = bool(FVISIBILITY_HIDDEN_PATTERN.search(data))
    has_openssldir = bool(OPENSSLDIR_PATTERN.search(data))
    has_enginesdir = bool(ENGINESDIR_PATTERN.search(data))
    sym_count, found_syms = _count_corroborating(data)

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


def _count_corroborating(data):
    """Count and return corroborating symbol strings present in data.

    Uses regex-based string extraction + set intersection: O(file_size + |symbols|).
    Works on both bytes and mmap.mmap objects.
    """
    global CORROBORATING_SYMBOLS
    _load_probe_symbols()
    if CORROBORATING_SYMBOLS is None:
        CORROBORATING_SYMBOLS = _FALLBACK_SYMBOLS
    probe_strs = set()
    for sym in CORROBORATING_SYMBOLS:
        probe_strs.add(sym.decode('ascii') if isinstance(sym, bytes) else sym)

    strings = _extract_printable_strings(data)

    found = sorted(strings & probe_strs)
    return len(found), found


def _extract_printable_strings(data):
    """Extract printable ASCII strings (>=4 chars) from NUL-delimited binary data.

    Uses re.finditer on a pre-compiled pattern that matches sequences of 4+
    non-NUL bytes. Works on both bytes and mmap.mmap objects, avoiding the
    AttributeError from mmap.split() for files > _MAX_SCAN_SIZE.
    """
    strings = set()
    for m in _NUL_CHUNK_RE.finditer(data):
        chunk = m.group()
        try:
            s = chunk.decode('ascii')
        except UnicodeDecodeError:
            continue
        if s.isprintable():
            strings.add(s)
    return strings


def scan_hidden_static_symbols(file_path, openssl_exports):
    """Scan binary for all OpenSSL symbol name strings.

    Single-pass extraction: regex-iterate non-NUL chunks, decode printable
    ASCII, then intersect with openssl_exports via hash set lookup.
    Uses mmap for files > _MAX_SCAN_SIZE to avoid excessive memory usage.

    Args:
        file_path: Path to the binary file.
        openssl_exports: Full set of known OpenSSL export names (str).

    Returns:
        Sorted list of OpenSSL symbol names found as strings.
    """
    try:
        with open(file_path, 'rb') as f:
            file_size = f.seek(0, 2)
            f.seek(0)

            if file_size == 0:
                return []

            if file_size > _MAX_SCAN_SIZE:
                try:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
                        strings = _extract_printable_strings(data)
                except ValueError:
                    return []
            else:
                data = f.read()
                strings = _extract_printable_strings(data)
    except (IOError, OSError):
        return []

    found = strings & set(openssl_exports)
    return sorted(found)
