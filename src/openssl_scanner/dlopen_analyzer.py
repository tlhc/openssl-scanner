"""
dlopen/dlsym OpenSSL detection for ELF binaries.

Detects dynamically loaded OpenSSL usage by:
1. Checking .dynsym for dlopen/dlsym imports
2. Extracting NULL-terminated strings from .rodata and similar sections
3. Matching strings against OpenSSL symbol names and library patterns
"""

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional, Set

from .constants import (
    DLOPEN_FUNCTION_NAMES,
    DLSYM_FUNCTION_NAMES,
    OPENSSL_LIBRARY_PATTERNS,
)

logger = logging.getLogger(__name__)

STRING_SECTIONS = ('.rodata', '.data.rel.ro', '.data')
MIN_STRING_LEN = 4
MAX_SECTION_SIZE = 64 * 1024 * 1024


@dataclass
class DlopenResult:
    """Results from dlopen/dlsym analysis of a single ELF."""
    uses_dlopen: bool = False
    uses_dlsym: bool = False
    dlopen_libs: List[str] = field(default_factory=list)
    dlsym_symbols: List[str] = field(default_factory=list)


def extract_c_strings(data: bytes, min_len: int = MIN_STRING_LEN) -> Set[str]:
    """
    Extract NULL-terminated printable ASCII strings from raw bytes.

    Splits on NULL bytes, keeps chunks where all bytes are printable
    ASCII (0x20-0x7e) and length >= min_len.
    """
    strings = set()
    for chunk in data.split(b'\x00'):
        if len(chunk) < min_len:
            continue
        try:
            s = chunk.decode('ascii')
        except UnicodeDecodeError:
            continue
        if s.isprintable():
            strings.add(s)
    return strings


def _is_openssl_lib_string(s: str, lib_patterns: List[str]) -> bool:
    """Check if a string looks like an OpenSSL library name or path."""
    basename = os.path.basename(s).lower()
    for pattern in lib_patterns:
        if basename.startswith(pattern):
            return True
    return False


def detect_dlopen_openssl(elf_path: str,
                          openssl_exports: Set[str],
                          lib_patterns: Optional[List[str]] = None,
                          ) -> Optional[DlopenResult]:
    """
    Analyze an ELF binary for dlopen/dlsym-based OpenSSL usage.

    Only scans .rodata when dlopen or dlsym is found in .dynsym UND.

    Args:
        elf_path: Path to the ELF file
        openssl_exports: Set of known OpenSSL symbol names
        lib_patterns: Library name prefixes (default: OPENSSL_LIBRARY_PATTERNS)

    Returns:
        DlopenResult with detected symbols and libraries, or None on error.
    """
    if lib_patterns is None:
        lib_patterns = OPENSSL_LIBRARY_PATTERNS

    try:
        from . import _vendor  # noqa: F401
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
        from elftools.common.exceptions import ELFError
    except ImportError:
        logger.warning("pyelftools not available for dlopen detection")
        return None

    try:
        with open(elf_path, 'rb') as f:
            magic = f.read(4)
            if magic != b'\x7fELF':
                return None
            f.seek(0)
            elf = ELFFile(f)

            has_dlopen = False
            has_dlsym = False
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                if section.name != '.dynsym':
                    continue
                for sym in section.iter_symbols():
                    name = sym.name
                    if not name:
                        continue
                    if sym['st_shndx'] != 'SHN_UNDEF':
                        continue
                    if name in DLOPEN_FUNCTION_NAMES:
                        has_dlopen = True
                    if name in DLSYM_FUNCTION_NAMES:
                        has_dlsym = True
                    if has_dlopen and has_dlsym:
                        break
                break

            if not has_dlopen and not has_dlsym:
                return DlopenResult()

            all_strings: Set[str] = set()
            for section_name in STRING_SECTIONS:
                section = elf.get_section_by_name(section_name)
                if section is None:
                    continue
                size = section.data_size
                if size > MAX_SECTION_SIZE:
                    logger.warning(
                        "Section %s in %s is %d bytes (>%dMB), skipping",
                        section_name, elf_path, size,
                        MAX_SECTION_SIZE // (1024 * 1024))
                    continue
                data = section.data()
                all_strings.update(extract_c_strings(data))

            dlsym_symbols = sorted(s for s in all_strings if s in openssl_exports)
            dlopen_libs = sorted(
                s for s in all_strings
                if _is_openssl_lib_string(s, lib_patterns)
            )

            return DlopenResult(
                uses_dlopen=has_dlopen,
                uses_dlsym=has_dlsym,
                dlopen_libs=dlopen_libs,
                dlsym_symbols=dlsym_symbols,
            )

    except (ELFError, IOError, OSError) as e:
        logger.debug("dlopen detection failed for %s: %s", elf_path, e)
        return None
