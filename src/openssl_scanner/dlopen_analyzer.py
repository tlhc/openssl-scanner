"""
dlopen/dlsym OpenSSL detection for ELF binaries.

Three-layer detection for accuracy:
  Layer A: .dynsym exclusion - exclude symbols already in .dynsym
  Layer B: String clustering - group matches by byte proximity
  Layer C: Disassembly cross-reference - trace dlsym call arguments

Detects dynamically loaded OpenSSL usage by:
1. Checking .dynsym for dlopen/dlsym imports
2. Extracting NULL-terminated strings from .rodata and similar sections
3. Matching strings against OpenSSL symbol names and library patterns
4. Filtering via exclude set, clustering, and disassembly confirmation
"""

import logging
import os
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

from .constants import (
    DLOPEN_FUNCTION_NAMES,
    DLSYM_FUNCTION_NAMES,
    OPENSSL_LIBRARY_PATTERNS,
)

logger = logging.getLogger(__name__)

STRING_SECTIONS = ('.rodata', '.data.rel.ro', '.data')
MIN_STRING_LEN = 4
MAX_SECTION_SIZE = 64 * 1024 * 1024
MAX_TEXT_SIZE = 64 * 1024 * 1024

CLUSTER_MAX_GAP = 256
CLUSTER_MIN_SIZE = 3

_AARCH64_PLT_HEADER_SIZE = 32
_AARCH64_PLT_ENTRY_SIZE = 16
_AARCH64_BL_MASK = 0xFC000000
_AARCH64_BL_OPCODE = 0x94000000
_AARCH64_ADRP_MASK = 0x9F000000
_AARCH64_ADRP_OPCODE = 0x90000000
_AARCH64_ADD_IMM_MASK = 0xFF800000
_AARCH64_ADD_IMM_OPCODE = 0x91000000

_X86_64_PLT_HEADER_SIZE = 16
_X86_64_PLT_ENTRY_SIZE = 16
_X86_64_CALL_REL32 = 0xE8
_X86_64_LEA_RSI_RIP = bytes([0x48, 0x8D, 0x35])

_MAX_BACKWARD_INSTRS = 16
_MAX_BACKWARD_BYTES = 64


@dataclass
class DlopenResult:
    """Results from dlopen/dlsym analysis of a single ELF."""
    uses_dlopen: bool = False
    uses_dlsym: bool = False
    dlopen_libs: List[str] = field(default_factory=list)
    dlsym_symbols: List[str] = field(default_factory=list)
    confidence: str = 'high'


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


def extract_c_strings_with_offsets(
    data: bytes, min_len: int = MIN_STRING_LEN,
) -> List[Tuple[int, str]]:
    """
    Extract NULL-terminated printable ASCII strings with byte offsets.

    Returns list of (byte_offset, string) tuples, ordered by offset.
    The offset is relative to the start of the data buffer.
    """
    results = []
    offset = 0
    for chunk in data.split(b'\x00'):
        if len(chunk) >= min_len:
            try:
                s = chunk.decode('ascii')
            except UnicodeDecodeError:
                pass
            else:
                if s.isprintable():
                    results.append((offset, s))
        offset += len(chunk) + 1
    return results


def _cluster_symbols(
    strings_with_offsets: List[Tuple[int, str]],
    candidates: Set[str],
    max_gap: int = CLUSTER_MAX_GAP,
    min_cluster: int = CLUSTER_MIN_SIZE,
) -> Set[str]:
    """
    Group candidate matches by byte proximity in section data.

    Real dlsym dispatch tables produce dense clusters of OpenSSL symbol
    strings in .rodata. Isolated matches are likely error messages or
    debug strings.

    Args:
        strings_with_offsets: (byte_offset, string) pairs from section
        candidates: OpenSSL symbol names to look for
        max_gap: Maximum byte gap between adjacent cluster members
        min_cluster: Minimum cluster size to trust

    Returns:
        Set of symbol names found in qualifying clusters.
    """
    matched = [(off, s) for off, s in strings_with_offsets if s in candidates]
    if len(matched) < min_cluster:
        return set()

    matched.sort(key=lambda x: x[0])

    result = set()
    cluster_start = 0
    for i in range(1, len(matched)):
        if matched[i][0] - matched[i - 1][0] > max_gap:
            if i - cluster_start >= min_cluster:
                result.update(s for _, s in matched[cluster_start:i])
            cluster_start = i

    if len(matched) - cluster_start >= min_cluster:
        result.update(s for _, s in matched[cluster_start:])

    return result


def _read_cstring(data: bytes, offset: int) -> Optional[str]:
    """Read a NULL-terminated ASCII string from data at offset."""
    if offset < 0 or offset >= len(data):
        return None
    end = data.find(b'\x00', offset)
    if end < 0:
        end = len(data)
    chunk = data[offset:end]
    if len(chunk) < MIN_STRING_LEN:
        return None
    try:
        s = chunk.decode('ascii')
    except UnicodeDecodeError:
        return None
    return s if s.isprintable() else None


def _find_dlsym_plt_addr(elf) -> Tuple[Optional[int], Optional[str]]:
    """
    Find the PLT entry virtual address for dlsym.

    Resolves through .dynsym symbol index -> .rela.plt relocation
    index -> .plt entry address.

    Returns:
        (plt_vaddr, arch_name) or (None, arch_name) if not found.
        arch_name is 'aarch64', 'x86_64', or None.
    """
    machine = elf.header.e_machine
    if machine == 'EM_AARCH64':
        arch = 'aarch64'
        header_size = _AARCH64_PLT_HEADER_SIZE
        entry_size = _AARCH64_PLT_ENTRY_SIZE
    elif machine == 'EM_X86_64':
        arch = 'x86_64'
        header_size = _X86_64_PLT_HEADER_SIZE
        entry_size = _X86_64_PLT_ENTRY_SIZE
    else:
        return None, None

    dynsym = elf.get_section_by_name('.dynsym')
    if not dynsym:
        return None, arch

    dlsym_idx = None
    for i, sym in enumerate(dynsym.iter_symbols()):
        name = sym.name if hasattr(sym, 'name') else ''
        if name in DLSYM_FUNCTION_NAMES:
            try:
                shndx = sym['st_shndx']
            except (KeyError, TypeError):
                shndx = None
            if shndx == 'SHN_UNDEF':
                dlsym_idx = i
                break
    if dlsym_idx is None:
        return None, arch

    rela_plt = elf.get_section_by_name('.rela.plt')
    if rela_plt is None:
        rela_plt = elf.get_section_by_name('.rel.plt')
    if rela_plt is None:
        return None, arch

    plt = elf.get_section_by_name('.plt')
    if plt is None:
        return None, arch

    try:
        plt_base = plt['sh_addr']
    except (KeyError, TypeError):
        return None, arch

    for idx, rel in enumerate(rela_plt.iter_relocations()):
        try:
            sym_idx = rel['r_info_sym']
        except (KeyError, TypeError):
            continue
        if sym_idx == dlsym_idx:
            addr = plt_base + header_size + idx * entry_size
            return addr, arch

    return None, arch


def _resolve_aarch64_dlsym_addrs(
    text_data: bytes, text_vaddr: int, dlsym_plt_addr: int,
) -> Set[int]:
    """
    Scan aarch64 .text for BL dlsym@plt, decode preceding ADRP+ADD
    to find the virtual address of the second argument (X1).

    ARM64 calling convention: X0=arg1, X1=arg2.
    Pattern: ADRP X1, #page; ADD X1, X1, #lo12; BL dlsym@plt

    Returns set of resolved virtual addresses pointing into .rodata.
    """
    resolved = set()
    n_instrs = len(text_data) // 4

    for i in range(n_instrs):
        insn = struct.unpack_from('<I', text_data, i * 4)[0]

        if (insn & _AARCH64_BL_MASK) != _AARCH64_BL_OPCODE:
            continue

        imm26 = insn & 0x03FFFFFF
        if imm26 >= 0x02000000:
            imm26 -= 0x04000000

        bl_pc = text_vaddr + i * 4
        target = bl_pc + imm26 * 4

        if target != dlsym_plt_addr:
            continue

        adrp_val = None
        add_imm = None
        scan_start = max(0, i - _MAX_BACKWARD_INSTRS)

        for j in range(i - 1, scan_start - 1, -1):
            prev = struct.unpack_from('<I', text_data, j * 4)[0]
            rd = prev & 0x1F

            if rd != 1:
                continue

            if add_imm is None and \
               (prev & _AARCH64_ADD_IMM_MASK) == _AARCH64_ADD_IMM_OPCODE:
                rn = (prev >> 5) & 0x1F
                if rn == 1:
                    shift = (prev >> 22) & 0x3
                    imm12 = (prev >> 10) & 0xFFF
                    add_imm = imm12 << (12 if shift == 1 else 0)

            if adrp_val is None and \
               (prev & _AARCH64_ADRP_MASK) == _AARCH64_ADRP_OPCODE:
                immlo = (prev >> 29) & 0x3
                immhi = (prev >> 5) & 0x7FFFF
                imm21 = (immhi << 2) | immlo
                if imm21 >= 0x100000:
                    imm21 -= 0x200000
                adrp_pc = text_vaddr + j * 4
                adrp_val = (adrp_pc & ~0xFFF) + (imm21 << 12)

            if adrp_val is not None and add_imm is not None:
                resolved.add(adrp_val + add_imm)
                break

    return resolved


def _resolve_x86_64_dlsym_addrs(
    text_data: bytes, text_vaddr: int, dlsym_plt_addr: int,
) -> Set[int]:
    """
    Scan x86_64 .text for CALL dlsym@plt, decode preceding LEA RSI
    to find the virtual address of the second argument (RSI).

    System V AMD64 ABI: RDI=arg1, RSI=arg2.
    Pattern: LEA RSI,[RIP+disp32]; CALL dlsym@plt

    Returns set of resolved virtual addresses pointing into .rodata.
    """
    resolved = set()
    text_len = len(text_data)
    i = 0

    while i < text_len - 4:
        if text_data[i] != _X86_64_CALL_REL32:
            i += 1
            continue

        rel32 = struct.unpack_from('<i', text_data, i + 1)[0]
        call_vaddr = text_vaddr + i
        target = call_vaddr + 5 + rel32

        if target != dlsym_plt_addr:
            i += 1
            continue

        scan_start = max(0, i - _MAX_BACKWARD_BYTES)
        for j in range(i - 7, scan_start - 1, -1):
            if j < 0:
                break
            if text_data[j:j + 3] == _X86_64_LEA_RSI_RIP:
                disp32 = struct.unpack_from('<i', text_data, j + 3)[0]
                lea_vaddr = text_vaddr + j
                str_addr = lea_vaddr + 7 + disp32
                resolved.add(str_addr)
                break

        i += 5

    return resolved


def _resolve_dlsym_strings(
    elf, candidates: Set[str],
    section_ranges: List[Tuple[int, bytes]],
) -> Set[str]:
    """
    Use disassembly to find strings actually passed to dlsym().

    Locates the PLT entry for dlsym, scans .text for call sites,
    decodes the preceding instructions to resolve the string address,
    then reads the string from .rodata.

    Args:
        elf: pyelftools ELFFile object (file must remain open)
        candidates: OpenSSL symbol names to match against
        section_ranges: (section_vaddr, section_data) for string sections

    Returns:
        Set of symbol names confirmed as dlsym arguments.
    """
    if not candidates or not section_ranges:
        return set()

    dlsym_plt_addr, arch = _find_dlsym_plt_addr(elf)
    if dlsym_plt_addr is None or arch is None:
        return set()

    text_section = elf.get_section_by_name('.text')
    if text_section is None:
        return set()

    try:
        text_data = text_section.data()
        text_vaddr = text_section['sh_addr']
    except (TypeError, KeyError):
        return set()

    if len(text_data) > MAX_TEXT_SIZE:
        logger.debug("Skipping disassembly: .text > %dMB", MAX_TEXT_SIZE // (1024*1024))
        return set()

    if arch == 'aarch64':
        addrs = _resolve_aarch64_dlsym_addrs(text_data, text_vaddr, dlsym_plt_addr)
    elif arch == 'x86_64':
        addrs = _resolve_x86_64_dlsym_addrs(text_data, text_vaddr, dlsym_plt_addr)
    else:
        return set()

    confirmed = set()
    for addr in addrs:
        for sec_vaddr, sec_data in section_ranges:
            sec_end = sec_vaddr + len(sec_data)
            if sec_vaddr <= addr < sec_end:
                s = _read_cstring(sec_data, addr - sec_vaddr)
                if s and s in candidates:
                    confirmed.add(s)
                break

    return confirmed


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
                          exclude_symbols: Optional[Set[str]] = None,
                          ) -> Optional[DlopenResult]:
    """
    Analyze an ELF binary for dlopen/dlsym-based OpenSSL usage.

    Three-layer detection:
      Layer A: Exclude symbols already in .dynsym (UND or DEF)
      Layer B: String clustering by byte proximity (min 3 adjacent)
      Layer C: Disassembly cross-reference (trace dlsym call args)

    When Layer B or C produce results, only high-confidence symbols
    are returned. Otherwise falls back to raw .rodata matching.

    Args:
        elf_path: Path to the ELF file
        openssl_exports: Set of known OpenSSL symbol names
        lib_patterns: Library name prefixes (default: OPENSSL_LIBRARY_PATTERNS)
        exclude_symbols: Symbols to exclude from .rodata matching
                         (typically .dynsym UND + DEF OpenSSL symbols)

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

            candidates = openssl_exports - (exclude_symbols or set())

            all_strings: Set[str] = set()
            all_with_offsets: List[Tuple[int, str]] = []
            section_ranges: List[Tuple[int, bytes]] = []
            base_offset = 0

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

                try:
                    section_vaddr = section['sh_addr']
                except (KeyError, TypeError):
                    section_vaddr = 0
                section_ranges.append((section_vaddr, data))

                # single-pass: extract with offsets, derive flat set from same data
                with_offsets = extract_c_strings_with_offsets(data)
                all_strings.update(s for _, s in with_offsets)
                for off, s in with_offsets:
                    all_with_offsets.append((base_offset + off, s))
                base_offset += size

            dlopen_libs = sorted(
                s for s in all_strings
                if _is_openssl_lib_string(s, lib_patterns)
            )

            raw_matches = {s for s in all_strings if s in candidates}

            resolved = set()
            try:
                resolved = _resolve_dlsym_strings(elf, candidates, section_ranges)
            except (struct.error, ValueError, TypeError, KeyError, IndexError) as e:
                logger.warning("Layer C failed for %s: %s", elf_path, e)

            clustered = _cluster_symbols(all_with_offsets, candidates)

            high_conf = resolved | clustered
            if high_conf:
                dlsym_symbols = sorted(high_conf)
                confidence = 'high'
            elif raw_matches:
                dlsym_symbols = sorted(raw_matches)
                confidence = 'inferred'
            else:
                dlsym_symbols = []
                confidence = 'high'

            return DlopenResult(
                uses_dlopen=has_dlopen,
                uses_dlsym=has_dlsym,
                dlopen_libs=dlopen_libs,
                dlsym_symbols=dlsym_symbols,
                confidence=confidence,
            )

    except (ELFError, IOError, OSError) as e:
        logger.debug("dlopen detection failed for %s: %s", elf_path, e)
        return None
