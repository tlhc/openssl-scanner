"""
ELF file analyzer using pyelftools.

Extracts symbol information and dependencies from ELF binaries.
"""

import os
import re
import struct
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple, Set

from . import _vendor  # noqa: F401 - adds vendored packages to sys.path
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection
from elftools.common.exceptions import ELFError

from .constants import DLOPEN_FUNCTION_NAMES, DLSYM_FUNCTION_NAMES

logger = logging.getLogger(__name__)


@dataclass
class Symbol:
    """Represents an ELF symbol."""
    name: str
    bind: str      # LOCAL, GLOBAL, WEAK
    type_: str     # NOTYPE, OBJECT, FUNC, SECTION, FILE
    defined: bool  # True if symbol is defined in this file


@dataclass
class ELFInfo:
    """Information extracted from an ELF file."""
    path: str
    arch: str
    elf_type: str  # EXEC, DYN, REL
    needed_libs: List[str]
    rpath: Optional[str]
    runpath: Optional[str]
    undefined_symbols: List[Symbol]
    defined_symbols: List[Symbol]
    soname: Optional[str]
    has_dlopen: bool = False
    has_dlsym: bool = False


class ELFAnalyzer:
    """
    Analyzes ELF files to extract symbols and dependencies.

    Uses pyelftools to parse ELF format, extracting:
    - DT_NEEDED entries (direct library dependencies)
    - DT_RPATH/DT_RUNPATH (library search paths)
    - Dynamic symbol table (.dynsym)
    - Symbol binding and type information
    """

    ELF_MAGIC = b'\x7fELF'

    def is_elf_file(self, path: str) -> bool:
        """Check if file is a valid ELF binary."""
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
                return magic == self.ELF_MAGIC
        except (IOError, OSError):
            return False

    def analyze(self, path: str) -> Optional[ELFInfo]:
        """
        Analyze an ELF file and extract all relevant information.

        Args:
            path: Path to the ELF file

        Returns:
            ELFInfo object or None if analysis fails
        """
        if not self.is_elf_file(path):
            return None

        try:
            with open(path, 'rb') as f:
                elf = ELFFile(f)

                arch = self._get_architecture(elf)
                elf_type = self._get_elf_type(elf)
                needed, rpath, runpath, soname = self._parse_dynamic(elf)
                undefined, defined, has_dlopen, has_dlsym = self._parse_symbols(elf)

                return ELFInfo(
                    path=path,
                    arch=arch,
                    elf_type=elf_type,
                    needed_libs=needed,
                    rpath=rpath,
                    runpath=runpath,
                    undefined_symbols=undefined,
                    defined_symbols=defined,
                    soname=soname,
                    has_dlopen=has_dlopen,
                    has_dlsym=has_dlsym,
                )
        except (ELFError, IOError, OSError) as e:
            logger.warning(f"Failed to analyze {path}: {e}")
            return None

    def _get_architecture(self, elf: ELFFile) -> str:
        """Extract architecture string from ELF header."""
        machine = elf.header.e_machine
        arch_map = {
            'EM_AARCH64': 'aarch64',
            'EM_ARM': 'arm',
            'EM_X86_64': 'x86_64',
            'EM_386': 'i386',
            'EM_RISCV': 'riscv',
        }
        return arch_map.get(machine, str(machine))

    def _get_elf_type(self, elf: ELFFile) -> str:
        """Extract ELF file type."""
        type_map = {
            'ET_EXEC': 'executable',
            'ET_DYN': 'shared_library',
            'ET_REL': 'relocatable',
        }
        return type_map.get(elf.header.e_type, 'unknown')

    def _parse_dynamic(self, elf: ELFFile) -> Tuple[List[str], Optional[str],
                                                      Optional[str], Optional[str]]:
        """
        Parse the dynamic section for dependencies and paths.

        Returns:
            Tuple of (needed_libs, rpath, runpath, soname)
        """
        needed = []
        rpath = None
        runpath = None
        soname = None

        for section in elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue

            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    needed.append(tag.needed)
                elif tag.entry.d_tag == 'DT_RPATH':
                    rpath = tag.rpath
                elif tag.entry.d_tag == 'DT_RUNPATH':
                    runpath = tag.runpath
                elif tag.entry.d_tag == 'DT_SONAME':
                    soname = tag.soname

        return needed, rpath, runpath, soname

    _BIND_MAP = {0: 'STB_LOCAL', 1: 'STB_GLOBAL', 2: 'STB_WEAK'}
    _TYPE_MAP = {0: 'STT_NOTYPE', 1: 'STT_OBJECT', 2: 'STT_FUNC',
                 3: 'STT_SECTION', 4: 'STT_FILE', 5: 'STT_COMMON',
                 6: 'STT_TLS', 10: 'STT_LOOS'}

    def _parse_symbols(self, elf: ELFFile) -> Tuple[List[Symbol], List[Symbol],
                                                      bool, bool]:
        """
        Parse dynamic symbol table (.dynsym).

        Uses raw struct.unpack_from on .dynsym section data for speed.
        pyelftools iter_symbols creates full Python objects with lazy
        attribute dicts per symbol; struct parsing is ~40x faster on
        large symbol tables (170K+ symbols).

        Returns:
            Tuple of (undefined_symbols, defined_symbols, has_dlopen, has_dlsym)
        """
        undefined = []
        defined = []
        has_dlopen = False
        has_dlsym = False

        dynsym_sec = elf.get_section_by_name('.dynsym')
        if dynsym_sec is None:
            return undefined, defined, has_dlopen, has_dlsym

        dynstr_sec = elf.get_section_by_name('.dynstr')
        if dynstr_sec is None:
            return undefined, defined, has_dlopen, has_dlsym

        dynsym_data = dynsym_sec.data()
        dynstr_data = dynstr_sec.data()
        dynstr_len = len(dynstr_data)

        is_64 = elf.elfclass == 64
        if is_64:
            sym_size = 24
            hdr_fmt = '<IBBH'
            hdr_off = 0
        else:
            sym_size = 16
            hdr_fmt = '<IBBH'
            hdr_off = 12

        sym_count = len(dynsym_data) // sym_size
        seen: Set[str] = set()

        for i in range(1, sym_count):
            off = i * sym_size
            if is_64:
                st_name, st_info, _, st_shndx = struct.unpack_from(
                    hdr_fmt, dynsym_data, off)
            else:
                st_name = struct.unpack_from('<I', dynsym_data, off)[0]
                st_info, _, st_shndx = struct.unpack_from(
                    '<BBH', dynsym_data, off + hdr_off)

            if st_name == 0 or st_name >= dynstr_len:
                continue
            end = dynstr_data.find(b'\x00', st_name)
            if end < 0:
                end = dynstr_len
            name = dynstr_data[st_name:end].decode('ascii', errors='replace')

            if not name or name in seen:
                continue
            seen.add(name)

            bind = self._BIND_MAP.get(st_info >> 4, f'STB_{st_info >> 4}')
            sym_type = self._TYPE_MAP.get(st_info & 0xf, f'STT_{st_info & 0xf}')
            is_undef = st_shndx == 0

            sym = Symbol(name=name, bind=bind, type_=sym_type, defined=not is_undef)

            if is_undef:
                undefined.append(sym)
                if name in DLOPEN_FUNCTION_NAMES:
                    has_dlopen = True
                if name in DLSYM_FUNCTION_NAMES:
                    has_dlsym = True
            else:
                defined.append(sym)

        return undefined, defined, has_dlopen, has_dlsym

    def get_undefined_symbols(self, path: str) -> List[str]:
        """Get list of undefined symbol names from ELF file."""
        info = self.analyze(path)
        if not info:
            return []
        return [s.name for s in info.undefined_symbols]

    def get_needed_libs(self, path: str) -> List[str]:
        """Get list of directly needed libraries (DT_NEEDED)."""
        info = self.analyze(path)
        if not info:
            return []
        return info.needed_libs

    def get_defined_symbols(self, path: str) -> List[str]:
        """Get list of defined symbol names exported by ELF file."""
        info = self.analyze(path)
        if not info:
            return []
        return [s.name for s in info.defined_symbols]


_RODATA_SECTIONS = ('.rodata', '.data.rel.ro', '.data')
_RODATA_MAX_SIZE = 2 * 1024 * 1024 * 1024
_RODATA_RE = re.compile(rb'[\x20-\x7e]{4,}')


def _iter_rodata_strings(elf_path, section_names=None, min_len=4):
    """Yield printable ASCII strings from .rodata and similar ELF sections.

    Shared generator used by both extract_rodata_strings and
    extract_rodata_matches to keep section names, regex, size cap,
    and error handling in one place.
    """
    if section_names is None:
        section_names = _RODATA_SECTIONS

    if min_len == 4:
        pat = _RODATA_RE
    else:
        pat = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)

    with open(elf_path, 'rb') as f:
        magic = f.read(4)
        if magic != b'\x7fELF':
            return
        f.seek(0)
        elf = ELFFile(f)

        for name in section_names:
            section = elf.get_section_by_name(name)
            if section is None:
                continue
            if section.data_size > _RODATA_MAX_SIZE:
                continue
            data = section.data()
            for m in pat.finditer(data):
                yield m.group().decode('ascii')


def extract_rodata_strings(elf_path, section_names=None, min_len=4):
    """Extract printable ASCII strings from .rodata and similar ELF sections.

    Args:
        elf_path: Path to an ELF binary.
        section_names: Sections to scan (default: .rodata, .data.rel.ro, .data).
        min_len: Minimum string length (default 4).

    Returns:
        Set of unique printable strings found across all matching sections.
    """
    try:
        return set(_iter_rodata_strings(elf_path, section_names, min_len))
    except (ELFError, IOError, OSError):
        return set()


def extract_rodata_matches(elf_path, candidates, section_names=None, min_len=4):
    """Extract rodata strings that match a candidate set.

    Same ELF parsing as extract_rodata_strings, but only returns strings
    present in candidates. Avoids materializing the full string set when
    only a small subset (e.g. 739 custom patterns) is needed.

    Args:
        elf_path: Path to an ELF binary.
        candidates: Set of strings to match against.
        section_names: Sections to scan (default: .rodata, .data.rel.ro, .data).
        min_len: Minimum string length (default 4).

    Returns:
        Set of strings from candidates found in rodata sections.
    """
    try:
        result = set()
        for s in _iter_rodata_strings(elf_path, section_names, min_len):
            if s in candidates:
                result.add(s)
        return result
    except (ELFError, IOError, OSError):
        return set()
