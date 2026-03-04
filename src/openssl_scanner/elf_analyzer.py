"""
ELF file analyzer using pyelftools.

Extracts symbol information and dependencies from ELF binaries.
"""

import os
import re
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

    def _parse_symbols(self, elf: ELFFile) -> Tuple[List[Symbol], List[Symbol],
                                                      bool, bool]:
        """
        Parse dynamic symbol table (.dynsym).

        Returns:
            Tuple of (undefined_symbols, defined_symbols, has_dlopen, has_dlsym)
        """
        undefined = []
        defined = []
        seen: Set[str] = set()
        has_dlopen = False
        has_dlsym = False

        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            if section.name != '.dynsym':
                continue

            for symbol in section.iter_symbols():
                name = symbol.name
                if not name or name in seen:
                    continue
                seen.add(name)

                bind = symbol['st_info']['bind']
                sym_type = symbol['st_info']['type']
                shndx = symbol['st_shndx']

                sym = Symbol(
                    name=name,
                    bind=bind,
                    type_=sym_type,
                    defined=(shndx != 'SHN_UNDEF'),
                )

                if shndx == 'SHN_UNDEF':
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
