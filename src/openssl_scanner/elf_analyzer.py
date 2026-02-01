"""
ELF file analyzer using pyelftools.

Extracts symbol information and dependencies from ELF binaries.
"""

import os
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple, Set

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection
from elftools.common.exceptions import ELFError

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
                undefined, defined = self._parse_symbols(elf)

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

    def _parse_symbols(self, elf: ELFFile) -> Tuple[List[Symbol], List[Symbol]]:
        """
        Parse dynamic symbol table (.dynsym).

        Returns:
            Tuple of (undefined_symbols, defined_symbols)
        """
        undefined = []
        defined = []
        seen: Set[str] = set()

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
                else:
                    defined.append(sym)

        return undefined, defined

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
