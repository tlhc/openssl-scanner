"""
Minimal ELF binary builder for integration testing.

Constructs valid ELF shared libraries with controlled section content.
Supports both aarch64 and x86_64 architectures.
No external dependencies -- pure struct packing.
"""
import struct
from typing import Dict, List, Optional, Tuple


# ELF constants
ELFMAG = b'\x7fELF'
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_DYN = 3
EM_AARCH64 = 183
EM_X86_64 = 62
SHT_NULL = 0
SHT_STRTAB = 3
SHT_DYNSYM = 11
SHT_PROGBITS = 1
SHT_RELA = 4
SHT_NOBITS = 8
SHF_ALLOC = 0x2
SHF_WRITE = 0x1
SHF_EXECINSTR = 0x4
STB_GLOBAL = 1
STT_FUNC = 2
STT_NOTYPE = 0
SHN_UNDEF = 0
SHN_ABS = 0xFFF1

EHDR_SIZE = 64
SHDR_SIZE = 64
SYM_SIZE = 24
RELA_SIZE = 24

R_AARCH64_JUMP_SLOT = 1026
R_X86_64_JUMP_SLOT = 7


def _pack_ehdr(e_machine, e_shoff, e_shnum, e_shstrndx):
    """Pack a 64-bit ELF header."""
    return struct.pack(
        '<4sBBBBB7sHHIQQQIHHHHHH',
        ELFMAG,
        ELFCLASS64,
        ELFDATA2LSB,
        EV_CURRENT,
        0,              # EI_OSABI
        0,              # EI_ABIVERSION
        b'\x00' * 7,    # EI_PAD
        ET_DYN,         # e_type
        e_machine,      # e_machine
        EV_CURRENT,     # e_version
        0,              # e_entry
        0,              # e_phoff
        e_shoff,        # e_shoff
        0,              # e_flags
        EHDR_SIZE,      # e_ehsize
        0,              # e_phentsize
        0,              # e_phnum
        SHDR_SIZE,      # e_shentsize
        e_shnum,        # e_shnum
        e_shstrndx,     # e_shstrndx
    )


def _pack_shdr(sh_name, sh_type, sh_flags, sh_addr, sh_offset,
               sh_size, sh_link=0, sh_info=0, sh_addralign=1,
               sh_entsize=0):
    """Pack a 64-bit section header."""
    return struct.pack(
        '<IIQQQQIIQQ',
        sh_name,
        sh_type,
        sh_flags,
        sh_addr,
        sh_offset,
        sh_size,
        sh_link,
        sh_info,
        sh_addralign,
        sh_entsize,
    )


def _pack_sym(st_name, st_info, st_shndx, st_value=0, st_size=0):
    """Pack a 64-bit ELF symbol."""
    return struct.pack('<IBBHQQ', st_name, st_info, 0, st_shndx,
                       st_value, st_size)


def _pack_rela(r_offset, r_sym, r_type, r_addend=0):
    """Pack a 64-bit RELA entry."""
    r_info = (r_sym << 32) | r_type
    return struct.pack('<QQq', r_offset, r_info, r_addend)


class ELFBuilder:
    """Build a minimal ELF shared library with controlled sections."""

    def __init__(self, arch='aarch64'):
        if arch == 'aarch64':
            self.e_machine = EM_AARCH64
            self.r_jump_slot = R_AARCH64_JUMP_SLOT
            self.plt_header_size = 32
            self.plt_entry_size = 16
        elif arch == 'x86_64':
            self.e_machine = EM_X86_64
            self.r_jump_slot = R_X86_64_JUMP_SLOT
            self.plt_header_size = 16
            self.plt_entry_size = 16
        else:
            raise ValueError(f"Unsupported arch: {arch}")

        self.arch = arch
        self._dynsym_names: List[Tuple[str, bool]] = []  # (name, is_defined)
        self._rodata = b''
        self._data_rel_ro = b''
        self._text = b''
        self._plt_base = 0
        self._text_vaddr = 0
        self._rodata_vaddr = 0
        self._data_rel_ro_vaddr = 0
        self._rela_plt_entries: List[Tuple[int, int]] = []  # (sym_idx, got_offset)

    def add_dynsym(self, name: str, defined: bool = False):
        """Add a symbol to .dynsym. undefined by default."""
        self._dynsym_names.append((name, defined))
        return self

    def set_rodata(self, data: bytes, vaddr: int = 0x2000):
        """Set .rodata section content."""
        self._rodata = data
        self._rodata_vaddr = vaddr
        return self

    def set_data_rel_ro(self, data: bytes, vaddr: int = 0x3000):
        """Set .data.rel.ro section content."""
        self._data_rel_ro = data
        self._data_rel_ro_vaddr = vaddr
        return self

    def set_text(self, data: bytes, vaddr: int = 0x1000):
        """Set .text section content."""
        self._text = data
        self._text_vaddr = vaddr
        return self

    def set_plt(self, base_vaddr: int = 0x400):
        """Set .plt base address."""
        self._plt_base = base_vaddr
        return self

    def add_rela_plt(self, sym_idx: int, got_offset: int = 0):
        """Add a .rela.plt relocation entry."""
        self._rela_plt_entries.append((sym_idx, got_offset))
        return self

    def build(self) -> bytes:
        """Assemble the complete ELF binary."""
        shstrtab_strings = [
            b'\x00',
            b'.shstrtab\x00',
            b'.dynstr\x00',
            b'.dynsym\x00',
        ]
        shstrtab_offsets = {}
        pos = 0
        names_in_order = ['.shstrtab', '.dynstr', '.dynsym']

        shstrtab = b'\x00'
        pos = 1
        for name in ['.shstrtab', '.dynstr', '.dynsym']:
            shstrtab_offsets[name] = pos
            shstrtab += name.encode() + b'\x00'
            pos += len(name) + 1

        optional_sections = []
        if self._rodata:
            shstrtab_offsets['.rodata'] = pos
            shstrtab += b'.rodata\x00'
            pos += 8
            optional_sections.append('.rodata')
        if self._data_rel_ro:
            shstrtab_offsets['.data.rel.ro'] = pos
            shstrtab += b'.data.rel.ro\x00'
            pos += 13
            optional_sections.append('.data.rel.ro')
        if self._text:
            shstrtab_offsets['.text'] = pos
            shstrtab += b'.text\x00'
            pos += 6
            optional_sections.append('.text')
        if self._plt_base:
            shstrtab_offsets['.plt'] = pos
            shstrtab += b'.plt\x00'
            pos += 5
            optional_sections.append('.plt')
        if self._rela_plt_entries:
            shstrtab_offsets['.rela.plt'] = pos
            shstrtab += b'.rela.plt\x00'
            pos += 10
            optional_sections.append('.rela.plt')

        dynstr = b'\x00'
        dynstr_offsets = {}
        dpos = 1
        for name, _ in self._dynsym_names:
            dynstr_offsets[name] = dpos
            dynstr += name.encode() + b'\x00'
            dpos += len(name) + 1

        dynsym_data = _pack_sym(0, 0, SHN_UNDEF)
        for name, defined in self._dynsym_names:
            st_info = (STB_GLOBAL << 4) | STT_FUNC
            shndx = SHN_ABS if defined else SHN_UNDEF
            dynsym_data += _pack_sym(dynstr_offsets[name], st_info, shndx)

        rela_plt_data = b''
        for sym_idx, got_off in self._rela_plt_entries:
            rela_plt_data += _pack_rela(got_off, sym_idx, self.r_jump_slot)

        # 1=null, 2=shstrtab, 3=dynstr, 4=dynsym, + optional
        n_sections = 4 + len(optional_sections)
        shstrtab_idx = 1

        data_offset = EHDR_SIZE
        section_layout = []

        def _alloc(data, align=8):
            nonlocal data_offset
            pad = (align - (data_offset % align)) % align
            data_offset += pad
            off = data_offset
            data_offset += len(data)
            return off, pad

        shstrtab_off, shstrtab_pad = _alloc(shstrtab)
        dynstr_off, dynstr_pad = _alloc(dynstr)
        dynsym_off, dynsym_pad = _alloc(dynsym_data)

        opt_offsets = {}
        opt_pads = {}
        for sec_name in optional_sections:
            if sec_name == '.rodata':
                off, pad = _alloc(self._rodata)
                opt_offsets['.rodata'] = off
                opt_pads['.rodata'] = pad
            elif sec_name == '.data.rel.ro':
                off, pad = _alloc(self._data_rel_ro)
                opt_offsets['.data.rel.ro'] = off
                opt_pads['.data.rel.ro'] = pad
            elif sec_name == '.text':
                off, pad = _alloc(self._text)
                opt_offsets['.text'] = off
                opt_pads['.text'] = pad
            elif sec_name == '.plt':
                plt_size = self.plt_header_size + self.plt_entry_size * max(len(self._rela_plt_entries), 1)
                plt_data = b'\x00' * plt_size
                off, pad = _alloc(plt_data)
                opt_offsets['.plt'] = off
                opt_pads['.plt'] = pad
            elif sec_name == '.rela.plt':
                off, pad = _alloc(rela_plt_data)
                opt_offsets['.rela.plt'] = off
                opt_pads['.rela.plt'] = pad

        shdr_align = (8 - (data_offset % 8)) % 8
        data_offset += shdr_align
        shdr_off = data_offset

        ehdr = _pack_ehdr(self.e_machine, shdr_off, n_sections, shstrtab_idx)

        shdrs = b''
        shdrs += _pack_shdr(0, SHT_NULL, 0, 0, 0, 0)

        shdrs += _pack_shdr(
            shstrtab_offsets['.shstrtab'], SHT_STRTAB, 0,
            0, shstrtab_off, len(shstrtab))

        dynstr_shidx = 2
        shdrs += _pack_shdr(
            shstrtab_offsets['.dynstr'], SHT_STRTAB, SHF_ALLOC,
            0, dynstr_off, len(dynstr))

        shdrs += _pack_shdr(
            shstrtab_offsets['.dynsym'], SHT_DYNSYM, SHF_ALLOC,
            0, dynsym_off, len(dynsym_data),
            sh_link=dynstr_shidx,
            sh_info=1,
            sh_entsize=SYM_SIZE)

        for sec_name in optional_sections:
            if sec_name == '.rodata':
                shdrs += _pack_shdr(
                    shstrtab_offsets['.rodata'], SHT_PROGBITS,
                    SHF_ALLOC, self._rodata_vaddr,
                    opt_offsets['.rodata'], len(self._rodata))
            elif sec_name == '.data.rel.ro':
                shdrs += _pack_shdr(
                    shstrtab_offsets['.data.rel.ro'], SHT_PROGBITS,
                    SHF_ALLOC | SHF_WRITE, self._data_rel_ro_vaddr,
                    opt_offsets['.data.rel.ro'], len(self._data_rel_ro))
            elif sec_name == '.text':
                shdrs += _pack_shdr(
                    shstrtab_offsets['.text'], SHT_PROGBITS,
                    SHF_ALLOC | SHF_EXECINSTR, self._text_vaddr,
                    opt_offsets['.text'], len(self._text))
            elif sec_name == '.plt':
                plt_size = self.plt_header_size + self.plt_entry_size * max(len(self._rela_plt_entries), 1)
                shdrs += _pack_shdr(
                    shstrtab_offsets['.plt'], SHT_PROGBITS,
                    SHF_ALLOC | SHF_EXECINSTR, self._plt_base,
                    opt_offsets['.plt'], plt_size)
            elif sec_name == '.rela.plt':
                dynsym_shidx = 3
                shdrs += _pack_shdr(
                    shstrtab_offsets['.rela.plt'], SHT_RELA,
                    SHF_ALLOC, 0,
                    opt_offsets['.rela.plt'], len(rela_plt_data),
                    sh_link=dynsym_shidx,
                    sh_entsize=RELA_SIZE)

        blob = bytearray(shdr_off + len(shdrs))
        blob[:EHDR_SIZE] = ehdr

        blob[shstrtab_off:shstrtab_off + len(shstrtab)] = shstrtab
        blob[dynstr_off:dynstr_off + len(dynstr)] = dynstr
        blob[dynsym_off:dynsym_off + len(dynsym_data)] = dynsym_data

        for sec_name in optional_sections:
            if sec_name == '.rodata':
                off = opt_offsets['.rodata']
                blob[off:off + len(self._rodata)] = self._rodata
            elif sec_name == '.data.rel.ro':
                off = opt_offsets['.data.rel.ro']
                blob[off:off + len(self._data_rel_ro)] = self._data_rel_ro
            elif sec_name == '.text':
                off = opt_offsets['.text']
                blob[off:off + len(self._text)] = self._text
            elif sec_name == '.plt':
                pass
            elif sec_name == '.rela.plt':
                off = opt_offsets['.rela.plt']
                blob[off:off + len(rela_plt_data)] = rela_plt_data

        blob[shdr_off:shdr_off + len(shdrs)] = shdrs

        return bytes(blob)
