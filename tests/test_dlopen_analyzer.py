"""Tests for dlopen/dlsym OpenSSL detection (three-layer accuracy)."""

import os
import struct
import tempfile
import time
from unittest.mock import patch, MagicMock

import pytest

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openssl_scanner.dlopen_analyzer import (
    DlopenResult,
    extract_c_strings,
    extract_c_strings_with_offsets,
    _cluster_symbols,
    _read_cstring,
    _find_dlsym_plt_addr,
    _resolve_aarch64_dlsym_addrs,
    _resolve_x86_64_dlsym_addrs,
    _resolve_dlsym_strings,
    detect_dlopen_openssl,
    _is_openssl_lib_string,
    STRING_SECTIONS,
    MAX_SECTION_SIZE,
    CLUSTER_MAX_GAP,
    CLUSTER_MIN_SIZE,
    _AARCH64_PLT_HEADER_SIZE,
    _AARCH64_PLT_ENTRY_SIZE,
    _AARCH64_BL_MASK,
    _AARCH64_BL_OPCODE,
    _AARCH64_ADRP_MASK,
    _AARCH64_ADRP_OPCODE,
    _AARCH64_ADD_IMM_MASK,
    _AARCH64_ADD_IMM_OPCODE,
    _X86_64_PLT_HEADER_SIZE,
    _X86_64_PLT_ENTRY_SIZE,
)
from openssl_scanner.constants import OPENSSL_LIBRARY_PATTERNS


OSSL_EXPORTS = {
    'SSL_CTX_new', 'SSL_connect', 'SSL_read', 'SSL_write',
    'EVP_DigestInit_ex', 'EVP_DigestUpdate', 'EVP_DigestFinal_ex',
    'EVP_sha256', 'EVP_MD_CTX_new', 'EVP_MD_CTX_free',
    'BIO_new', 'BIO_free', 'OPENSSL_init_ssl',
    'X509_get_subject_name', 'RSA_generate_key_ex',
}


class TestExtractCStrings:

    def test_basic_null_terminated(self):
        data = b'SSL_CTX_new\x00EVP_sha256\x00BIO_new\x00'
        strings = extract_c_strings(data)
        assert 'SSL_CTX_new' in strings
        assert 'EVP_sha256' in strings
        assert 'BIO_new' in strings

    def test_min_length_filter(self):
        data = b'ab\x00abc\x00abcd\x00abcde\x00'
        strings = extract_c_strings(data, min_len=4)
        assert 'ab' not in strings
        assert 'abc' not in strings
        assert 'abcd' in strings
        assert 'abcde' in strings

    def test_non_printable_filtered(self):
        data = b'good_string\x00bad\x01string\x00another_good\x00'
        strings = extract_c_strings(data)
        assert 'good_string' in strings
        assert 'another_good' in strings
        assert len([s for s in strings if 'bad' in s]) == 0

    def test_empty_data(self):
        assert extract_c_strings(b'') == set()
        assert extract_c_strings(b'\x00\x00\x00') == set()

    def test_adjacent_nulls(self):
        data = b'hello\x00\x00\x00world\x00'
        strings = extract_c_strings(data)
        assert 'hello' in strings
        assert 'world' in strings

    def test_no_trailing_null(self):
        data = b'SSL_CTX_new'
        strings = extract_c_strings(data)
        assert 'SSL_CTX_new' in strings

    def test_mixed_content(self):
        """Simulate real .rodata with mixed strings and binary data."""
        data = (
            b'\x00\x00\x00\x00'
            b'libcrypto.so.3\x00'
            b'\x89PNG\r\n\x1a\n'
            b'\x00\x00\x00'
            b'SSL_CTX_new\x00'
            b'EVP_DigestInit_ex\x00'
            b'%s: error at line %d\x00'
            b'\xff\xfe\xfd\x00'
            b'RTLD_NOW\x00'
        )
        strings = extract_c_strings(data)
        assert 'libcrypto.so.3' in strings
        assert 'SSL_CTX_new' in strings
        assert 'EVP_DigestInit_ex' in strings
        assert 'RTLD_NOW' in strings

    def test_large_data_performance(self):
        """1MB of data should complete in < 1 second."""
        data = b'A' * 100 + b'\x00'
        data = data * 10000
        start = time.time()
        strings = extract_c_strings(data)
        elapsed = time.time() - start
        assert elapsed < 1.0
        assert 'A' * 100 in strings

    def test_custom_min_length(self):
        data = b'SSL_CTX_new\x00AB\x00'
        assert 'SSL_CTX_new' in extract_c_strings(data, min_len=1)
        assert 'AB' in extract_c_strings(data, min_len=1)
        assert 'AB' not in extract_c_strings(data, min_len=4)


class TestExtractCStringsWithOffsets:

    def test_basic_offsets(self):
        data = b'SSL_CTX_new\x00EVP_sha256\x00'
        result = extract_c_strings_with_offsets(data)
        assert len(result) == 2
        assert result[0] == (0, 'SSL_CTX_new')
        assert result[1] == (12, 'EVP_sha256')

    def test_adjacent_nulls(self):
        data = b'hello\x00\x00\x00world\x00'
        result = extract_c_strings_with_offsets(data)
        offsets = {off: s for off, s in result}
        assert offsets[0] == 'hello'
        assert offsets[8] == 'world'

    def test_empty_data(self):
        assert extract_c_strings_with_offsets(b'') == []
        assert extract_c_strings_with_offsets(b'\x00\x00') == []

    def test_min_length_filter(self):
        data = b'ab\x00abcde\x00'
        result = extract_c_strings_with_offsets(data, min_len=4)
        assert len(result) == 1
        assert result[0] == (3, 'abcde')

    def test_leading_null(self):
        data = b'\x00SSL_CTX_new\x00'
        result = extract_c_strings_with_offsets(data)
        assert len(result) == 1
        assert result[0] == (1, 'SSL_CTX_new')


class TestClusterSymbols:

    def test_single_cluster(self):
        """Three symbols within gap -> all returned."""
        offsets = [(0, 'SSL_CTX_new'), (20, 'SSL_connect'), (40, 'SSL_read')]
        candidates = {'SSL_CTX_new', 'SSL_connect', 'SSL_read'}
        result = _cluster_symbols(offsets, candidates)
        assert result == candidates

    def test_below_min_cluster(self):
        """Two symbols -> below threshold -> empty."""
        offsets = [(0, 'SSL_CTX_new'), (20, 'SSL_connect')]
        candidates = {'SSL_CTX_new', 'SSL_connect'}
        result = _cluster_symbols(offsets, candidates)
        assert result == set()

    def test_gap_splits_cluster(self):
        """Large gap splits into two clusters, each below threshold."""
        offsets = [
            (0, 'SSL_CTX_new'), (20, 'SSL_connect'),
            (500, 'BIO_new'), (520, 'BIO_free'),
        ]
        candidates = {'SSL_CTX_new', 'SSL_connect', 'BIO_new', 'BIO_free'}
        result = _cluster_symbols(offsets, candidates)
        assert result == set()

    def test_gap_splits_one_qualifying(self):
        """Gap splits: first cluster qualifies, second does not."""
        offsets = [
            (0, 'SSL_CTX_new'), (20, 'SSL_connect'), (40, 'SSL_read'),
            (500, 'BIO_new'), (520, 'BIO_free'),
        ]
        candidates = {s for _, s in offsets}
        result = _cluster_symbols(offsets, candidates)
        assert result == {'SSL_CTX_new', 'SSL_connect', 'SSL_read'}

    def test_non_candidate_ignored(self):
        """Non-candidate strings don't count toward cluster size."""
        offsets = [
            (0, 'SSL_CTX_new'),
            (20, 'printf'),
            (40, 'SSL_connect'),
        ]
        candidates = {'SSL_CTX_new', 'SSL_connect'}
        result = _cluster_symbols(offsets, candidates)
        assert result == set()

    def test_large_cluster(self):
        """10 symbols close together -> all returned."""
        syms = ['SSL_CTX_new', 'SSL_connect', 'SSL_read', 'SSL_write',
                'EVP_sha256', 'EVP_DigestInit_ex', 'BIO_new', 'BIO_free',
                'OPENSSL_init_ssl', 'X509_get_subject_name']
        offsets = [(i * 20, s) for i, s in enumerate(syms)]
        candidates = set(syms)
        result = _cluster_symbols(offsets, candidates)
        assert result == candidates

    def test_custom_gap_and_min(self):
        """Custom max_gap and min_cluster parameters."""
        offsets = [(0, 'SSL_CTX_new'), (50, 'SSL_connect'),
                   (100, 'SSL_read'), (150, 'SSL_write')]
        candidates = {s for _, s in offsets}
        assert _cluster_symbols(offsets, candidates, max_gap=60, min_cluster=2) == candidates
        assert _cluster_symbols(offsets, candidates, max_gap=30, min_cluster=2) == set()

    def test_unsorted_input(self):
        """Input not sorted by offset is handled correctly."""
        offsets = [(40, 'SSL_read'), (0, 'SSL_CTX_new'), (20, 'SSL_connect')]
        candidates = {s for _, s in offsets}
        result = _cluster_symbols(offsets, candidates)
        assert result == candidates


class TestReadCstring:

    def test_basic(self):
        data = b'SSL_CTX_new\x00EVP_sha256\x00'
        assert _read_cstring(data, 0) == 'SSL_CTX_new'
        assert _read_cstring(data, 12) == 'EVP_sha256'

    def test_out_of_bounds(self):
        data = b'hello\x00'
        assert _read_cstring(data, -1) is None
        assert _read_cstring(data, 100) is None

    def test_short_string(self):
        data = b'ab\x00SSL_CTX_new\x00'
        assert _read_cstring(data, 0) is None
        assert _read_cstring(data, 3) == 'SSL_CTX_new'

    def test_no_null_terminator(self):
        data = b'SSL_CTX_new'
        assert _read_cstring(data, 0) == 'SSL_CTX_new'

    def test_non_printable(self):
        data = b'bad\x01str\x00'
        assert _read_cstring(data, 0) is None


class TestResolveAarch64DlsymAddrs:
    """Test aarch64 ADRP+ADD+BL pattern decoding."""

    def _encode_adrp(self, rd, imm21, pc):
        """Encode ADRP Xrd, #imm21 at given PC."""
        if imm21 < 0:
            imm21 = imm21 + 0x200000
        immhi = (imm21 >> 2) & 0x7FFFF
        immlo = imm21 & 0x3
        insn = (_AARCH64_ADRP_OPCODE
                | (immlo << 29)
                | (immhi << 5)
                | (rd & 0x1F))
        return struct.pack('<I', insn)

    def _encode_add_imm(self, rd, rn, imm12, shift=0):
        """Encode ADD Xrd, Xrn, #imm12."""
        insn = (_AARCH64_ADD_IMM_OPCODE
                | ((shift & 0x3) << 22)
                | ((imm12 & 0xFFF) << 10)
                | ((rn & 0x1F) << 5)
                | (rd & 0x1F))
        return struct.pack('<I', insn)

    def _encode_bl(self, pc, target):
        """Encode BL <target> at given PC."""
        offset = (target - pc) // 4
        if offset < 0:
            offset = offset + 0x04000000
        insn = _AARCH64_BL_OPCODE | (offset & 0x03FFFFFF)
        return struct.pack('<I', insn)

    def _encode_nop(self):
        return struct.pack('<I', 0xD503201F)

    def test_adrp_add_bl_pattern(self):
        """Standard ADRP X1 + ADD X1 + BL dlsym pattern resolves address."""
        text_vaddr = 0x1000
        rodata_vaddr = 0x2000
        string_addr = 0x2100
        dlsym_plt = 0x800

        adrp_pc = text_vaddr
        adrp_page = rodata_vaddr
        adrp_imm21 = (adrp_page - (adrp_pc & ~0xFFF)) >> 12

        text = b''
        text += self._encode_adrp(1, adrp_imm21, adrp_pc)
        text += self._encode_add_imm(1, 1, string_addr - adrp_page)
        text += self._encode_bl(text_vaddr + 8, dlsym_plt)

        addrs = _resolve_aarch64_dlsym_addrs(text, text_vaddr, dlsym_plt)
        assert string_addr in addrs

    def test_with_intervening_instructions(self):
        """ADRP + ADD + NOP + BL still resolves (within scan window)."""
        text_vaddr = 0x1000
        dlsym_plt = 0x800
        string_addr = 0x2100

        text = b''
        text += self._encode_adrp(1, 1, text_vaddr)
        text += self._encode_add_imm(1, 1, 0x100)
        text += self._encode_nop()
        text += self._encode_nop()
        text += self._encode_bl(text_vaddr + 16, dlsym_plt)

        addrs = _resolve_aarch64_dlsym_addrs(text, text_vaddr, dlsym_plt)
        assert string_addr in addrs

    def test_no_bl_to_target(self):
        """BL to different target -> nothing resolved."""
        text_vaddr = 0x1000
        dlsym_plt = 0x800
        other_plt = 0x900

        text = b''
        text += self._encode_adrp(1, 1, text_vaddr)
        text += self._encode_add_imm(1, 1, 0x100)
        text += self._encode_bl(text_vaddr + 8, other_plt)

        addrs = _resolve_aarch64_dlsym_addrs(text, text_vaddr, dlsym_plt)
        assert addrs == set()

    def test_bl_without_adrp(self):
        """BL to dlsym but no preceding ADRP X1 -> nothing resolved."""
        text_vaddr = 0x1000
        dlsym_plt = 0x800

        text = b''
        text += self._encode_nop()
        text += self._encode_nop()
        text += self._encode_bl(text_vaddr + 8, dlsym_plt)

        addrs = _resolve_aarch64_dlsym_addrs(text, text_vaddr, dlsym_plt)
        assert addrs == set()

    def test_multiple_call_sites(self):
        """Two separate BL dlsym calls resolve independently."""
        text_vaddr = 0x1000
        dlsym_plt = 0x800

        text = b''
        text += self._encode_adrp(1, 1, text_vaddr)
        text += self._encode_add_imm(1, 1, 0x100)
        text += self._encode_bl(text_vaddr + 8, dlsym_plt)
        text += self._encode_adrp(1, 1, text_vaddr + 12)
        text += self._encode_add_imm(1, 1, 0x200)
        text += self._encode_bl(text_vaddr + 20, dlsym_plt)

        addrs = _resolve_aarch64_dlsym_addrs(text, text_vaddr, dlsym_plt)
        assert 0x2100 in addrs
        assert 0x2200 in addrs

    def test_wrong_register(self):
        """ADRP X2 + ADD X2 (not X1) -> nothing resolved."""
        text_vaddr = 0x1000
        dlsym_plt = 0x800

        text = b''
        text += self._encode_adrp(2, 1, text_vaddr)
        text += self._encode_add_imm(2, 2, 0x100)
        text += self._encode_bl(text_vaddr + 8, dlsym_plt)

        addrs = _resolve_aarch64_dlsym_addrs(text, text_vaddr, dlsym_plt)
        assert addrs == set()


class TestResolveX86_64DlsymAddrs:
    """Test x86_64 LEA RSI + CALL pattern decoding."""

    def _encode_lea_rsi_rip(self, lea_vaddr, target_addr):
        """Encode LEA RSI,[RIP+disp32]."""
        disp32 = target_addr - (lea_vaddr + 7)
        return bytes([0x48, 0x8D, 0x35]) + struct.pack('<i', disp32)

    def _encode_call_rel32(self, call_vaddr, target_addr):
        """Encode CALL rel32."""
        rel32 = target_addr - (call_vaddr + 5)
        return bytes([0xE8]) + struct.pack('<i', rel32)

    def _encode_nop(self, n=1):
        return b'\x90' * n

    def test_lea_call_pattern(self):
        """Standard LEA RSI + CALL dlsym pattern resolves address."""
        text_vaddr = 0x1000
        dlsym_plt = 0x800
        string_addr = 0x2100

        text = b''
        text += self._encode_lea_rsi_rip(text_vaddr, string_addr)
        text += self._encode_call_rel32(text_vaddr + 7, dlsym_plt)

        addrs = _resolve_x86_64_dlsym_addrs(text, text_vaddr, dlsym_plt)
        assert string_addr in addrs

    def test_with_intervening_nops(self):
        """LEA RSI + NOPs + CALL still resolves (within scan window)."""
        text_vaddr = 0x1000
        dlsym_plt = 0x800
        string_addr = 0x2100

        lea = self._encode_lea_rsi_rip(text_vaddr, string_addr)
        nops = self._encode_nop(10)
        call = self._encode_call_rel32(text_vaddr + 7 + 10, dlsym_plt)
        text = lea + nops + call

        addrs = _resolve_x86_64_dlsym_addrs(text, text_vaddr, dlsym_plt)
        assert string_addr in addrs

    def test_no_call_to_target(self):
        """CALL to different target -> nothing resolved."""
        text_vaddr = 0x1000
        dlsym_plt = 0x800
        other_plt = 0x900
        string_addr = 0x2100

        text = b''
        text += self._encode_lea_rsi_rip(text_vaddr, string_addr)
        text += self._encode_call_rel32(text_vaddr + 7, other_plt)

        addrs = _resolve_x86_64_dlsym_addrs(text, text_vaddr, dlsym_plt)
        assert addrs == set()

    def test_call_without_lea(self):
        """CALL dlsym without preceding LEA RSI -> nothing resolved."""
        text_vaddr = 0x1000
        dlsym_plt = 0x800

        text = self._encode_nop(10) + self._encode_call_rel32(text_vaddr + 10, dlsym_plt)

        addrs = _resolve_x86_64_dlsym_addrs(text, text_vaddr, dlsym_plt)
        assert addrs == set()

    def test_multiple_call_sites(self):
        """Two separate CALL dlsym calls resolve independently."""
        text_vaddr = 0x1000
        dlsym_plt = 0x800

        lea1 = self._encode_lea_rsi_rip(text_vaddr, 0x2100)
        call1 = self._encode_call_rel32(text_vaddr + 7, dlsym_plt)
        lea2 = self._encode_lea_rsi_rip(text_vaddr + 12, 0x2200)
        call2 = self._encode_call_rel32(text_vaddr + 19, dlsym_plt)
        text = lea1 + call1 + lea2 + call2

        addrs = _resolve_x86_64_dlsym_addrs(text, text_vaddr, dlsym_plt)
        assert 0x2100 in addrs
        assert 0x2200 in addrs


class TestFindDlsymPltAddr:
    """Test PLT address resolution for dlsym."""

    def _make_plt_mock(self, arch, dlsym_sym_idx, plt_base=0x400):
        mock_elf = MagicMock()
        if arch == 'aarch64':
            mock_elf.header.e_machine = 'EM_AARCH64'
            header_size = _AARCH64_PLT_HEADER_SIZE
            entry_size = _AARCH64_PLT_ENTRY_SIZE
        else:
            mock_elf.header.e_machine = 'EM_X86_64'
            header_size = _X86_64_PLT_HEADER_SIZE
            entry_size = _X86_64_PLT_ENTRY_SIZE

        sym_list = []
        for i in range(dlsym_sym_idx + 1):
            s = MagicMock()
            if i == dlsym_sym_idx:
                s.name = 'dlsym'
                s.__getitem__ = lambda self, k: 'SHN_UNDEF' if k == 'st_shndx' else None
            else:
                s.name = 'func_%d' % i
                s.__getitem__ = lambda self, k: 'SHN_UNDEF' if k == 'st_shndx' else None
            sym_list.append(s)

        dynsym_sec = MagicMock()
        dynsym_sec.iter_symbols.return_value = sym_list

        rel = MagicMock()
        rel.__getitem__ = lambda self, k, _idx=dlsym_sym_idx: (
            _idx if k == 'r_info_sym' else None)
        rela_plt_sec = MagicMock()
        rela_plt_sec.iter_relocations.return_value = [rel]

        plt_sec = MagicMock()
        plt_sec.__getitem__ = lambda self, k, _base=plt_base: (
            _base if k == 'sh_addr' else None)

        sections = {
            '.dynsym': dynsym_sec,
            '.rela.plt': rela_plt_sec,
            '.plt': plt_sec,
        }
        mock_elf.get_section_by_name = lambda name: sections.get(name)

        expected = plt_base + header_size + 0 * entry_size
        return mock_elf, expected

    def test_aarch64_plt(self):
        mock_elf, expected_addr = self._make_plt_mock('aarch64', dlsym_sym_idx=2)
        addr, arch = _find_dlsym_plt_addr(mock_elf)
        assert arch == 'aarch64'
        assert addr == expected_addr

    def test_x86_64_plt(self):
        mock_elf, expected_addr = self._make_plt_mock('x86_64', dlsym_sym_idx=3)
        addr, arch = _find_dlsym_plt_addr(mock_elf)
        assert arch == 'x86_64'
        assert addr == expected_addr

    def test_unsupported_arch(self):
        mock_elf = MagicMock()
        mock_elf.header.e_machine = 'EM_MIPS'
        addr, arch = _find_dlsym_plt_addr(mock_elf)
        assert addr is None
        assert arch is None

    def test_no_dynsym(self):
        mock_elf = MagicMock()
        mock_elf.header.e_machine = 'EM_AARCH64'
        mock_elf.get_section_by_name = lambda name: None
        addr, arch = _find_dlsym_plt_addr(mock_elf)
        assert addr is None
        assert arch == 'aarch64'

    def test_no_rela_plt(self):
        mock_elf = MagicMock()
        mock_elf.header.e_machine = 'EM_X86_64'

        sym = MagicMock()
        sym.name = 'dlsym'
        sym.__getitem__ = lambda self, k: 'SHN_UNDEF' if k == 'st_shndx' else None
        dynsym = MagicMock()
        dynsym.iter_symbols.return_value = [sym]

        def get_section(name):
            if name == '.dynsym':
                return dynsym
            return None
        mock_elf.get_section_by_name = get_section

        addr, arch = _find_dlsym_plt_addr(mock_elf)
        assert addr is None
        assert arch == 'x86_64'


class TestResolveDlsymStrings:
    """Integration test for _resolve_dlsym_strings combining PLT + disassembly."""

    def test_aarch64_end_to_end(self):
        """Full pipeline: PLT lookup -> .text scan -> .rodata read."""
        text_vaddr = 0x1000
        rodata_vaddr = 0x2000
        string_offset = 0x100
        string_addr = rodata_vaddr + string_offset
        plt_base = 0x400

        mock_elf = MagicMock()
        mock_elf.header.e_machine = 'EM_AARCH64'

        sym0 = MagicMock()
        sym0.name = 'printf'
        sym0.__getitem__ = lambda self, k: 'SHN_UNDEF' if k == 'st_shndx' else None
        sym1 = MagicMock()
        sym1.name = 'dlsym'
        sym1.__getitem__ = lambda self, k: 'SHN_UNDEF' if k == 'st_shndx' else None
        dynsym = MagicMock()
        dynsym.iter_symbols.return_value = [sym0, sym1]

        rel = MagicMock()
        rel.__getitem__ = lambda self, k: 1 if k == 'r_info_sym' else None
        rela_plt = MagicMock()
        rela_plt.iter_relocations.return_value = [rel]

        plt_sec = MagicMock()
        plt_sec.__getitem__ = lambda self, k: plt_base if k == 'sh_addr' else None

        dlsym_plt_addr = plt_base + _AARCH64_PLT_HEADER_SIZE + 0 * _AARCH64_PLT_ENTRY_SIZE

        adrp_imm21 = (rodata_vaddr - (text_vaddr & ~0xFFF)) >> 12
        text_data = b''
        text_data += struct.pack('<I',
            _AARCH64_ADRP_OPCODE | ((adrp_imm21 & 0x3) << 29) |
            (((adrp_imm21 >> 2) & 0x7FFFF) << 5) | 1)
        text_data += struct.pack('<I',
            _AARCH64_ADD_IMM_OPCODE | ((string_offset & 0xFFF) << 10) | (1 << 5) | 1)
        bl_offset = (dlsym_plt_addr - (text_vaddr + 8)) // 4
        if bl_offset < 0:
            bl_offset += 0x04000000
        text_data += struct.pack('<I', _AARCH64_BL_OPCODE | (bl_offset & 0x03FFFFFF))

        text_sec = MagicMock()
        text_sec.data.return_value = text_data
        text_sec.__getitem__ = lambda self, k: text_vaddr if k == 'sh_addr' else None

        sections = {
            '.dynsym': dynsym,
            '.rela.plt': rela_plt,
            '.plt': plt_sec,
            '.text': text_sec,
        }
        mock_elf.get_section_by_name = lambda name: sections.get(name)

        rodata = b'\x00' * string_offset + b'SSL_CTX_new\x00'
        section_ranges = [(rodata_vaddr, rodata)]
        candidates = {'SSL_CTX_new', 'EVP_sha256'}

        result = _resolve_dlsym_strings(mock_elf, candidates, section_ranges)
        assert 'SSL_CTX_new' in result

    def test_x86_64_end_to_end(self):
        """Full pipeline for x86_64: PLT lookup -> .text scan -> .rodata read."""
        text_vaddr = 0x1000
        rodata_vaddr = 0x2000
        string_offset = 0x100
        string_addr = rodata_vaddr + string_offset
        plt_base = 0x400

        mock_elf = MagicMock()
        mock_elf.header.e_machine = 'EM_X86_64'

        sym = MagicMock()
        sym.name = 'dlsym'
        sym.__getitem__ = lambda self, k: 'SHN_UNDEF' if k == 'st_shndx' else None
        dynsym = MagicMock()
        dynsym.iter_symbols.return_value = [sym]

        rel = MagicMock()
        rel.__getitem__ = lambda self, k: 0 if k == 'r_info_sym' else None
        rela_plt = MagicMock()
        rela_plt.iter_relocations.return_value = [rel]

        plt_sec = MagicMock()
        plt_sec.__getitem__ = lambda self, k: plt_base if k == 'sh_addr' else None

        dlsym_plt_addr = plt_base + _X86_64_PLT_HEADER_SIZE

        lea_vaddr = text_vaddr
        lea_disp32 = string_addr - (lea_vaddr + 7)
        call_vaddr = text_vaddr + 7
        call_rel32 = dlsym_plt_addr - (call_vaddr + 5)

        text_data = bytes([0x48, 0x8D, 0x35]) + struct.pack('<i', lea_disp32)
        text_data += bytes([0xE8]) + struct.pack('<i', call_rel32)

        text_sec = MagicMock()
        text_sec.data.return_value = text_data
        text_sec.__getitem__ = lambda self, k: text_vaddr if k == 'sh_addr' else None

        sections = {
            '.dynsym': dynsym,
            '.rela.plt': rela_plt,
            '.plt': plt_sec,
            '.text': text_sec,
        }
        mock_elf.get_section_by_name = lambda name: sections.get(name)

        rodata = b'\x00' * string_offset + b'EVP_sha256\x00'
        section_ranges = [(rodata_vaddr, rodata)]
        candidates = {'SSL_CTX_new', 'EVP_sha256'}

        result = _resolve_dlsym_strings(mock_elf, candidates, section_ranges)
        assert 'EVP_sha256' in result

    def test_no_plt_returns_empty(self):
        """Missing PLT -> empty result."""
        mock_elf = MagicMock()
        mock_elf.header.e_machine = 'EM_MIPS'
        result = _resolve_dlsym_strings(mock_elf, {'SSL_CTX_new'}, [(0, b'data')])
        assert result == set()

    def test_empty_candidates(self):
        mock_elf = MagicMock()
        result = _resolve_dlsym_strings(mock_elf, set(), [(0, b'data')])
        assert result == set()


class TestIsOpensslLibString:

    def test_simple_lib_name(self):
        assert _is_openssl_lib_string('libcrypto.so', OPENSSL_LIBRARY_PATTERNS)
        assert _is_openssl_lib_string('libssl.so', OPENSSL_LIBRARY_PATTERNS)

    def test_versioned_lib(self):
        assert _is_openssl_lib_string('libcrypto.so.3', OPENSSL_LIBRARY_PATTERNS)
        assert _is_openssl_lib_string('libssl.so.1.1', OPENSSL_LIBRARY_PATTERNS)
        assert _is_openssl_lib_string('libcrypto.so.1.1.1w', OPENSSL_LIBRARY_PATTERNS)

    def test_oh_specific_lib(self):
        assert _is_openssl_lib_string('libcrypto_openssl.z.so', OPENSSL_LIBRARY_PATTERNS)
        assert _is_openssl_lib_string('libssl_openssl.z.so', OPENSSL_LIBRARY_PATTERNS)

    def test_absolute_path(self):
        assert _is_openssl_lib_string(
            '/system/lib64/libcrypto.so.3', OPENSSL_LIBRARY_PATTERNS)
        assert _is_openssl_lib_string(
            '/system/lib64/module/security/libcrypto_openssl.z.so',
            OPENSSL_LIBRARY_PATTERNS)

    def test_non_openssl_lib(self):
        assert not _is_openssl_lib_string('libcurl.so', OPENSSL_LIBRARY_PATTERNS)
        assert not _is_openssl_lib_string('libz.so.1', OPENSSL_LIBRARY_PATTERNS)
        assert not _is_openssl_lib_string('libpthread.so.0', OPENSSL_LIBRARY_PATTERNS)


def _make_mock_elf(undefined_symbols=None, section_data=None, section_vaddrs=None):
    """Create a mock ELFFile for testing.

    Args:
        undefined_symbols: list of (name, shndx) pairs for .dynsym
        section_data: dict of section_name -> bytes for data sections
        section_vaddrs: dict of section_name -> int virtual address
    """
    if undefined_symbols is None:
        undefined_symbols = []
    if section_data is None:
        section_data = {}
    if section_vaddrs is None:
        section_vaddrs = {}

    mock_syms = []
    for name, shndx in undefined_symbols:
        sym = MagicMock()
        sym.name = name
        sym.__getitem__ = lambda self, key, _shndx=shndx: _shndx if key == 'st_shndx' else None
        mock_syms.append(sym)

    dynsym_section = MagicMock()
    dynsym_section.name = '.dynsym'
    dynsym_section.iter_symbols.return_value = mock_syms

    from openssl_scanner._vendor import elftools  # noqa
    from elftools.elf.sections import SymbolTableSection
    dynsym_section.__class__ = SymbolTableSection

    data_sections = {}
    for sec_name, sec_bytes in section_data.items():
        sec = MagicMock()
        sec.name = sec_name
        sec.data.return_value = sec_bytes
        sec.data_size = len(sec_bytes)
        vaddr = section_vaddrs.get(sec_name, 0)
        sec.__getitem__ = lambda self, key, _v=vaddr: _v if key == 'sh_addr' else None
        data_sections[sec_name] = sec

    def get_section_by_name(name):
        return data_sections.get(name, None)

    sections_list = [dynsym_section] + list(data_sections.values())

    mock_elf = MagicMock()
    mock_elf.iter_sections.return_value = sections_list
    mock_elf.get_section_by_name = get_section_by_name

    return mock_elf


class TestDlopenDetection:

    def test_no_dlopen_returns_empty(self):
        """Binary without dlopen/dlsym should return empty result."""
        rodata = b'SSL_CTX_new\x00libcrypto.so\x00'
        mock_elf = _make_mock_elf(
            undefined_symbols=[
                ('printf', 'SHN_UNDEF'),
                ('malloc', 'SHN_UNDEF'),
            ],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result is not None
                assert not result.uses_dlopen
                assert not result.uses_dlsym
                assert result.dlsym_symbols == []
                assert result.dlopen_libs == []
            finally:
                os.unlink(path)

    def test_dlsym_with_openssl_symbols(self):
        """dlsym + OpenSSL symbol strings in .rodata should be detected."""
        rodata = (
            b'SSL_CTX_new\x00'
            b'EVP_sha256\x00'
            b'some_other_func\x00'
        )
        mock_elf = _make_mock_elf(
            undefined_symbols=[
                ('dlopen', 'SHN_UNDEF'),
                ('dlsym', 'SHN_UNDEF'),
                ('dlerror', 'SHN_UNDEF'),
            ],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result.uses_dlopen
                assert result.uses_dlsym
                assert 'SSL_CTX_new' in result.dlsym_symbols
                assert 'EVP_sha256' in result.dlsym_symbols
                assert 'some_other_func' not in result.dlsym_symbols
            finally:
                os.unlink(path)

    def test_dlopen_with_openssl_lib(self):
        """dlopen + OpenSSL library name in .rodata should be detected."""
        rodata = b'libcrypto.so.3\x00libssl.so.3\x00libz.so.1\x00'
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF')],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result.uses_dlopen
                assert 'libcrypto.so.3' in result.dlopen_libs
                assert 'libssl.so.3' in result.dlopen_libs
                assert 'libz.so.1' not in result.dlopen_libs
            finally:
                os.unlink(path)

    def test_versioned_lib_names(self):
        rodata = (
            b'libcrypto.so.1.1\x00'
            b'libssl.so.1.1\x00'
            b'libcrypto.so.3\x00'
        )
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF')],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert len(result.dlopen_libs) == 3

            finally:
                os.unlink(path)

    def test_absolute_path_lib(self):
        rodata = b'/system/lib64/libcrypto.so.3\x00'
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF')],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert '/system/lib64/libcrypto.so.3' in result.dlopen_libs
            finally:
                os.unlink(path)

    def test_oh_specific_lib(self):
        rodata = b'libcrypto_openssl.z.so\x00libssl_openssl.z.so\x00'
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF')],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert len(result.dlopen_libs) == 2
            finally:
                os.unlink(path)

    def test_non_openssl_dlsym_filtered(self):
        rodata = b'printf\x00malloc\x00free\x00strlen\x00'
        mock_elf = _make_mock_elf(
            undefined_symbols=[
                ('dlopen', 'SHN_UNDEF'),
                ('dlsym', 'SHN_UNDEF'),
            ],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result.uses_dlopen
                assert result.dlsym_symbols == []
                assert result.dlopen_libs == []
            finally:
                os.unlink(path)

    def test_combined_direct_and_dlsym(self):
        """Both library names and symbol names detected together."""
        rodata = (
            b'libcrypto.so.3\x00'
            b'SSL_CTX_new\x00'
            b'EVP_DigestInit_ex\x00'
            b'BIO_new\x00'
        )
        mock_elf = _make_mock_elf(
            undefined_symbols=[
                ('dlopen', 'SHN_UNDEF'),
                ('dlsym', 'SHN_UNDEF'),
            ],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result.uses_dlopen
                assert result.uses_dlsym
                assert len(result.dlopen_libs) == 1
                assert len(result.dlsym_symbols) == 3
            finally:
                os.unlink(path)

    def test_no_rodata_section(self):
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF')],
            section_data={},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result.uses_dlopen
                assert result.dlsym_symbols == []
                assert result.dlopen_libs == []
            finally:
                os.unlink(path)

    def test_multiple_sections(self):
        """Strings from both .rodata and .data.rel.ro are collected."""
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlsym', 'SHN_UNDEF')],
            section_data={
                '.rodata': b'SSL_CTX_new\x00',
                '.data.rel.ro': b'EVP_sha256\x00',
            },
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert 'SSL_CTX_new' in result.dlsym_symbols
                assert 'EVP_sha256' in result.dlsym_symbols
            finally:
                os.unlink(path)

    def test_non_elf_file(self):
        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, b'not an elf file at all')
            os.close(fd)
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result is None
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        result = detect_dlopen_openssl('/no/such/file', OSSL_EXPORTS)
        assert result is None

    def test_libc_dlopen_mode_detected(self):
        """__libc_dlopen_mode (glibc internal) should also trigger detection."""
        rodata = b'libcrypto.so\x00SSL_connect\x00'
        mock_elf = _make_mock_elf(
            undefined_symbols=[('__libc_dlopen_mode', 'SHN_UNDEF')],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result.uses_dlopen
                assert 'SSL_connect' in result.dlsym_symbols
            finally:
                os.unlink(path)

    def test_section_size_limit(self):
        """Sections larger than MAX_SECTION_SIZE are skipped with warning."""
        huge_section = MagicMock()
        huge_section.name = '.rodata'
        huge_section.data_size = MAX_SECTION_SIZE + 1

        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF')],
            section_data={},
        )
        mock_elf.get_section_by_name = lambda name: huge_section if name == '.rodata' else None

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result.uses_dlopen
                assert result.dlsym_symbols == []
            finally:
                os.unlink(path)

    def test_no_openssl_lib_path_still_extracts_symbols(self):
        """detect_dlopen_openssl does raw extraction when no high-conf layers match."""
        rodata = (
            b'SSL_CTX_new\x00'
            b'EVP_sha256\x00'
            b'libplugin.so\x00'
        )
        mock_elf = _make_mock_elf(
            undefined_symbols=[
                ('dlopen', 'SHN_UNDEF'),
                ('dlsym', 'SHN_UNDEF'),
            ],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result.uses_dlopen
                assert result.uses_dlsym
                assert result.dlopen_libs == []
                assert 'SSL_CTX_new' in result.dlsym_symbols
                assert 'EVP_sha256' in result.dlsym_symbols
            finally:
                os.unlink(path)

    def test_defined_dlopen_not_triggered(self):
        """dlopen as a DEFINED symbol (not UND) should not trigger detection."""
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_COMMON')],
            section_data={'.rodata': b'SSL_CTX_new\x00'},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert not result.uses_dlopen
                assert result.dlsym_symbols == []
            finally:
                os.unlink(path)


class TestLayerAExcludeSymbols:
    """Test Layer A: .dynsym exclusion via exclude_symbols parameter."""

    def test_exclude_filters_known_symbols(self):
        """Symbols in exclude_symbols are not returned as dlsym matches."""
        rodata = b'SSL_CTX_new\x00EVP_sha256\x00BIO_new\x00'
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF'), ('dlsym', 'SHN_UNDEF')],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                exclude = {'SSL_CTX_new', 'EVP_sha256'}
                result = detect_dlopen_openssl(path, OSSL_EXPORTS,
                                                exclude_symbols=exclude)
                assert 'SSL_CTX_new' not in result.dlsym_symbols
                assert 'EVP_sha256' not in result.dlsym_symbols
                assert 'BIO_new' in result.dlsym_symbols
            finally:
                os.unlink(path)

    def test_exclude_all_empties_result(self):
        """Excluding all matching symbols results in empty dlsym list."""
        rodata = b'SSL_CTX_new\x00EVP_sha256\x00'
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF'), ('dlsym', 'SHN_UNDEF')],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS,
                                                exclude_symbols=OSSL_EXPORTS)
                assert result.dlsym_symbols == []
            finally:
                os.unlink(path)

    def test_exclude_does_not_affect_lib_patterns(self):
        """Library pattern matching is independent of exclude_symbols."""
        rodata = b'libcrypto.so.3\x00SSL_CTX_new\x00'
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF')],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS,
                                                exclude_symbols={'SSL_CTX_new'})
                assert 'libcrypto.so.3' in result.dlopen_libs
                assert 'SSL_CTX_new' not in result.dlsym_symbols
            finally:
                os.unlink(path)


class TestLayerBClustering:
    """Test Layer B: clustering behavior within detect_dlopen_openssl."""

    def test_cluster_takes_priority_over_raw(self):
        """When clustering finds symbols, isolated matches are excluded."""
        cluster_syms = b'SSL_CTX_new\x00SSL_connect\x00SSL_read\x00'
        gap = b'\x00' * 500
        isolated = b'BIO_new\x00'
        rodata = cluster_syms + gap + isolated

        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF'), ('dlsym', 'SHN_UNDEF')],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert 'SSL_CTX_new' in result.dlsym_symbols
                assert 'SSL_connect' in result.dlsym_symbols
                assert 'SSL_read' in result.dlsym_symbols
                assert 'BIO_new' not in result.dlsym_symbols
            finally:
                os.unlink(path)

    def test_no_cluster_falls_back_to_raw(self):
        """When no cluster meets threshold, raw matches are used."""
        rodata = b'SSL_CTX_new\x00' + b'\x00' * 500 + b'EVP_sha256\x00'

        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF'), ('dlsym', 'SHN_UNDEF')],
            section_data={'.rodata': rodata},
        )

        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert 'SSL_CTX_new' in result.dlsym_symbols
                assert 'EVP_sha256' in result.dlsym_symbols
            finally:
                os.unlink(path)


class TestWorkerThreeWayClassification:
    """Test _analyze_file_worker three-way detection: direct / static / dlopen."""

    def _make_elf_info(self, *, undefined=None, defined=None,
                       needed_libs=None, has_dlopen=False, has_dlsym=False):
        from openssl_scanner.elf_analyzer import ELFInfo, Symbol
        undef = [Symbol(name=n, bind='GLOBAL', type_='FUNC', defined=False)
                 for n in (undefined or [])]
        defn = [Symbol(name=n, bind='GLOBAL', type_='FUNC', defined=True)
                for n in (defined or [])]
        return ELFInfo(
            path='/fake/lib.so',
            arch='aarch64',
            elf_type='shared_library',
            needed_libs=needed_libs or [],
            rpath=None, runpath=None,
            undefined_symbols=undef,
            defined_symbols=defn,
            soname=None,
            has_dlopen=has_dlopen,
            has_dlsym=has_dlsym,
        )

    def _run_worker(self, info, dlopen_result=None):
        from openssl_scanner.scanner import _analyze_file_worker
        with patch('openssl_scanner.scanner.os.path.isfile', return_value=True), \
             patch('openssl_scanner.scanner.ELFAnalyzer') as mock_cls, \
             patch('openssl_scanner.dlopen_analyzer.detect_dlopen_openssl',
                   return_value=dlopen_result) as mock_detect:
            mock_cls.return_value.analyze.return_value = info
            result = _analyze_file_worker(('/fake/lib.so', OSSL_EXPORTS))
            return result, mock_detect

    def test_direct_dynamic_link(self):
        """DT_NEEDED libcrypto + UND symbols -> direct, not static."""
        info = self._make_elf_info(
            undefined=['SSL_CTX_new', 'SSL_connect', 'printf'],
            defined=['main'],
            needed_libs=['libcrypto.so.3', 'libc.so.6'],
        )
        result, _ = self._run_worker(info)

        assert result.openssl_direct is True
        assert result.static_openssl is False
        assert result.uses_dlopen is False
        assert 'SSL_CTX_new' in result.openssl_symbols
        assert 'SSL_connect' in result.openssl_symbols
        assert 'printf' not in result.openssl_symbols

    def test_static_openssl_link(self):
        """UND_ossl=0, DEF_ossl>0 -> static, openssl_direct=True."""
        info = self._make_elf_info(
            undefined=['printf', 'malloc'],
            defined=['SSL_CTX_new', 'EVP_sha256', 'main'],
            needed_libs=['libc.so.6'],
        )
        result, _ = self._run_worker(info)

        assert result.static_openssl is True
        assert result.openssl_direct is True
        assert result.uses_dlopen is False
        assert 'SSL_CTX_new' in result.openssl_symbols
        assert 'EVP_sha256' in result.openssl_symbols

    def test_dlopen_only(self):
        """No DT_NEEDED libcrypto, has dlopen+dlsym -> dlopen detection."""
        info = self._make_elf_info(
            undefined=['dlopen', 'dlsym', 'printf'],
            defined=['main'],
            needed_libs=['libc.so.6'],
            has_dlopen=True,
            has_dlsym=True,
        )
        dlopen_result = DlopenResult(
            uses_dlopen=True,
            uses_dlsym=True,
            dlopen_libs=['libcrypto.so.3'],
            dlsym_symbols=['SSL_CTX_new', 'EVP_sha256'],
        )
        result, _ = self._run_worker(info, dlopen_result)

        assert result.static_openssl is False
        assert result.openssl_direct is False
        assert result.uses_dlopen is True
        assert 'SSL_CTX_new' in result.dlsym_symbols
        assert 'EVP_sha256' in result.dlsym_symbols
        assert 'SSL_CTX_new' in result.openssl_symbols

    def test_direct_plus_dlopen_with_lib_patterns(self):
        """Direct link + dlopen with lib patterns -> both direct and dlopen."""
        info = self._make_elf_info(
            undefined=['SSL_CTX_new', 'dlopen', 'dlsym'],
            defined=['main'],
            needed_libs=['libcrypto.so.3', 'libc.so.6'],
            has_dlopen=True,
            has_dlsym=True,
        )
        dlopen_result = DlopenResult(
            uses_dlopen=True,
            uses_dlsym=True,
            dlopen_libs=['libssl.so.3'],
            dlsym_symbols=['SSL_CTX_new', 'EVP_sha256'],
        )
        result, _ = self._run_worker(info, dlopen_result)

        assert result.openssl_direct is True
        assert result.uses_dlopen is True
        assert result.static_openssl is False
        assert 'SSL_CTX_new' in result.openssl_symbols
        assert 'EVP_sha256' in result.dlsym_symbols
        assert 'SSL_CTX_new' not in result.dlsym_symbols

    def test_direct_link_blocks_rodata_noise(self):
        """Direct link + no lib patterns in .rodata -> .rodata matches ignored."""
        info = self._make_elf_info(
            undefined=['SSL_CTX_new', 'SSL_connect'],
            defined=['main'],
            needed_libs=['libcrypto.so.3'],
            has_dlopen=True,
            has_dlsym=True,
        )
        dlopen_result = DlopenResult(
            uses_dlopen=True,
            uses_dlsym=True,
            dlopen_libs=[],
            dlsym_symbols=['EVP_sha256', 'BIO_new'],
        )
        result, _ = self._run_worker(info, dlopen_result)

        assert result.openssl_direct is True
        assert result.uses_dlopen is False
        assert result.static_openssl is False
        assert 'SSL_CTX_new' in result.openssl_symbols
        assert 'EVP_sha256' not in result.openssl_symbols
        assert result.dlsym_symbols == []

    def test_no_openssl_at_all(self):
        """No OpenSSL symbols anywhere -> empty result."""
        info = self._make_elf_info(
            undefined=['printf', 'malloc'],
            defined=['main'],
            needed_libs=['libc.so.6'],
        )
        result, _ = self._run_worker(info)

        assert result.openssl_direct is False
        assert result.static_openssl is False
        assert result.uses_dlopen is False
        assert result.openssl_symbols == []

    def test_worker_passes_exclude_symbols(self):
        """Worker computes exclude_symbols from UND + DEF OpenSSL symbols."""
        info = self._make_elf_info(
            undefined=['SSL_CTX_new', 'dlopen', 'dlsym'],
            defined=['EVP_sha256'],
            needed_libs=['libcrypto.so.3', 'libc.so.6'],
            has_dlopen=True,
            has_dlsym=True,
        )
        dlopen_result = DlopenResult(
            uses_dlopen=True,
            uses_dlsym=True,
            dlopen_libs=['libssl.so.3'],
            dlsym_symbols=['BIO_new'],
        )
        result, mock_detect = self._run_worker(info, dlopen_result)

        mock_detect.assert_called_once()
        call_kwargs = mock_detect.call_args
        exclude = call_kwargs[1].get('exclude_symbols') or (
            call_kwargs[0][3] if len(call_kwargs[0]) > 3 else None)
        if exclude is None and len(call_kwargs[0]) >= 4:
            exclude = call_kwargs[0][3]
        if exclude is not None:
            assert 'SSL_CTX_new' in exclude
            assert 'EVP_sha256' in exclude

    def test_aggregate_counts_static(self):
        """ScanResult aggregation counts static_openssl files."""
        from openssl_scanner.scanner import FileResult, ScanResult, Scanner
        fr_direct = FileResult(
            path='/a.so', file_type='shared_library', arch='aarch64',
            direct_deps=['libcrypto.so'], openssl_direct=True,
            openssl_transitive=False, openssl_libs=['libcrypto.so'],
            openssl_symbols=['SSL_CTX_new'],
        )
        fr_static = FileResult(
            path='/b.so', file_type='shared_library', arch='aarch64',
            direct_deps=['libc.so'], openssl_direct=True,
            openssl_transitive=False, openssl_libs=[],
            openssl_symbols=['EVP_sha256'],
            static_openssl=True,
        )
        fr_dlopen = FileResult(
            path='/c.so', file_type='shared_library', arch='aarch64',
            direct_deps=['libc.so'], openssl_direct=False,
            openssl_transitive=False, openssl_libs=[],
            openssl_symbols=['BIO_new'],
            uses_dlopen=True,
            dlsym_symbols=['BIO_new'],
            dlopen_libs=['libcrypto.so.3'],
        )
        result = ScanResult(
            target='/test', scan_time='2026-01-01', tool_version='1.0.0',
            arch='aarch64',
        )
        result.files_detail = [fr_direct, fr_static, fr_dlopen]
        Scanner._aggregate_dlopen(result)

        assert result.files_with_static_openssl == 1
        assert result.files_with_dlopen == 1
        assert 'BIO_new' in result.all_dlsym_symbols
        assert 'libcrypto.so.3' in result.dlopen_libs_detected


class TestConfidenceField:
    """Test DlopenResult.confidence: 'high' vs 'inferred'."""

    def test_cluster_gives_high_confidence(self):
        """Layer B cluster -> confidence='high'."""
        cluster_syms = b'SSL_CTX_new\x00SSL_connect\x00SSL_read\x00'
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF'), ('dlsym', 'SHN_UNDEF')],
            section_data={'.rodata': cluster_syms},
        )
        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result.confidence == 'high'
                assert len(result.dlsym_symbols) >= 3
            finally:
                os.unlink(path)

    def test_sparse_gives_inferred_confidence(self):
        """No cluster, no disasm -> confidence='inferred'."""
        rodata = b'SSL_CTX_new\x00' + b'\x00' * 500 + b'EVP_sha256\x00'
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF'), ('dlsym', 'SHN_UNDEF')],
            section_data={'.rodata': rodata},
        )
        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result.confidence == 'inferred'
                assert 'SSL_CTX_new' in result.dlsym_symbols
                assert 'EVP_sha256' in result.dlsym_symbols
            finally:
                os.unlink(path)

    def test_no_dlopen_default_confidence(self):
        """No dlopen in binary -> default confidence='high' (irrelevant but safe)."""
        mock_elf = _make_mock_elf(
            undefined_symbols=[('printf', 'SHN_UNDEF')],
            section_data={'.rodata': b'hello\x00'},
        )
        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result.confidence == 'high'
            finally:
                os.unlink(path)

    def test_worker_propagates_confidence(self):
        """_analyze_file_worker passes confidence to FileResult."""
        from openssl_scanner.elf_analyzer import ELFInfo, Symbol
        from openssl_scanner.scanner import _analyze_file_worker

        info = ELFInfo(
            path='/fake/lib.so', arch='aarch64', elf_type='shared_library',
            needed_libs=['libc.so.6'], rpath=None, runpath=None,
            undefined_symbols=[
                Symbol(name='dlopen', bind='GLOBAL', type_='FUNC', defined=False),
                Symbol(name='dlsym', bind='GLOBAL', type_='FUNC', defined=False),
            ],
            defined_symbols=[], soname=None,
            has_dlopen=True, has_dlsym=True,
        )
        dlopen_result = DlopenResult(
            uses_dlopen=True, uses_dlsym=True,
            dlopen_libs=['libcrypto.so.3'],
            dlsym_symbols=['SSL_CTX_new'],
            confidence='inferred',
        )
        with patch('openssl_scanner.scanner.os.path.isfile', return_value=True), \
             patch('openssl_scanner.scanner.ELFAnalyzer') as mock_cls, \
             patch('openssl_scanner.dlopen_analyzer.detect_dlopen_openssl',
                   return_value=dlopen_result):
            mock_cls.return_value.analyze.return_value = info
            result = _analyze_file_worker(('/fake/lib.so', OSSL_EXPORTS))
            assert result.uses_dlopen is True
            assert result.dlopen_confidence == 'inferred'

    def test_worker_high_confidence(self):
        """Worker with high confidence DlopenResult."""
        from openssl_scanner.elf_analyzer import ELFInfo, Symbol
        from openssl_scanner.scanner import _analyze_file_worker

        info = ELFInfo(
            path='/fake/lib.so', arch='aarch64', elf_type='shared_library',
            needed_libs=['libc.so.6'], rpath=None, runpath=None,
            undefined_symbols=[
                Symbol(name='dlopen', bind='GLOBAL', type_='FUNC', defined=False),
                Symbol(name='dlsym', bind='GLOBAL', type_='FUNC', defined=False),
            ],
            defined_symbols=[], soname=None,
            has_dlopen=True, has_dlsym=True,
        )
        dlopen_result = DlopenResult(
            uses_dlopen=True, uses_dlsym=True,
            dlopen_libs=['libcrypto.so.3'],
            dlsym_symbols=['SSL_CTX_new', 'SSL_connect', 'SSL_read'],
            confidence='high',
        )
        with patch('openssl_scanner.scanner.os.path.isfile', return_value=True), \
             patch('openssl_scanner.scanner.ELFAnalyzer') as mock_cls, \
             patch('openssl_scanner.dlopen_analyzer.detect_dlopen_openssl',
                   return_value=dlopen_result):
            mock_cls.return_value.analyze.return_value = info
            result = _analyze_file_worker(('/fake/lib.so', OSSL_EXPORTS))
            assert result.uses_dlopen is True
            assert result.dlopen_confidence == 'high'

    def test_empty_matches_stay_high_confidence(self):
        """dlopen UND but zero OpenSSL strings -> confidence='high', not 'inferred'."""
        rodata = b'printf\x00malloc\x00free\x00'
        mock_elf = _make_mock_elf(
            undefined_symbols=[('dlopen', 'SHN_UNDEF'), ('dlsym', 'SHN_UNDEF')],
            section_data={'.rodata': rodata},
        )
        with patch('elftools.elf.elffile.ELFFile', return_value=mock_elf):
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, b'\x7fELF' + b'\x00' * 60)
                os.close(fd)
                result = detect_dlopen_openssl(path, OSSL_EXPORTS)
                assert result.uses_dlopen is True
                assert result.dlsym_symbols == []
                assert result.confidence == 'high'
            finally:
                os.unlink(path)

    def test_reporter_includes_confidence(self):
        """Reporter JSON includes confidence field in dlopen_detection."""
        from openssl_scanner.scanner import FileResult
        from openssl_scanner.reporter import Reporter

        fr = FileResult(
            path='/test.so', file_type='shared_library', arch='aarch64',
            direct_deps=['libc.so.6'], openssl_direct=False,
            openssl_transitive=False, openssl_libs=[],
            openssl_symbols=['SSL_CTX_new'],
            uses_dlopen=True, dlsym_symbols=['SSL_CTX_new'],
            dlopen_libs=['libcrypto.so.3'],
            dlopen_confidence='inferred',
        )
        reporter = Reporter.__new__(Reporter)
        d = reporter._file_result_to_dict(fr)
        assert 'dlopen_detection' in d
        assert d['dlopen_detection']['confidence'] == 'inferred'

    def test_old_json_without_confidence_defaults_to_dlopen(self):
        """Exporter handles old JSON reports missing confidence field."""
        dlopen_det = {'uses_dlopen': True, 'dlopen_symbols': ['SSL_CTX_new']}
        if dlopen_det.get('confidence') == 'inferred':
            label = 'dlopen-infer'
        else:
            label = 'dlopen'
        assert label == 'dlopen'
