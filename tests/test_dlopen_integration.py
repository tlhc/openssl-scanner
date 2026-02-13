"""
Integration tests with real ELF binaries for dlopen/dlsym detection.

Tests all three layers (A: dynsym exclusion, B: clustering, C: disassembly)
against programmatically constructed ELF files with valid section layouts.

Coverage:
  - aarch64 and x86_64 architectures
  - 7 detection scenarios (direct, dlopen-cluster, dlopen-sparse, static,
    mixed, no-openssl, HarmonyOS plugin)
  - Layer C end-to-end (real PLT + .text instruction patterns)
  - Cross-architecture consistency
"""
import os
import struct
import tempfile

import pytest

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'fixtures'))

from elf_builder import ELFBuilder
from openssl_scanner.dlopen_analyzer import (
    DlopenResult,
    detect_dlopen_openssl,
    _AARCH64_BL_OPCODE,
    _AARCH64_ADRP_OPCODE,
    _AARCH64_ADD_IMM_OPCODE,
    _AARCH64_PLT_HEADER_SIZE,
    _AARCH64_PLT_ENTRY_SIZE,
    _X86_64_PLT_HEADER_SIZE,
    _X86_64_PLT_ENTRY_SIZE,
)
from openssl_scanner.constants import OPENSSL_LIBRARY_PATTERNS


OSSL_EXPORTS = {
    'SSL_CTX_new', 'SSL_connect', 'SSL_read', 'SSL_write',
    'SSL_CTX_free', 'SSL_free', 'SSL_new', 'SSL_set_fd',
    'EVP_DigestInit_ex', 'EVP_DigestUpdate', 'EVP_DigestFinal_ex',
    'EVP_sha256', 'EVP_MD_CTX_new', 'EVP_MD_CTX_free',
    'BIO_new', 'BIO_free', 'BIO_read', 'BIO_write',
    'OPENSSL_init_ssl', 'OPENSSL_init_crypto',
    'X509_get_subject_name', 'RSA_generate_key_ex',
    'EVP_EncryptInit_ex', 'EVP_DecryptInit_ex',
    'EVP_PKEY_new', 'EVP_PKEY_free',
}


def _encode_aarch64_adrp(rd, imm21):
    if imm21 < 0:
        imm21 += 0x200000
    immhi = (imm21 >> 2) & 0x7FFFF
    immlo = imm21 & 0x3
    insn = _AARCH64_ADRP_OPCODE | (immlo << 29) | (immhi << 5) | (rd & 0x1F)
    return struct.pack('<I', insn)


def _encode_aarch64_add_imm(rd, rn, imm12):
    insn = _AARCH64_ADD_IMM_OPCODE | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)
    return struct.pack('<I', insn)


def _encode_aarch64_bl(pc, target):
    offset = (target - pc) // 4
    if offset < 0:
        offset += 0x04000000
    insn = _AARCH64_BL_OPCODE | (offset & 0x03FFFFFF)
    return struct.pack('<I', insn)


def _encode_aarch64_nop():
    return struct.pack('<I', 0xD503201F)


def _encode_x86_64_lea_rsi_rip(lea_vaddr, target_addr):
    disp32 = target_addr - (lea_vaddr + 7)
    return bytes([0x48, 0x8D, 0x35]) + struct.pack('<i', disp32)


def _encode_x86_64_call_rel32(call_vaddr, target_addr):
    rel32 = target_addr - (call_vaddr + 5)
    return bytes([0xE8]) + struct.pack('<i', rel32)


def _write_temp_elf(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix='.so')
    os.write(fd, data)
    os.close(fd)
    return path


class TestScenario1DirectLink:
    """Scenario 1: Binary directly links libcrypto (UND symbols in .dynsym)."""

    def test_aarch64_direct_link_detected(self):
        elf = (ELFBuilder('aarch64')
               .add_dynsym('SSL_CTX_new')
               .add_dynsym('SSL_connect')
               .add_dynsym('EVP_sha256')
               .add_dynsym('printf')
               .set_rodata(b'some_log_string\x00error: %s\x00'))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result is not None
            assert not result.uses_dlopen
            assert not result.uses_dlsym
            assert result.dlsym_symbols == []
            assert result.dlopen_libs == []
        finally:
            os.unlink(path)

    def test_x86_64_direct_link_detected(self):
        elf = (ELFBuilder('x86_64')
               .add_dynsym('SSL_CTX_new')
               .add_dynsym('SSL_read')
               .add_dynsym('BIO_new')
               .set_rodata(b'log message\x00'))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result is not None
            assert not result.uses_dlopen
            assert result.dlsym_symbols == []
        finally:
            os.unlink(path)


class TestScenario2DlopenCluster:
    """Scenario 2: dlopen+dlsym with clustered OpenSSL symbols in .rodata.
    Layer B should find the cluster and return high-confidence results.
    """

    def _build_clustered_rodata(self):
        syms = [b'SSL_CTX_new', b'SSL_connect', b'SSL_read',
                b'EVP_sha256', b'EVP_DigestInit_ex']
        data = b''
        for s in syms:
            data += s + b'\x00'
        return data

    def test_aarch64_cluster_detected(self):
        rodata = self._build_clustered_rodata()
        elf = (ELFBuilder('aarch64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym')
               .add_dynsym('dlerror')
               .set_rodata(b'libcrypto.so.3\x00' + rodata))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result.uses_dlopen
            assert result.uses_dlsym
            assert 'libcrypto.so.3' in result.dlopen_libs
            assert 'SSL_CTX_new' in result.dlsym_symbols
            assert 'SSL_connect' in result.dlsym_symbols
            assert 'EVP_sha256' in result.dlsym_symbols
            assert len(result.dlsym_symbols) == 5
        finally:
            os.unlink(path)

    def test_x86_64_cluster_detected(self):
        rodata = self._build_clustered_rodata()
        elf = (ELFBuilder('x86_64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym')
               .set_rodata(rodata))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result.uses_dlopen
            assert result.uses_dlsym
            assert len(result.dlsym_symbols) == 5
        finally:
            os.unlink(path)


class TestScenario3DlopenSparse:
    """Scenario 3: dlopen+dlsym with isolated (sparse) OpenSSL symbols.
    No cluster, no disassembly -> falls back to raw .rodata matching.
    """

    def test_sparse_falls_back_to_raw(self):
        rodata = (b'SSL_CTX_new\x00'
                  + b'\x00' * 500
                  + b'EVP_sha256\x00')
        elf = (ELFBuilder('aarch64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym')
               .set_rodata(rodata))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result.uses_dlopen
            assert 'SSL_CTX_new' in result.dlsym_symbols
            assert 'EVP_sha256' in result.dlsym_symbols
        finally:
            os.unlink(path)


class TestScenario4StaticLink:
    """Scenario 4: Defines (exports) OpenSSL-named symbols - simulated static link.
    .dynsym has symbols as DEFINED, not UND. No dlopen/dlsym.
    """

    def test_static_no_dlopen_no_dlsym(self):
        elf = (ELFBuilder('aarch64')
               .add_dynsym('SSL_CTX_new', defined=True)
               .add_dynsym('EVP_sha256', defined=True)
               .add_dynsym('BIO_new', defined=True)
               .set_rodata(b'static build log\x00'))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result is not None
            assert not result.uses_dlopen
            assert not result.uses_dlsym
            assert result.dlsym_symbols == []
        finally:
            os.unlink(path)


class TestScenario5Mixed:
    """Scenario 5: Direct link + dlopen for additional symbols.
    UND OpenSSL symbols + dlopen/dlsym + more symbols in .rodata.
    Layer A should exclude the UND symbols from .rodata candidates.
    """

    def test_mixed_exclude_und_symbols(self):
        rodata = (b'SSL_CTX_new\x00'
                  b'EVP_DigestInit_ex\x00'
                  b'EVP_DigestUpdate\x00'
                  b'EVP_DigestFinal_ex\x00'
                  b'libcrypto.so.3\x00')
        elf = (ELFBuilder('aarch64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym')
               .add_dynsym('SSL_CTX_new')
               .add_dynsym('SSL_connect')
               .set_rodata(rodata))
        path = _write_temp_elf(elf.build())
        try:
            exclude = {'SSL_CTX_new', 'SSL_connect'}
            result = detect_dlopen_openssl(path, OSSL_EXPORTS,
                                           exclude_symbols=exclude)
            assert result.uses_dlopen
            assert result.uses_dlsym
            assert 'SSL_CTX_new' not in result.dlsym_symbols
            assert 'SSL_connect' not in result.dlsym_symbols
            assert 'EVP_DigestInit_ex' in result.dlsym_symbols
            assert 'EVP_DigestUpdate' in result.dlsym_symbols
            assert 'libcrypto.so.3' in result.dlopen_libs
        finally:
            os.unlink(path)


class TestScenario6NoOpenSSL:
    """Scenario 6: No OpenSSL at all (negative control)."""

    def test_no_openssl_empty_result(self):
        elf = (ELFBuilder('x86_64')
               .add_dynsym('printf')
               .add_dynsym('malloc')
               .set_rodata(b'hello world\x00error: %d\x00'))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result is not None
            assert not result.uses_dlopen
            assert not result.uses_dlsym
            assert result.dlsym_symbols == []
            assert result.dlopen_libs == []
        finally:
            os.unlink(path)

    def test_dlopen_but_no_openssl_symbols(self):
        elf = (ELFBuilder('aarch64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym')
               .set_rodata(b'libplugin.so\x00custom_func\x00init_module\x00'))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result.uses_dlopen
            assert result.uses_dlsym
            assert result.dlsym_symbols == []
            assert result.dlopen_libs == []
        finally:
            os.unlink(path)


class TestScenario7HarmonyOSPlugin:
    """Scenario 7: HarmonyOS-style plugin.
    dlopen('libcrypto_openssl.z.so') with OpenSSL symbol dispatch table.
    """

    def test_hm_lib_pattern_detected(self):
        hm_syms = (b'SSL_CTX_new\x00SSL_connect\x00SSL_read\x00'
                   b'SSL_write\x00EVP_sha256\x00EVP_DigestInit_ex\x00')
        rodata = (b'libcrypto_openssl.z.so\x00'
                  b'libssl_openssl.z.so\x00'
                  + hm_syms)
        elf = (ELFBuilder('aarch64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym')
               .add_dynsym('dlerror')
               .set_rodata(rodata))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result.uses_dlopen
            assert result.uses_dlsym
            assert 'libcrypto_openssl.z.so' in result.dlopen_libs
            assert 'libssl_openssl.z.so' in result.dlopen_libs
            assert len(result.dlsym_symbols) == 6
            for s in ['SSL_CTX_new', 'SSL_connect', 'SSL_read',
                       'SSL_write', 'EVP_sha256', 'EVP_DigestInit_ex']:
                assert s in result.dlsym_symbols
        finally:
            os.unlink(path)

    def test_hm_x86_64_variant(self):
        """x86_64 variant for HarmonyOS emulator."""
        rodata = (b'libcrypto_openssl.z.so\x00'
                  b'SSL_CTX_new\x00SSL_connect\x00SSL_read\x00'
                  b'EVP_sha256\x00BIO_new\x00')
        elf = (ELFBuilder('x86_64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym')
               .set_rodata(rodata))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result.uses_dlopen
            assert 'libcrypto_openssl.z.so' in result.dlopen_libs
            assert len(result.dlsym_symbols) == 5
        finally:
            os.unlink(path)


class TestLayerCEndToEnd:
    """End-to-end Layer C (disassembly) tests with real ELF section layout.
    Constructs valid .plt + .rela.plt + .text + .rodata in a single ELF.
    """

    def test_aarch64_disasm_confirms_symbol(self):
        """aarch64: ADRP+ADD+BL pattern -> Layer C confirms the symbol."""
        text_vaddr = 0x1000
        rodata_vaddr = 0x2000
        plt_base = 0x400
        string_offset = 0x100
        string_addr = rodata_vaddr + string_offset

        dlsym_sym_idx = 2
        dlsym_plt_addr = plt_base + _AARCH64_PLT_HEADER_SIZE + 0 * _AARCH64_PLT_ENTRY_SIZE

        adrp_pc = text_vaddr
        adrp_imm21 = (rodata_vaddr - (adrp_pc & ~0xFFF)) >> 12

        text = b''
        text += _encode_aarch64_adrp(1, adrp_imm21)
        text += _encode_aarch64_add_imm(1, 1, string_offset)
        text += _encode_aarch64_bl(text_vaddr + 8, dlsym_plt_addr)

        rodata = b'\x00' * string_offset + b'EVP_sha256\x00padding\x00'
        cluster = b'SSL_CTX_new\x00SSL_connect\x00SSL_read\x00BIO_new\x00'
        rodata += cluster

        elf = (ELFBuilder('aarch64')
               .add_dynsym('printf')
               .add_dynsym('dlsym')
               .add_dynsym('dlopen')
               .set_rodata(rodata, vaddr=rodata_vaddr)
               .set_text(text, vaddr=text_vaddr)
               .set_plt(base_vaddr=plt_base)
               .add_rela_plt(sym_idx=dlsym_sym_idx, got_offset=0x3000))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result.uses_dlopen
            assert result.uses_dlsym
            assert 'EVP_sha256' in result.dlsym_symbols
            assert 'SSL_CTX_new' in result.dlsym_symbols
        finally:
            os.unlink(path)

    def test_x86_64_disasm_confirms_symbol(self):
        """x86_64: LEA RSI+CALL pattern -> Layer C confirms the symbol."""
        text_vaddr = 0x1000
        rodata_vaddr = 0x2000
        plt_base = 0x400
        string_offset = 0x80
        string_addr = rodata_vaddr + string_offset

        dlsym_sym_idx = 1
        dlsym_plt_addr = plt_base + _X86_64_PLT_HEADER_SIZE + 0 * _X86_64_PLT_ENTRY_SIZE

        text = b''
        lea_vaddr = text_vaddr
        text += _encode_x86_64_lea_rsi_rip(lea_vaddr, string_addr)
        call_vaddr = text_vaddr + 7
        text += _encode_x86_64_call_rel32(call_vaddr, dlsym_plt_addr)

        rodata = b'\x00' * string_offset + b'BIO_new\x00'
        rodata += b'SSL_CTX_new\x00SSL_connect\x00SSL_read\x00'

        elf = (ELFBuilder('x86_64')
               .add_dynsym('dlsym')
               .add_dynsym('dlopen')
               .set_rodata(rodata, vaddr=rodata_vaddr)
               .set_text(text, vaddr=text_vaddr)
               .set_plt(base_vaddr=plt_base)
               .add_rela_plt(sym_idx=dlsym_sym_idx, got_offset=0x3000))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result.uses_dlopen
            assert result.uses_dlsym
            assert 'BIO_new' in result.dlsym_symbols
            assert 'SSL_CTX_new' in result.dlsym_symbols
        finally:
            os.unlink(path)

    def test_aarch64_multiple_dlsym_calls(self):
        """Multiple BL dlsym sites, each resolving a different symbol."""
        text_vaddr = 0x1000
        rodata_vaddr = 0x2000
        plt_base = 0x400
        dlsym_sym_idx = 1
        dlsym_plt_addr = plt_base + _AARCH64_PLT_HEADER_SIZE

        sym1_offset = 0x100
        sym2_offset = 0x200
        sym1_addr = rodata_vaddr + sym1_offset
        sym2_addr = rodata_vaddr + sym2_offset

        text = b''
        pc = text_vaddr

        imm21_1 = (rodata_vaddr - (pc & ~0xFFF)) >> 12
        text += _encode_aarch64_adrp(1, imm21_1)
        text += _encode_aarch64_add_imm(1, 1, sym1_offset)
        text += _encode_aarch64_bl(pc + 8, dlsym_plt_addr)
        pc += 12

        imm21_2 = (rodata_vaddr - (pc & ~0xFFF)) >> 12
        text += _encode_aarch64_adrp(1, imm21_2)
        text += _encode_aarch64_add_imm(1, 1, sym2_offset)
        text += _encode_aarch64_bl(pc + 8, dlsym_plt_addr)

        rodata = bytearray(0x300)
        s1 = b'SSL_CTX_new'
        s2 = b'EVP_sha256'
        rodata[sym1_offset:sym1_offset + len(s1)] = s1
        rodata[sym2_offset:sym2_offset + len(s2)] = s2
        rodata = bytes(rodata)

        elf = (ELFBuilder('aarch64')
               .add_dynsym('dlsym')
               .add_dynsym('dlopen')
               .set_rodata(rodata, vaddr=rodata_vaddr)
               .set_text(text, vaddr=text_vaddr)
               .set_plt(base_vaddr=plt_base)
               .add_rela_plt(sym_idx=dlsym_sym_idx))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert 'SSL_CTX_new' in result.dlsym_symbols
            assert 'EVP_sha256' in result.dlsym_symbols
        finally:
            os.unlink(path)


class TestLayerAWithRealELF:
    """Layer A: exclude_symbols with real ELF section layout."""

    def test_exclude_removes_und_from_candidates(self):
        """Symbols already in .dynsym UND should be excluded from dlsym results."""
        rodata = (b'SSL_CTX_new\x00SSL_connect\x00SSL_read\x00'
                  b'EVP_DigestInit_ex\x00EVP_sha256\x00BIO_new\x00')
        elf = (ELFBuilder('aarch64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym')
               .add_dynsym('SSL_CTX_new')
               .add_dynsym('SSL_connect')
               .set_rodata(rodata))
        path = _write_temp_elf(elf.build())
        try:
            exclude = {'SSL_CTX_new', 'SSL_connect'}
            result = detect_dlopen_openssl(path, OSSL_EXPORTS,
                                           exclude_symbols=exclude)
            assert 'SSL_CTX_new' not in result.dlsym_symbols
            assert 'SSL_connect' not in result.dlsym_symbols
            assert 'EVP_DigestInit_ex' in result.dlsym_symbols
            assert 'EVP_sha256' in result.dlsym_symbols
            assert 'BIO_new' in result.dlsym_symbols
        finally:
            os.unlink(path)

    def test_exclude_all_produces_empty(self):
        rodata = b'SSL_CTX_new\x00EVP_sha256\x00'
        elf = (ELFBuilder('x86_64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym')
               .set_rodata(rodata))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS,
                                           exclude_symbols=OSSL_EXPORTS)
            assert result.dlsym_symbols == []
        finally:
            os.unlink(path)


class TestLayerBWithRealELF:
    """Layer B: clustering with real ELF binary layout."""

    def test_cluster_filters_isolated_symbol(self):
        cluster = b'SSL_CTX_new\x00SSL_connect\x00SSL_read\x00EVP_sha256\x00'
        gap = b'\x00' * 500
        isolated = b'BIO_new\x00'
        rodata = cluster + gap + isolated

        elf = (ELFBuilder('aarch64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym')
               .set_rodata(rodata))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert 'SSL_CTX_new' in result.dlsym_symbols
            assert 'SSL_connect' in result.dlsym_symbols
            assert 'SSL_read' in result.dlsym_symbols
            assert 'EVP_sha256' in result.dlsym_symbols
            assert 'BIO_new' not in result.dlsym_symbols
        finally:
            os.unlink(path)


class TestMultiSectionRealELF:
    """Test with .rodata + .data.rel.ro both present."""

    def test_symbols_from_both_sections(self):
        rodata = b'SSL_CTX_new\x00SSL_connect\x00SSL_read\x00'
        data_rel_ro = b'EVP_sha256\x00EVP_DigestInit_ex\x00BIO_new\x00'

        elf = (ELFBuilder('x86_64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym')
               .set_rodata(rodata, vaddr=0x2000)
               .set_data_rel_ro(data_rel_ro, vaddr=0x3000))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result.uses_dlopen
            all_syms = set(result.dlsym_symbols)
            assert 'SSL_CTX_new' in all_syms
            assert 'EVP_sha256' in all_syms
            assert 'BIO_new' in all_syms
            assert len(all_syms) == 6
        finally:
            os.unlink(path)


class TestCrossArchConsistency:
    """Same scenario on both architectures should produce same detection results."""

    def test_cluster_detection_same_across_archs(self):
        rodata = (b'libcrypto.so.3\x00'
                  b'SSL_CTX_new\x00SSL_connect\x00SSL_read\x00'
                  b'EVP_sha256\x00BIO_new\x00')

        results = {}
        for arch in ('aarch64', 'x86_64'):
            elf = (ELFBuilder(arch)
                   .add_dynsym('dlopen')
                   .add_dynsym('dlsym')
                   .set_rodata(rodata))
            path = _write_temp_elf(elf.build())
            try:
                results[arch] = detect_dlopen_openssl(path, OSSL_EXPORTS)
            finally:
                os.unlink(path)

        for arch in ('aarch64', 'x86_64'):
            r = results[arch]
            assert r.uses_dlopen, f"{arch}: should detect dlopen"
            assert r.uses_dlsym, f"{arch}: should detect dlsym"
            assert 'libcrypto.so.3' in r.dlopen_libs, f"{arch}: should detect lib"
            assert set(r.dlsym_symbols) == {
                'SSL_CTX_new', 'SSL_connect', 'SSL_read',
                'EVP_sha256', 'BIO_new',
            }, f"{arch}: symbol set mismatch"


class TestEdgeCases:
    """Edge cases for real ELF parsing."""

    def test_empty_rodata(self):
        elf = (ELFBuilder('aarch64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym')
               .set_rodata(b'\x00'))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result.uses_dlopen
            assert result.dlsym_symbols == []
        finally:
            os.unlink(path)

    def test_no_rodata_section(self):
        elf = (ELFBuilder('x86_64')
               .add_dynsym('dlopen')
               .add_dynsym('dlsym'))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result.uses_dlopen
            assert result.dlsym_symbols == []
            assert result.dlopen_libs == []
        finally:
            os.unlink(path)

    def test_truncated_elf(self):
        path = _write_temp_elf(b'\x7fELF' + b'\x00' * 10)
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result is None
        finally:
            os.unlink(path)

    def test_non_elf_magic(self):
        path = _write_temp_elf(b'NOT_ELF_FILE_AT_ALL')
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result is None
        finally:
            os.unlink(path)

    def test_libc_dlopen_mode(self):
        """__libc_dlopen_mode (glibc internal) triggers detection."""
        rodata = b'libcrypto.so.3\x00SSL_CTX_new\x00SSL_connect\x00SSL_read\x00'
        elf = (ELFBuilder('aarch64')
               .add_dynsym('__libc_dlopen_mode')
               .add_dynsym('__libc_dlsym')
               .set_rodata(rodata))
        path = _write_temp_elf(elf.build())
        try:
            result = detect_dlopen_openssl(path, OSSL_EXPORTS)
            assert result.uses_dlopen
            assert result.uses_dlsym
            assert 'libcrypto.so.3' in result.dlopen_libs
            assert len(result.dlsym_symbols) == 3
        finally:
            os.unlink(path)
