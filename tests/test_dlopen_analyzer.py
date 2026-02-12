"""Tests for dlopen/dlsym OpenSSL detection."""

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
    detect_dlopen_openssl,
    _is_openssl_lib_string,
    STRING_SECTIONS,
    MAX_SECTION_SIZE,
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


def _make_mock_elf(undefined_symbols=None, section_data=None):
    """Create a mock ELFFile for testing.

    Args:
        undefined_symbols: list of (name, shndx) pairs for .dynsym
        section_data: dict of section_name -> bytes for data sections
    """
    if undefined_symbols is None:
        undefined_symbols = []
    if section_data is None:
        section_data = {}

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
        """dlopen/dlsym without OpenSSL library path still extracts symbols.

        detect_dlopen_openssl does raw extraction. Policy decisions
        (e.g., gating on openssl_direct) are in the scanner worker.
        """
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
            return _analyze_file_worker(('/fake/lib.so', OSSL_EXPORTS))

    def test_direct_dynamic_link(self):
        """DT_NEEDED libcrypto + UND symbols -> direct, not static."""
        info = self._make_elf_info(
            undefined=['SSL_CTX_new', 'SSL_connect', 'printf'],
            defined=['main'],
            needed_libs=['libcrypto.so.3', 'libc.so.6'],
        )
        result = self._run_worker(info)

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
        result = self._run_worker(info)

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
        result = self._run_worker(info, dlopen_result)

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
        result = self._run_worker(info, dlopen_result)

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
        result = self._run_worker(info, dlopen_result)

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
        result = self._run_worker(info)

        assert result.openssl_direct is False
        assert result.static_openssl is False
        assert result.uses_dlopen is False
        assert result.openssl_symbols == []

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
