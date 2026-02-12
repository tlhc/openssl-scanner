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
