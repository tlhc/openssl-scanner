"""Tests for mmap code path in static_detector.py.

Patches _MAX_SCAN_SIZE to 0 to force mmap usage on small test files,
validating that detect_static_ssl and scan_hidden_static_symbols work
correctly when the underlying data is an mmap object (no .split method).
"""

import os
import tempfile
import unittest
from unittest.mock import patch
from openssl_scanner.static_detector import (
    detect_static_ssl,
    scan_hidden_static_symbols,
    _extract_printable_strings,
)


class TestExtractPrintableStrings(unittest.TestCase):
    """Unit tests for _extract_printable_strings on both bytes and mmap."""

    def test_basic_extraction(self):
        data = b"\x00hello\x00world\x00foo\x00ab\x00"
        result = _extract_printable_strings(data)
        assert "hello" in result
        assert "world" in result
        assert "ab" not in result  # < 4 chars

    def test_non_ascii_skipped(self):
        data = b"\x00\xff\xfe\xfd\xfc\x00good_sym\x00"
        result = _extract_printable_strings(data)
        assert "good_sym" in result
        assert len(result) == 1

    def test_non_printable_skipped(self):
        data = b"\x00he\x01llo\x00SSL_CTX_new\x00"
        result = _extract_printable_strings(data)
        assert "SSL_CTX_new" in result
        assert len(result) == 1

    def test_empty_data(self):
        result = _extract_printable_strings(b"")
        assert len(result) == 0

    def test_works_on_mmap(self):
        content = b"\x00SSL_connect\x00EVP_DigestInit\x00ab\x00"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            import mmap
            with open(path, 'rb') as fobj:
                with mmap.mmap(fobj.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    result = _extract_printable_strings(mm)
                    assert "SSL_connect" in result
                    assert "EVP_DigestInit" in result
                    assert "ab" not in result
        finally:
            os.unlink(path)


class TestDetectStaticSSLMmap(unittest.TestCase):
    """Test detect_static_ssl through the mmap code path."""

    def test_strict_banner_via_mmap(self):
        content = b"\x00OpenSSL 1.1.1t  7 Feb 2023\x00"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            with patch('openssl_scanner.static_detector._MAX_SCAN_SIZE', 0):
                result = detect_static_ssl(path)
                assert result.detected
                assert result.version == "1.1.1t"
                assert "version_banner_strict" in result.signals
        finally:
            os.unlink(path)

    def test_loose_banner_with_corroboration_via_mmap(self):
        content = (
            b"\x00OpenSSL 3.0.0\x00"
            b"SSL_CTX_new\x00"
            b"EVP_EncryptInit\x00"
            b"SHA256_Update\x00"
        )
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            with patch('openssl_scanner.static_detector._MAX_SCAN_SIZE', 0):
                result = detect_static_ssl(path)
                assert result.detected
                assert result.version == "3.0.0"
                corr = [s for s in result.signals
                        if s.startswith('corroborating_symbols_')]
                assert len(corr) > 0
        finally:
            os.unlink(path)


class TestScanHiddenStaticSymbolsMmap(unittest.TestCase):
    """Test scan_hidden_static_symbols through the mmap code path."""

    def test_finds_symbols_via_mmap(self):
        content = (
            b"\x00SSL_CTX_new\x00"
            b"EVP_EncryptInit_ex\x00"
            b"not_openssl_sym\x00"
            b"BIO_new_socket\x00"
        )
        exports = {"SSL_CTX_new", "EVP_EncryptInit_ex", "BIO_new_socket"}
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            with patch('openssl_scanner.static_detector._MAX_SCAN_SIZE', 0):
                found = scan_hidden_static_symbols(path, exports)
                assert "SSL_CTX_new" in found
                assert "EVP_EncryptInit_ex" in found
                assert "BIO_new_socket" in found
                assert "not_openssl_sym" not in found
        finally:
            os.unlink(path)

    def test_empty_file_via_mmap(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            with patch('openssl_scanner.static_detector._MAX_SCAN_SIZE', 0):
                found = scan_hidden_static_symbols(path, {"SSL_CTX_new"})
                assert found == []
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
