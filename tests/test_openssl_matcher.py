"""Tests for OpenSSL symbol matcher (strict mode)."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openssl_scanner.openssl_matcher import OpenSSLMatcher


class TestOpenSSLMatcherStrict:
    """Test cases for OpenSSLMatcher class in strict mode."""

    def setup_method(self):
        """Set up test fixtures with mock OpenSSL symbols."""
        self.matcher = OpenSSLMatcher()
        self.matcher._openssl_exports = {
            "EVP_DigestInit_ex",
            "EVP_MD_CTX_new",
            "EVP_sha256",
            "SSL_connect",
            "SSL_read",
            "SSL_write",
            "SSL_CTX_new",
            "RSA_public_encrypt",
            "RSA_private_decrypt",
            "EC_KEY_new",
            "ECDSA_sign",
            "ECDH_compute_key",
            "SM2_sign",
            "SM3_Init",
            "SM4_encrypt",
            "OPENSSL_init_crypto",
            "OpenSSL_version",
            "SHA256_Init",
            "MD5_Init",
            "TLS_method",
            "DTLS_method",
            "RSA_sign",
            "BN_new",
        }

    def test_is_loaded(self):
        """Test is_loaded check."""
        assert self.matcher.is_loaded()
        empty_matcher = OpenSSLMatcher()
        assert not empty_matcher.is_loaded()

    def test_is_openssl_symbol_evp(self):
        """Test EVP symbol recognition."""
        assert self.matcher.is_openssl_symbol("EVP_DigestInit_ex")
        assert self.matcher.is_openssl_symbol("EVP_MD_CTX_new")
        assert self.matcher.is_openssl_symbol("EVP_sha256")

    def test_is_openssl_symbol_ssl(self):
        """Test SSL symbol recognition."""
        assert self.matcher.is_openssl_symbol("SSL_connect")
        assert self.matcher.is_openssl_symbol("SSL_read")
        assert self.matcher.is_openssl_symbol("SSL_CTX_new")

    def test_is_openssl_symbol_rsa(self):
        """Test RSA symbol recognition."""
        assert self.matcher.is_openssl_symbol("RSA_public_encrypt")
        assert self.matcher.is_openssl_symbol("RSA_private_decrypt")

    def test_is_openssl_symbol_ec(self):
        """Test EC symbol recognition."""
        assert self.matcher.is_openssl_symbol("EC_KEY_new")
        assert self.matcher.is_openssl_symbol("ECDSA_sign")
        assert self.matcher.is_openssl_symbol("ECDH_compute_key")

    def test_is_openssl_symbol_sm(self):
        """Test SM symbol recognition for Chinese algorithms."""
        assert self.matcher.is_openssl_symbol("SM2_sign")
        assert self.matcher.is_openssl_symbol("SM3_Init")
        assert self.matcher.is_openssl_symbol("SM4_encrypt")

    def test_is_openssl_symbol_exact_match(self):
        """Test exact symbol matching."""
        assert self.matcher.is_openssl_symbol("OPENSSL_init_crypto")
        assert self.matcher.is_openssl_symbol("OpenSSL_version")

    def test_is_not_openssl_symbol(self):
        """Test non-OpenSSL symbols are rejected."""
        assert not self.matcher.is_openssl_symbol("printf")
        assert not self.matcher.is_openssl_symbol("malloc")
        assert not self.matcher.is_openssl_symbol("pthread_create")
        assert not self.matcher.is_openssl_symbol("memcpy")
        assert not self.matcher.is_openssl_symbol("EVP_unknown_symbol")

    def test_is_openssl_library(self):
        """Test OpenSSL library name detection."""
        assert self.matcher.is_openssl_library("libcrypto.so.3")
        assert self.matcher.is_openssl_library("libssl.so.3")
        assert self.matcher.is_openssl_library("libcrypto_openssl.so")
        assert self.matcher.is_openssl_library("libssl_openssl.so")
        assert self.matcher.is_openssl_library("libopenssl.so")
        assert self.matcher.is_openssl_library("libopenssl.so.1.1")
        assert self.matcher.is_openssl_library("libboringssl.so")
        assert self.matcher.is_openssl_library("libboringssl.so.1")
        assert self.matcher.is_openssl_library("libboringcrypto.so")

    def test_is_not_openssl_library(self):
        """Test non-OpenSSL library names."""
        assert not self.matcher.is_openssl_library("libc.so.6")
        assert not self.matcher.is_openssl_library("libstdc++.so.6")
        assert not self.matcher.is_openssl_library("libcurl.so")
        # Regression test for Codex Finding 1: non-so files should not match
        assert not self.matcher.is_openssl_library("libcrypto.txt")
        assert not self.matcher.is_openssl_library("libssl_readme.md")

    def test_categorize_symbol_ssl(self):
        """Test SSL symbol categorization."""
        assert self.matcher.categorize_symbol("SSL_connect") == "ssl_core"
        assert self.matcher.categorize_symbol("SSL_read") == "ssl_core"

    def test_categorize_symbol_tls(self):
        """Test TLS symbol categorization."""
        assert self.matcher.categorize_symbol("TLS_method") == "ssl_tls"
        assert self.matcher.categorize_symbol("DTLS_method") == "ssl_tls"

    def test_categorize_symbol_evp(self):
        """Test EVP symbol categorization."""
        assert self.matcher.categorize_symbol("EVP_DigestInit_ex") == "crypto_evp"
        assert self.matcher.categorize_symbol("EVP_sha256") == "crypto_evp"

    def test_categorize_symbol_rsa(self):
        """Test RSA symbol categorization."""
        assert self.matcher.categorize_symbol("RSA_public_encrypt") == "crypto_rsa"

    def test_categorize_symbol_ec(self):
        """Test EC symbol categorization."""
        assert self.matcher.categorize_symbol("EC_KEY_new") == "crypto_ec"
        assert self.matcher.categorize_symbol("ECDSA_sign") == "crypto_ec"

    def test_categorize_symbol_hash(self):
        """Test hash symbol categorization."""
        assert self.matcher.categorize_symbol("SHA256_Init") == "crypto_hash"
        assert self.matcher.categorize_symbol("MD5_Init") == "crypto_hash"

    def test_categorize_symbol_sm(self):
        """Test SM symbol categorization."""
        assert self.matcher.categorize_symbol("SM2_sign") == "crypto_sm"
        assert self.matcher.categorize_symbol("SM3_Init") == "crypto_sm"
        assert self.matcher.categorize_symbol("SM4_encrypt") == "crypto_sm"

    def test_filter_openssl_symbols(self):
        """Test filtering of symbol list."""
        symbols = [
            "SSL_connect",
            "printf",
            "EVP_sha256",
            "malloc",
            "RSA_sign",
        ]
        filtered = self.matcher.filter_openssl_symbols(symbols)
        assert len(filtered) == 3
        assert "SSL_connect" in filtered
        assert "EVP_sha256" in filtered
        assert "RSA_sign" in filtered
        assert "printf" not in filtered
        assert "malloc" not in filtered

    def test_categorize_symbols(self):
        """Test bulk symbol categorization."""
        symbols = [
            "SSL_connect",
            "SSL_read",
            "EVP_sha256",
            "RSA_sign",
        ]
        result = self.matcher.categorize_symbols(symbols)

        assert "ssl_core" in result
        assert len(result["ssl_core"]) == 2
        assert "crypto_evp" in result
        assert len(result["crypto_evp"]) == 1
        assert "crypto_rsa" in result
        assert len(result["crypto_rsa"]) == 1

    def test_unloaded_matcher_raises(self):
        """Test that unloaded matcher raises RuntimeError on is_openssl_symbol."""
        empty_matcher = OpenSSLMatcher()
        with pytest.raises(RuntimeError):
            empty_matcher.is_openssl_symbol("SSL_connect")

    def test_unloaded_filter_returns_empty(self):
        """Test that filter_openssl_symbols returns empty list when not loaded."""
        empty_matcher = OpenSSLMatcher()
        result = empty_matcher.filter_openssl_symbols(["SSL_connect"])
        assert result == []

    def test_get_stats(self):
        """Test statistics reporting."""
        stats = self.matcher.get_stats()
        assert stats['symbols_loaded'] == len(self.matcher._openssl_exports)
        assert stats['libcrypto_path'] is None
        assert stats['libssl_path'] is None

    def test_get_all_exports(self):
        """Test getting all exports."""
        exports = self.matcher.get_all_exports()
        assert len(exports) == len(self.matcher._openssl_exports)
        assert "SSL_connect" in exports


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
