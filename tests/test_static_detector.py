
import os
import tempfile
from openssl_scanner.static_detector import (
    detect_static_openssl,
    detect_static_ssl,
    StaticSSLResult,
)


class TestDetectStaticOpenssl:
    """Backward-compatible wrapper returning version string or None."""

    def test_strict_pattern(self):
        content = b"Some binary content... OpenSSL 1.1.1t  7 Feb 2023 ...more data"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            version = detect_static_openssl(path)
            assert version == "1.1.1t"
        finally:
            os.unlink(path)

    def test_strict_pattern_3x(self):
        content = b"\x00OpenSSL 3.4.0  22 Oct 2024\x00"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            assert detect_static_openssl(path) == "3.4.0"
        finally:
            os.unlink(path)

    def test_loose_pattern_with_evidence(self):
        content = (b"\x00OpenSSL 3.0.0\x00"
                   b"SSL_CTX_new\x00"
                   b"EVP_EncryptInit\x00"
                   b"SHA256_Update\x00")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            assert detect_static_openssl(path) == "3.0.0"
        finally:
            os.unlink(path)

    def test_loose_pattern_insufficient_evidence(self):
        content = b"This requires OpenSSL 1.1.1 to run."
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            assert detect_static_openssl(path) is None
        finally:
            os.unlink(path)

    def test_no_match(self):
        content = b"Just random data"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            assert detect_static_openssl(path) is None
        finally:
            os.unlink(path)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            assert detect_static_openssl(path) is None
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        assert detect_static_openssl("/tmp/no_such_file_xyz123") is None


class TestDetectStaticSSL:
    """Full detection with signal details."""

    def test_strict_openssl_with_date(self):
        content = b"\x00OpenSSL 1.1.1i  8 Dec 2020\x00more data\x00"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.library == 'OpenSSL'
            assert r.version == '1.1.1i'
            assert 'version_banner_strict' in r.signals
        finally:
            os.unlink(path)

    def test_strict_with_fvisibility(self):
        content = (b"\x00OpenSSL 3.4.0  22 Oct 2024\x00"
                   b"-fvisibility=hidden\x00"
                   b"OPENSSLDIR:\x00")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.fvisibility_hidden is True
            assert 'fvisibility_hidden' in r.signals
            assert 'openssldir' in r.signals
        finally:
            os.unlink(path)

    def test_boringssl_with_symbols(self):
        content = (b"BoringSSL\x00"
                   b"SSL_CTX_new\x00"
                   b"EVP_EncryptInit\x00"
                   b"SHA256_Update\x00")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.library == 'BoringSSL'
            assert r.version is None
            assert 'boringssl_banner' in r.signals
        finally:
            os.unlink(path)

    def test_boringssl_compat_string(self):
        content = (b"OpenSSL 1.1.1 (compatible; BoringSSL)\x00"
                   b"SSL_CTX_new\x00"
                   b"EVP_EncryptInit\x00"
                   b"ERR_get_error\x00")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.library == 'BoringSSL'
        finally:
            os.unlink(path)

    def test_boringssl_no_corroboration(self):
        content = b"BoringSSL\x00some other data\x00"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is False
        finally:
            os.unlink(path)

    def test_boringssl_with_fvisibility_only(self):
        content = b"BoringSSL\x00-fvisibility=hidden\x00"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.library == 'BoringSSL'
            assert r.fvisibility_hidden is True
        finally:
            os.unlink(path)

    def test_libressl(self):
        content = (b"LibreSSL 3.8.2\x00"
                   b"SSL_CTX_new\x00"
                   b"EVP_EncryptInit\x00"
                   b"X509_free\x00")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.library == 'LibreSSL'
            assert r.version == '3.8.2'
        finally:
            os.unlink(path)

    def test_libressl_no_corroboration(self):
        content = b"LibreSSL 3.8.2\x00unrelated data\x00"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is False
        finally:
            os.unlink(path)

    def test_loose_openssl_fvisibility_one_symbol(self):
        """Loose version + -fvisibility=hidden + 1 symbol is enough."""
        content = (b"OpenSSL 1.1.1\x00"
                   b"-fvisibility=hidden\x00"
                   b"SSL_CTX_new\x00")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.library == 'OpenSSL'
            assert r.version == '1.1.1'
            assert 'fvisibility_hidden' in r.signals
            assert 'version_banner_loose' in r.signals
        finally:
            os.unlink(path)

    def test_loose_openssl_openssldir_one_symbol(self):
        """Loose version + OPENSSLDIR + 1 symbol is enough."""
        content = (b"OpenSSL 3.0.0\x00"
                   b"OPENSSLDIR:\x00"
                   b"EVP_EncryptInit\x00")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert 'openssldir' in r.signals
        finally:
            os.unlink(path)

    def test_loose_openssl_no_evidence(self):
        """Loose version alone is not enough."""
        content = b"Uses OpenSSL 1.1.1 for TLS connections"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is False
        finally:
            os.unlink(path)

    def test_loose_openssl_fvisibility_but_no_symbols(self):
        """Loose version + -fvisibility=hidden but NO symbols: not enough."""
        content = (b"OpenSSL 1.1.1\x00"
                   b"-fvisibility=hidden\x00"
                   b"no relevant symbols here\x00")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is False
        finally:
            os.unlink(path)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is False
        finally:
            os.unlink(path)

    def test_enginesdir_signal(self):
        content = (b"OpenSSL 3.0.0\x00"
                   b"ENGINESDIR:\x00"
                   b"SSL_connect\x00")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert 'enginesdir' in r.signals
        finally:
            os.unlink(path)

    def test_version_suffix_handling(self):
        """Handle pre-release or distro-suffixed version strings."""
        content = b"\x00OpenSSL 1.1.1k-fips  25 Mar 2021\x00"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.version == '1.1.1k-fips'
        finally:
            os.unlink(path)


class TestReporterStaticVersion:
    """Test that reporter serializes static_openssl_version."""

    def test_file_result_to_dict_includes_version(self):
        from openssl_scanner.scanner import FileResult
        from openssl_scanner.reporter import Reporter

        fr = FileResult(
            path='/test/lib.so',
            file_type='shared_library',
            arch='aarch64',
            direct_deps=[],
            openssl_direct=True,
            openssl_transitive=False,
            openssl_libs=[],
            openssl_symbols=['SSL_CTX_new'],
            static_openssl=True,
            static_openssl_version='1.1.1i',
        )

        reporter = Reporter()
        d = reporter._file_result_to_dict(fr)
        assert d['static_openssl'] is True
        assert d['static_openssl_version'] == '1.1.1i'

    def test_file_result_to_dict_null_version(self):
        from openssl_scanner.scanner import FileResult
        from openssl_scanner.reporter import Reporter

        fr = FileResult(
            path='/test/lib.so',
            file_type='shared_library',
            arch='aarch64',
            direct_deps=[],
            openssl_direct=False,
            openssl_transitive=False,
            openssl_libs=[],
            openssl_symbols=[],
        )

        reporter = Reporter()
        d = reporter._file_result_to_dict(fr)
        assert d['static_openssl'] is False
        assert d['static_openssl_version'] is None


class TestCountCorroboratingFallback:
    """Verify _count_corroborating falls back gracefully when CORROBORATING_SYMBOLS is None."""

    def test_none_symbols_falls_back(self):
        from openssl_scanner import static_detector
        from openssl_scanner.static_detector import _count_corroborating, _FALLBACK_SYMBOLS

        orig_symbols = static_detector.CORROBORATING_SYMBOLS
        orig_loaded = static_detector._CORROBORATING_LOADED
        try:
            static_detector.CORROBORATING_SYMBOLS = None
            static_detector._CORROBORATING_LOADED = True

            data = b"\x00SSL_CTX_new\x00EVP_EncryptInit\x00SHA256_Update\x00random junk\x00"
            count, found = _count_corroborating(data)

            assert static_detector.CORROBORATING_SYMBOLS is _FALLBACK_SYMBOLS
            assert count == 3
            assert "SSL_CTX_new" in found
            assert "EVP_EncryptInit" in found
            assert "SHA256_Update" in found
        finally:
            static_detector.CORROBORATING_SYMBOLS = orig_symbols
            static_detector._CORROBORATING_LOADED = orig_loaded

    def test_no_matching_symbols(self):
        """Data with no OpenSSL symbols returns zero count."""
        from openssl_scanner.static_detector import _count_corroborating

        data = b"\x00printf\x00malloc\x00free\x00strncpy\x00"
        count, found = _count_corroborating(data)
        assert count == 0
        assert found == []

    def test_normal_load_path(self):
        """Normal case: _load_probe_symbols succeeds, symbols are populated."""
        from openssl_scanner import static_detector
        from openssl_scanner.static_detector import _count_corroborating

        orig_symbols = static_detector.CORROBORATING_SYMBOLS
        orig_loaded = static_detector._CORROBORATING_LOADED
        try:
            static_detector.CORROBORATING_SYMBOLS = None
            static_detector._CORROBORATING_LOADED = False

            data = b"\x00SSL_CTX_new\x00EVP_EncryptInit\x00SHA256_Update\x00"
            count, found = _count_corroborating(data)

            assert static_detector.CORROBORATING_SYMBOLS is not None
            assert len(static_detector.CORROBORATING_SYMBOLS) >= 10
            assert count >= 3
        finally:
            static_detector.CORROBORATING_SYMBOLS = orig_symbols
            static_detector._CORROBORATING_LOADED = orig_loaded


class TestBoringSSLUniqueErrors:
    """Verify BORINGSSL_UNIQUE_ERRORS contains genuine BoringSSL-only fingerprints.

    Channel ID and ALPS are Google-proprietary TLS extensions never implemented
    in OpenSSL, so they are reliable BoringSSL fingerprints.
    WRONG_SIGNATURE_TYPE was removed (also in OpenSSL as SSL_R_WRONG_SIGNATURE_TYPE).
    NO_COMMON_SIGNATURE_ALGORITHMS is kept (OpenSSL uses the different string
    NO_SUITABLE_SIGNATURE_ALGORITHM).
    """

    def _write_file(self, content):
        import tempfile
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_channel_id_strings_detect_boringssl(self):
        """Two TLS Channel ID strings trigger BoringSSL detection via unique_errors signal."""
        content = b"CHANNEL_ID_NOT_P256\x00CHANNEL_ID_SIGNATURE_INVALID\x00"
        path = self._write_file(content)
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.library == 'BoringSSL'
            assert 'boringssl_unique_errors' in r.signals
        finally:
            os.unlink(path)

    def test_alps_strings_detect_boringssl(self):
        """Two ALPS extension strings trigger BoringSSL detection."""
        content = b"ALPS_MISMATCH_ON_EARLY_DATA\x00INVALID_ALPS_CODEPOINT\x00"
        path = self._write_file(content)
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.library == 'BoringSSL'
            assert 'boringssl_unique_errors' in r.signals
        finally:
            os.unlink(path)

    def test_wrong_signature_type_plus_no_common_insufficient(self):
        """WRONG_SIGNATURE_TYPE is in OpenSSL (correctly excluded from our list).
        NO_COMMON_SIGNATURE_ALGORITHMS is BoringSSL-only (re-added to list).
        The combination yields only 1 unique-error match, below the >= 2 threshold."""
        content = b"WRONG_SIGNATURE_TYPE\x00NO_COMMON_SIGNATURE_ALGORITHMS\x00"
        path = self._write_file(content)
        try:
            r = detect_static_ssl(path)
            assert r.detected is False
        finally:
            os.unlink(path)

    def test_no_common_signature_algorithms_with_channel_id_detects_boringssl(self):
        """NO_COMMON_SIGNATURE_ALGORITHMS (BoringSSL-only) + CHANNEL_ID_NOT_P256 = 2 unique -> detected."""
        content = b"NO_COMMON_SIGNATURE_ALGORITHMS\x00CHANNEL_ID_NOT_P256\x00"
        path = self._write_file(content)
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.library == 'BoringSSL'
            assert 'boringssl_unique_errors' in r.signals
        finally:
            os.unlink(path)

    def test_new_unique_errors_detect_boringssl(self):
        """Three newly added unique errors trigger BoringSSL detection when two are present."""
        content = (
            b"NEGOTIATED_ALPS_WITHOUT_ALPN\x00"
            b"ECH_SERVER_WOULD_HAVE_NO_RETRY_CONFIGS\x00"
        )
        path = self._write_file(content)
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.library == 'BoringSSL'
        finally:
            os.unlink(path)

    def test_could_not_parse_hints_with_alps_detects_boringssl(self):
        """COULD_NOT_PARSE_HINTS + ALPS_MISMATCH_ON_EARLY_DATA = 2 unique -> detected."""
        content = b"COULD_NOT_PARSE_HINTS\x00ALPS_MISMATCH_ON_EARLY_DATA\x00"
        path = self._write_file(content)
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.library == 'BoringSSL'
        finally:
            os.unlink(path)

    def test_single_unique_error_insufficient(self):
        """One unique error string alone is below the >= 2 threshold."""
        content = b"CHANNEL_ID_NOT_P256\x00other_data\x00"
        path = self._write_file(content)
        try:
            r = detect_static_ssl(path)
            assert r.detected is False
        finally:
            os.unlink(path)

    def test_ech_with_channel_id_detect_boringssl(self):
        """ECH_REJECTED + CHANNEL_ID_NOT_P256 combination also triggers detection."""
        content = b"ECH_REJECTED\x00CHANNEL_ID_NOT_P256\x00"
        path = self._write_file(content)
        try:
            r = detect_static_ssl(path)
            assert r.detected is True
            assert r.library == 'BoringSSL'
        finally:
            os.unlink(path)
