
import os
import tempfile
from openssl_scanner.static_detector import (
    detect_static_openssl,
    detect_static_ssl,
    score_openssl_fingerprint,
    FingerprintResult,
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


class TestFingerprintScoring:
    """Tests for score_openssl_fingerprint() function."""

    def _write_file(self, content):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            return f.name

    def _build_openssl_binary(self, strings):
        """Build fake binary with NUL-separated strings."""
        parts = []
        for s in strings:
            if isinstance(s, str):
                s = s.encode('ascii')
            parts.append(s)
        return b'\x00'.join(parts)

    def test_empty_file(self):
        path = self._write_file(b'')
        try:
            r = score_openssl_fingerprint(path)
            assert r.score == 0.0
            assert r.confidence == ''
        finally:
            os.unlink(path)

    def test_no_matches(self):
        path = self._write_file(b'\x00hello world\x00foo bar\x00')
        try:
            r = score_openssl_fingerprint(path)
            assert r.score == 0.0
            assert r.confidence == ''
            assert r.matched_count == 0
        finally:
            os.unlink(path)

    def test_high_confidence_openssl(self):
        """OpenSSL-style strings across all 7 categories should yield high confidence."""
        t1a = [
            "BIO routines", "Diffie-Hellman routines", "ECDH routines",
            "ECDSA routines", "HMAC routines", "OCSP routines",
            "PEM routines", "PKCS7 routines", "SSL routines",
            "UI routines", "X509 V3 routines", "bignum routines",
            "common libcrypto routines", "configuration file routines",
            "elliptic curve routines", "memory buffer routines",
            "object identifier routines",
            "asn1 encoding routines", "digital envelope routines",
            "dsa routines", "engine routines", "rsa routines",
            "x509 certificate routines",
        ]
        t1b = [
            "X509v3 Basic Constraints", "X509v3 Key Usage",
            "X509v3 Subject Key Identifier", "X509v3 Authority Key Identifier",
            "X509v3 Subject Alternative Name", "X509v3 Extended Key Usage",
            "X509v3 CRL Distribution Points", "X509v3 Certificate Policies",
            "X509v3 CRL Number", "X509v3 CRL Reason Code",
            "X509v3 Issuer Alternative Name", "X509v3 Name Constraints",
            "X509v3 Policy Constraints", "X509v3 Inhibit Any Policy",
            "X509v3 Delta CRL Indicator", "X509v3 Freshest CRL",
        ]
        t2a = [
            "prime256v1", "secp384r1", "secp521r1",
            "RSA-SHA256", "RSA-SHA384", "RSA-SHA512",
            "ecdsa-with-SHA256", "ecdsa-with-SHA384",
            "sha256WithRSAEncryption", "sha384WithRSAEncryption",
            "id-ecPublicKey", "rsaEncryption",
            "AES-256-CBC", "AES-128-CBC", "ChaCha20-Poly1305",
        ]
        t2b = [
            "basicConstraints", "subjectKeyIdentifier",
            "authorityKeyIdentifier", "keyUsage", "extendedKeyUsage",
            "subjectAltName", "TLS Web Server Authentication",
            "TLS Web Client Authentication", "OCSP Signing",
        ]
        t3a = [
            "ASN1_ANY", "ASN1_BIT_STRING", "ASN1_BOOLEAN",
            "ASN1_ENUMERATED", "ASN1_FBOOLEAN", "ASN1_GENERALIZEDTIME",
            "ASN1_IA5STRING", "ASN1_INTEGER", "ASN1_NULL",
            "ASN1_OBJECT", "ASN1_OCTET_STRING", "ASN1_PRINTABLE",
            "ASN1_SEQUENCE", "ASN1_TIME", "ASN1_UTF8STRING",
        ]
        t3b = [
            "certificate chain too long", "certificate has expired",
            "certificate is not yet valid", "certificate not trusted",
            "certificate rejected", "unable to verify the first certificate",
        ]
        t4a = [
            "crypto/asn1/tasn_dec.c", "crypto/asn1/tasn_enc.c",
            "crypto/pem/pem_lib.c", "crypto/stack/stack.c",
            "crypto/x509/by_dir.c",
        ]
        t4b = [
            "sslv3 alert handshake failure", "sslv3 alert bad certificate",
            "sslv3 alert certificate expired", "sslv3 alert unexpected message",
            "tlsv1 alert unknown ca", "tlsv1 alert protocol version",
            "tlsv1 alert internal error", "tlsv1 alert insufficient security",
            "tlsv13 alert certificate required", "tlsv13 alert missing extension",
            "ssl handshake failure", "no shared cipher",
            "wrong version number", "inappropriate fallback",
        ]
        all_strings = t1a + t1b + t2a + t2b + t3a + t3b + t4a + t4b
        content = self._build_openssl_binary(all_strings)
        path = self._write_file(content)
        try:
            r = score_openssl_fingerprint(path)
            assert r.confidence == 'high', \
                f"Expected high, got {r.confidence} (score={r.score})"
            assert r.score >= 60
            assert len(r.category_scores) == 8
            assert 'T1A_err_lib' in r.category_scores
            assert 'T1B_x509v3_ext' in r.category_scores
            assert 'T2A_oid_names' in r.category_scores
            assert 'T4B_protocol_errs_openssl' in r.category_scores
            assert r.library == 'OpenSSL'
        finally:
            os.unlink(path)

    def test_high_confidence_boringssl(self):
        """BoringSSL-variant strings should also yield high confidence."""
        t1a = [
            "BIO routines", "Diffie-Hellman routines", "ECDH routines",
            "ECDSA routines", "HMAC routines", "OCSP routines",
            "PEM routines", "PKCS7 routines", "SSL routines",
            "UI routines", "X509 V3 routines", "bignum routines",
            "common libcrypto routines", "configuration file routines",
            "elliptic curve routines", "memory buffer routines",
            "object identifier routines",
            "ASN.1 encoding routines", "COMP routines", "ENGINE routines",
            "PKCS8 routines", "RSA routines", "X.509 certificate routines",
            "public key routines",
        ]
        t1b = [
            "X509v3 Basic Constraints", "X509v3 Key Usage",
            "X509v3 Subject Key Identifier", "X509v3 Authority Key Identifier",
            "X509v3 Subject Alternative Name", "X509v3 Extended Key Usage",
            "X509v3 CRL Distribution Points", "X509v3 Certificate Policies",
            "X509v3 CRL Number", "X509v3 CRL Reason Code",
            "X509v3 Issuer Alternative Name", "X509v3 Name Constraints",
            "X509v3 Policy Constraints", "X509v3 Inhibit Any Policy",
            "X509v3 Delta CRL Indicator", "X509v3 Freshest CRL",
        ]
        t2a = [
            "prime256v1", "secp384r1", "secp521r1", "secp256k1",
            "RSA-SHA256", "RSA-SHA384", "RSA-SHA512", "RSA-SHA1",
            "ecdsa-with-SHA256", "ecdsa-with-SHA384", "ecdsa-with-SHA512",
            "sha256WithRSAEncryption", "sha384WithRSAEncryption",
            "sha512WithRSAEncryption", "id-ecPublicKey", "rsaEncryption",
            "id-aes256-GCM", "id-aes128-GCM", "id-aes256-wrap", "id-aes128-wrap",
            "hmacWithSHA256", "hmacWithSHA384", "hmacWithSHA512",
            "AES-256-CBC", "AES-128-CBC", "AES-256-CTR", "AES-128-CTR",
            "ChaCha20-Poly1305", "pkcs7-data", "pkcs7-signedData",
            "pkcs7-envelopedData",
        ]
        t3a = [
            "ASN1_ANY", "ASN1_BIT_STRING", "ASN1_BOOLEAN",
            "ASN1_ENUMERATED", "ASN1_FBOOLEAN", "ASN1_GENERALIZEDTIME",
            "ASN1_IA5STRING", "ASN1_INTEGER", "ASN1_NULL",
            "ASN1_OBJECT", "ASN1_OCTET_STRING", "ASN1_PRINTABLE",
            "ASN1_SEQUENCE", "ASN1_TIME", "ASN1_UTF8STRING",
        ]
        t3b = [
            "certificate chain too long", "certificate has expired",
            "certificate is not yet valid", "certificate not trusted",
            "certificate rejected", "unable to verify the first certificate",
            "unable to get local issuer certificate",
            "unable to decode issuer public key",
            "self signed certificate",
        ]
        t4a_boring = [
            "../../flutter/third_party/boringssl/src/crypto/asn1/tasn_dec.c",
            "../../flutter/third_party/boringssl/src/crypto/asn1/tasn_enc.c",
            "../../flutter/third_party/boringssl/src/crypto/pem/pem_lib.c",
            "../../flutter/third_party/boringssl/src/crypto/stack/stack.c",
            "../../flutter/third_party/boringssl/src/crypto/x509/by_dir.c",
        ]
        t4b_boring = [
            "SSLV3_ALERT_BAD_CERTIFICATE", "SSLV3_ALERT_CERTIFICATE_EXPIRED",
            "SSLV3_ALERT_CERTIFICATE_REVOKED", "SSLV3_ALERT_HANDSHAKE_FAILURE",
            "SSLV3_ALERT_ILLEGAL_PARAMETER", "SSLV3_ALERT_UNEXPECTED_MESSAGE",
            "TLSV1_ALERT_UNKNOWN_CA", "TLSV1_ALERT_PROTOCOL_VERSION",
            "TLSV1_ALERT_INTERNAL_ERROR", "TLSV1_ALERT_INSUFFICIENT_SECURITY",
            "TLSV1_ALERT_CERTIFICATE_REQUIRED",
            "SSL_HANDSHAKE_FAILURE", "NO_SHARED_CIPHER",
            "WRONG_VERSION_NUMBER", "INAPPROPRIATE_FALLBACK",
            "BAD_CHANGE_CIPHER_SPEC",
        ]
        all_strings = t1a + t1b + t2a + t3a + t3b + t4a_boring + t4b_boring
        content = self._build_openssl_binary(all_strings)
        path = self._write_file(content)
        try:
            r = score_openssl_fingerprint(path)
            assert r.confidence == 'high', \
                f"Expected high, got {r.confidence} (score={r.score})"
            assert r.score >= 60
            assert 'T4A_src_paths' in r.category_scores, \
                "BoringSSL-prefixed paths should match via substring"
            assert 'T4B_protocol_errs_boringssl' in r.category_scores, \
                "BoringSSL UPPERCASE protocol alerts should match"
            assert r.library == 'BoringSSL', \
                f"Expected BoringSSL, got {r.library}"
        finally:
            os.unlink(path)

    def test_medium_confidence(self):
        """Moderate coverage across 5 categories yields medium."""
        t1a = [
            "BIO routines", "SSL routines", "PEM routines",
            "OCSP routines", "HMAC routines", "PKCS7 routines",
            "UI routines", "X509 V3 routines",
            "bignum routines", "common libcrypto routines",
            "elliptic curve routines", "memory buffer routines",
            "object identifier routines",
        ]
        t1b = [
            "X509v3 Basic Constraints", "X509v3 Key Usage",
            "X509v3 Subject Key Identifier", "X509v3 Authority Key Identifier",
            "X509v3 Subject Alternative Name", "X509v3 Extended Key Usage",
        ]
        t2a = [
            "prime256v1", "secp384r1", "RSA-SHA256",
            "ecdsa-with-SHA256", "sha256WithRSAEncryption",
            "id-ecPublicKey", "rsaEncryption",
            "AES-256-CBC", "AES-128-CBC", "ChaCha20-Poly1305",
        ]
        t2b = [
            "basicConstraints", "subjectKeyIdentifier",
            "authorityKeyIdentifier", "keyUsage", "extendedKeyUsage",
        ]
        t3a = [
            "ASN1_INTEGER", "ASN1_OBJECT", "ASN1_BOOLEAN",
            "ASN1_OCTET_STRING", "ASN1_NULL", "ASN1_TIME",
            "ASN1_SEQUENCE",
        ]
        all_strings = t1a + t1b + t2a + t2b + t3a
        content = self._build_openssl_binary(all_strings)
        path = self._write_file(content)
        try:
            r = score_openssl_fingerprint(path)
            assert r.confidence == 'medium', \
                f"Expected medium, got {r.confidence} (score={r.score})"
            assert r.score >= 30
        finally:
            os.unlink(path)

    def test_low_confidence(self):
        """Sparse coverage across a few categories yields low confidence."""
        strings = [
            "BIO routines", "SSL routines", "PEM routines",
            "OCSP routines", "HMAC routines",
            "PKCS7 routines", "bignum routines",
            "common libcrypto routines", "elliptic curve routines",
            "memory buffer routines", "object identifier routines",
            "prime256v1", "secp384r1", "RSA-SHA256",
            "ecdsa-with-SHA256", "sha256WithRSAEncryption",
            "id-ecPublicKey",
            "ASN1_INTEGER", "ASN1_OBJECT", "ASN1_BOOLEAN",
            "ASN1_NULL", "ASN1_TIME",
        ]
        content = self._build_openssl_binary(strings)
        path = self._write_file(content)
        try:
            r = score_openssl_fingerprint(path)
            assert r.confidence == 'low', \
                f"Expected low, got {r.confidence} (score={r.score})"
            assert r.score >= 15
        finally:
            os.unlink(path)

    def test_below_threshold(self):
        """Very few matches should yield no confidence."""
        strings = ["ASN1_INTEGER", "ASN1_OBJECT", "BIO routines"]
        content = self._build_openssl_binary(strings)
        path = self._write_file(content)
        try:
            r = score_openssl_fingerprint(path)
            assert r.confidence == '', \
                f"Expected none, got {r.confidence} (score={r.score})"
            assert r.score < 15
        finally:
            os.unlink(path)

    def test_category_cap(self):
        """Per-category cap prevents single category from dominating."""
        all_err = [
            "BIO routines", "Diffie-Hellman routines", "ECDH routines",
            "ECDSA routines", "HMAC routines", "OCSP routines",
            "PEM routines", "PKCS7 routines", "SSL routines",
            "UI routines", "X509 V3 routines", "bignum routines",
            "common libcrypto routines", "configuration file routines",
            "elliptic curve routines", "memory buffer routines",
            "object identifier routines",
            "ASN.1 encoding routines", "COMP routines", "ENGINE routines",
            "PKCS8 routines", "RSA routines", "X.509 certificate routines",
            "public key routines",
            "asn1 encoding routines", "digital envelope routines",
            "dsa routines", "engine routines", "rsa routines",
            "x509 certificate routines",
        ]
        content = self._build_openssl_binary(all_err)
        path = self._write_file(content)
        try:
            r = score_openssl_fingerprint(path)
            t1a = r.category_scores.get('T1A_err_lib', {})
            assert t1a.get('capped', 0) <= 20, \
                f"T1A_err_lib exceeded cap: {t1a}"
            assert t1a.get('raw', 0) > 20, \
                f"Expected raw > cap, got {t1a}"
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        r = score_openssl_fingerprint('/nonexistent/file.so')
        assert r.score == 0.0
        assert r.confidence == ''

    def test_result_dataclass_fields(self):
        r = FingerprintResult()
        assert r.score == 0.0
        assert r.confidence == ''
        assert r.category_scores == {}
        assert r.matched_count == 0
        assert r.total_candidates == 0

    def test_boringssl_unique_errs_category(self):
        """T5A BoringSSL-unique errors contribute to library inference."""
        base = [
            "BIO routines", "SSL routines", "PEM routines",
            "OCSP routines", "HMAC routines", "PKCS7 routines",
            "UI routines", "X509 V3 routines", "bignum routines",
            "common libcrypto routines", "elliptic curve routines",
            "memory buffer routines", "object identifier routines",
            "X509v3 Basic Constraints", "X509v3 Key Usage",
            "X509v3 Subject Key Identifier", "X509v3 Authority Key Identifier",
            "X509v3 Subject Alternative Name", "X509v3 Extended Key Usage",
            "prime256v1", "secp384r1", "RSA-SHA256",
            "ecdsa-with-SHA256", "sha256WithRSAEncryption",
            "id-ecPublicKey", "rsaEncryption",
            "AES-256-CBC", "AES-128-CBC", "ChaCha20-Poly1305",
            "basicConstraints", "subjectKeyIdentifier",
            "authorityKeyIdentifier", "keyUsage", "extendedKeyUsage",
            "ASN1_INTEGER", "ASN1_OBJECT", "ASN1_BOOLEAN",
            "ASN1_OCTET_STRING", "ASN1_NULL", "ASN1_TIME",
            "ASN1_SEQUENCE",
        ]
        boring_unique = [
            "ECH_REJECTED", "CHANNEL_ID_NOT_P256",
            "ALPS_MISMATCH_ON_EARLY_DATA",
        ]
        content = self._build_openssl_binary(base + boring_unique)
        path = self._write_file(content)
        try:
            r = score_openssl_fingerprint(path)
            assert r.confidence in ('medium', 'high'), \
                f"Expected medium+, got {r.confidence} (score={r.score})"
            assert 'T5A_boringssl_unique_errs' in r.category_scores
            assert r.library == 'BoringSSL', \
                f"Expected BoringSSL from T5A, got {r.library}"
        finally:
            os.unlink(path)

    def test_library_inference_shared_only(self):
        """Shared-only categories default library to OpenSSL."""
        strings = [
            "BIO routines", "SSL routines", "PEM routines",
            "OCSP routines", "HMAC routines",
            "PKCS7 routines", "bignum routines",
            "common libcrypto routines", "elliptic curve routines",
            "memory buffer routines", "object identifier routines",
            "prime256v1", "secp384r1", "RSA-SHA256",
            "ecdsa-with-SHA256", "sha256WithRSAEncryption",
            "id-ecPublicKey",
            "ASN1_INTEGER", "ASN1_OBJECT", "ASN1_BOOLEAN",
            "ASN1_NULL", "ASN1_TIME",
        ]
        content = self._build_openssl_binary(strings)
        path = self._write_file(content)
        try:
            r = score_openssl_fingerprint(path)
            assert r.confidence == 'low'
            assert r.library == 'OpenSSL', \
                "Shared-only categories should default to OpenSSL"
        finally:
            os.unlink(path)

    def test_library_tag_in_category_scores(self):
        """Library-tagged categories carry 'library' key in category_scores."""
        strings = [
            "BIO routines", "SSL routines", "PEM routines",
            "OCSP routines", "HMAC routines", "PKCS7 routines",
            "UI routines", "X509 V3 routines", "bignum routines",
            "common libcrypto routines", "elliptic curve routines",
            "memory buffer routines", "object identifier routines",
            "SSLV3_ALERT_BAD_CERTIFICATE", "SSLV3_ALERT_HANDSHAKE_FAILURE",
            "TLSV1_ALERT_UNKNOWN_CA", "SSL_HANDSHAKE_FAILURE",
        ]
        content = self._build_openssl_binary(strings)
        path = self._write_file(content)
        try:
            r = score_openssl_fingerprint(path)
            t4b_b = r.category_scores.get('T4B_protocol_errs_boringssl', {})
            assert t4b_b.get('library') == 'BoringSSL'
            t1a = r.category_scores.get('T1A_err_lib', {})
            assert 'library' not in t1a, \
                "Shared categories should not have library tag"
        finally:
            os.unlink(path)

    def test_no_false_positive_openhitls(self):
        """Generic TLS strings should NOT trigger OpenSSL fingerprint."""
        non_ossl = [
            "TLS handshake failed",
            "certificate verify failed",
            "connection reset by peer",
            "SSL_ERROR_SYSCALL",
        ]
        content = self._build_openssl_binary(non_ossl)
        path = self._write_file(content)
        try:
            r = score_openssl_fingerprint(path)
            assert r.confidence == '', \
                f"False positive: {r.confidence} (score={r.score})"
        finally:
            os.unlink(path)
