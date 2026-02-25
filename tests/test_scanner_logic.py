
import pytest
from unittest.mock import MagicMock
import sys
import os

# Adjust path to import src
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openssl_scanner.scanner import Scanner, FileResult
from openssl_scanner.elf_analyzer import ELFInfo, Symbol

class TestScannerLogic:
    def setup_method(self):
        self.scanner = Scanner()
        self.scanner._analyzer = MagicMock()
        self.scanner._matcher = MagicMock()
        
        # Setup matcher to return exports
        self.scanner._matcher.get_openssl_exports.return_value = {
            'SSL_connect', 'EVP_sha256', 'RSA_sign'
        }
        self.scanner._matcher.filter_openssl_symbols.side_effect = lambda syms: [
            s for s in syms if s in {'SSL_connect', 'EVP_sha256', 'RSA_sign'}
        ]
        self.scanner._matcher.is_openssl_library.side_effect = lambda l: '.so' in l and ('crypto' in l or 'ssl' in l)

    def test_static_openssl_hybrid_case(self):
        """
        Test that a file with both OpenSSL imports (UND) and definitions (DEF)
        is flagged as static_openssl if it implements OpenSSL symbols.
        Regression test for Codex Finding 3.
        """
        # Mock ELFInfo
        info = MagicMock(spec=ELFInfo)
        info.elf_type = 'shared_library'
        info.arch = 'aarch64'
        info.needed_libs = ['libssl.so', 'libc.so']
        
        # UND symbols (Imports)
        info.undefined_symbols = [
            Symbol(name='SSL_connect', bind='GLOBAL', type_='FUNC', defined=False),
            Symbol(name='malloc', bind='GLOBAL', type_='FUNC', defined=False)
        ]
        
        # DEF symbols (Exports/Implementation)
        info.defined_symbols = [
            Symbol(name='EVP_sha256', bind='GLOBAL', type_='FUNC', defined=True),
            Symbol(name='my_func', bind='GLOBAL', type_='FUNC', defined=True)
        ]
        
        info.has_dlopen = False
        info.has_dlsym = False
        
        self.scanner._analyzer.analyze.return_value = info
        self.scanner._analyzer.is_elf_file.return_value = True
        
        # Mock os.path.isfile
        with pytest.MonkeyPatch.context() as m:
            m.setattr(os.path, 'isfile', lambda p: True)
            
            result = self.scanner.scan_file('/path/to/hybrid_lib.so')
            
            assert result.static_openssl is True
            assert 'EVP_sha256' in result.openssl_symbols
            assert 'SSL_connect' in result.openssl_symbols
            assert result.openssl_direct is True

    def test_static_openssl_pure_static_case(self):
        """Test pure static linking (no imports)."""
        info = MagicMock(spec=ELFInfo)
        info.elf_type = 'executable'
        info.arch = 'aarch64'
        info.needed_libs = ['libc.so']
        
        # UND symbols (No OpenSSL imports)
        info.undefined_symbols = [
            Symbol(name='malloc', bind='GLOBAL', type_='FUNC', defined=False)
        ]
        
        # DEF symbols (Exports)
        info.defined_symbols = [
            Symbol(name='RSA_sign', bind='GLOBAL', type_='FUNC', defined=True)
        ]
        
        info.has_dlopen = False
        info.has_dlsym = False
        
        self.scanner._analyzer.analyze.return_value = info
        
        with pytest.MonkeyPatch.context() as m:
            m.setattr(os.path, 'isfile', lambda p: True)
            
            result = self.scanner.scan_file('/path/to/static_app')
            
            assert result.static_openssl is True
            assert 'RSA_sign' in result.openssl_symbols
            assert 'malloc' not in result.openssl_symbols

    def test_dynamic_openssl_case(self):
        """Test standard dynamic linking (imports only)."""
        info = MagicMock(spec=ELFInfo)
        info.elf_type = 'executable'
        info.arch = 'aarch64'
        info.needed_libs = ['libssl.so', 'libcrypto.so']
        
        # UND symbols (Imports)
        info.undefined_symbols = [
            Symbol(name='SSL_connect', bind='GLOBAL', type_='FUNC', defined=False)
        ]
        
        # DEF symbols (No OpenSSL exports)
        info.defined_symbols = [
            Symbol(name='main', bind='GLOBAL', type_='FUNC', defined=True)
        ]
        
        info.has_dlopen = False
        info.has_dlsym = False
        
        self.scanner._analyzer.analyze.return_value = info
        
        with pytest.MonkeyPatch.context() as m:
            m.setattr(os.path, 'isfile', lambda p: True)
            
            result = self.scanner.scan_file('/path/to/dynamic_app')
            
            assert result.static_openssl is False
            assert 'SSL_connect' in result.openssl_symbols


class TestStaticConfidenceBoringSSL:
    """Tests for _compute_static_confidence with BoringSSL (version=None) results."""

    def _boringssl_result(self):
        from openssl_scanner.static_detector import StaticSSLResult
        return StaticSSLResult(
            detected=True, library='BoringSSL', version=None,
            signals=['boringssl_banner']
        )

    def _no_ssl_result(self):
        from openssl_scanner.static_detector import StaticSSLResult
        return StaticSSLResult()

    def test_boringssl_with_two_tier1_is_high(self):
        """BoringSSL detected (no version) + 2 tier1 symbols -> high confidence."""
        from openssl_scanner.scanner import _compute_static_confidence
        # SSL_CTX_new and SSL_connect are ssl_core (tier1)
        level, reason = _compute_static_confidence(
            {'SSL_CTX_new', 'SSL_connect'}, self._boringssl_result())
        assert level == 'high'
        assert 'BoringSSL' in reason

    def test_boringssl_with_five_tier1_is_high(self):
        """BoringSSL + 5 tier1 symbols: the t1 >= 5 path also produces high."""
        from openssl_scanner.scanner import _compute_static_confidence
        syms = {'SSL_CTX_new', 'SSL_connect', 'SSL_read', 'SSL_write', 'SSL_free'}
        level, reason = _compute_static_confidence(syms, self._boringssl_result())
        assert level == 'high'

    def test_boringssl_with_one_tier1_stays_medium(self):
        """BoringSSL detected + only 1 tier1 symbol stays at medium (not enough for high)."""
        from openssl_scanner.scanner import _compute_static_confidence
        level, reason = _compute_static_confidence(
            {'SSL_CTX_new'}, self._boringssl_result())
        assert level == 'medium'

    def test_boringssl_no_symbols_is_medium(self):
        """BoringSSL detected with no exported symbols -> medium."""
        from openssl_scanner.scanner import _compute_static_confidence
        level, reason = _compute_static_confidence(set(), self._boringssl_result())
        assert level == 'medium'

    def test_openssl_with_version_and_tier1_is_high(self):
        """OpenSSL version banner always produces high regardless of tier1 count."""
        from openssl_scanner.scanner import _compute_static_confidence
        from openssl_scanner.static_detector import StaticSSLResult
        ssl = StaticSSLResult(
            detected=True, library='OpenSSL', version='3.0.9',
            signals=['version_banner_strict']
        )
        level, reason = _compute_static_confidence({'AES_encrypt'}, ssl)
        assert level == 'high'
        assert '3.0.9' in reason


class TestConfidenceModelEdgeCases:
    """Tests for _compute_static_confidence edge cases (Tier 1 fix: T1-4)."""

    def _no_ssl_result(self):
        from openssl_scanner.static_detector import StaticSSLResult
        return StaticSSLResult()

    def test_zero_symbols_no_ssl_is_none(self):
        """No symbols + no ssl detection -> 'none'."""
        from openssl_scanner.scanner import _compute_static_confidence
        level, _ = _compute_static_confidence(set(), self._no_ssl_result())
        assert level == 'none'

    def test_one_tier3_symbol_no_ssl_is_none(self):
        """Single tier3 symbol (e.g., AES_encrypt) with no banner -> 'none'."""
        from openssl_scanner.scanner import _compute_static_confidence
        level, _ = _compute_static_confidence({'AES_encrypt'}, self._no_ssl_result())
        assert level == 'none'

    def test_two_tier3_symbols_no_ssl_is_none(self):
        """Two tier3 symbols with no ssl detection -> 'none', not 'low'."""
        from openssl_scanner.scanner import _compute_static_confidence
        level, _ = _compute_static_confidence({'SHA256_Update', 'AES_encrypt'}, self._no_ssl_result())
        assert level == 'none'

    def test_three_tier3_same_category_is_none(self):
        """Three tier3 symbols from one category -> 'none' via single_primitive path."""
        from openssl_scanner.scanner import _compute_static_confidence
        level, _ = _compute_static_confidence(
            {'SHA256_Update', 'SHA256_Final', 'SHA256_Init'}, self._no_ssl_result())
        assert level == 'none'


class TestDynamicLinkSuppression:
    """DT_NEEDED to libcrypto/libssl suppresses static detection false positives.

    When a binary dynamically links OpenSSL (DT_NEEDED libcrypto.so), a version
    banner in .rodata (e.g. from OPENSSL_VERSION_TEXT macro) should NOT trigger
    static_openssl=True.  The corroborating symbols found in .dynstr are dynamic
    imports, not evidence of static linking.
    """

    def _make_info(self, needed_libs, und_names, def_names):
        info = MagicMock(spec=ELFInfo)
        info.elf_type = 'shared_library'
        info.arch = 'aarch64'
        info.needed_libs = needed_libs
        info.undefined_symbols = [
            Symbol(name=n, bind='GLOBAL', type_='FUNC', defined=False)
            for n in und_names
        ]
        info.defined_symbols = [
            Symbol(name=n, bind='GLOBAL', type_='FUNC', defined=True)
            for n in def_names
        ]
        info.has_dlopen = False
        info.has_dlsym = False
        return info

    def _run(self, info, openssl_exports=None):
        """Call _build_file_result with a patched detect_static_ssl."""
        from openssl_scanner.scanner import _build_file_result
        if openssl_exports is None:
            openssl_exports = {
                'SSL_CTX_new', 'SSL_connect', 'EVP_DigestInit_ex',
                'EVP_sha256', 'RSA_sign', 'BIO_new_socket',
                'X509_free', 'ERR_get_error',
            }
        und = [s.name for s in info.undefined_symbols]
        ossl_syms = [s for s in und if s in openssl_exports]
        defs = [s.name for s in info.defined_symbols]
        ossl_def = [s for s in defs if s in openssl_exports]
        ossl_libs = [lib for lib in info.needed_libs
                     if 'crypto' in lib.lower() or 'ssl' in lib.lower()]
        return _build_file_result(
            '/tmp/test.so', info, ossl_syms, ossl_def,
            ossl_libs, openssl_exports)

    def test_dynamic_link_with_banner_not_static(self):
        """DT_NEEDED libcrypto.so + version banner -> static_openssl=False.

        Even if detect_static_ssl() finds a banner in .rodata, the presence
        of DT_NEEDED overrides it.
        """
        info = self._make_info(
            needed_libs=['libcrypto.so', 'libc.so'],
            und_names=['SSL_CTX_new', 'EVP_DigestInit_ex', 'malloc'],
            def_names=['my_app_func'],
        )
        with pytest.MonkeyPatch.context() as m:
            from openssl_scanner.static_detector import StaticSSLResult
            banner_result = StaticSSLResult(
                detected=True, library='OpenSSL', version='3.0.9',
                signals=['version_banner_strict', 'corroborating_symbols_5'],
            )
            m.setattr('openssl_scanner.scanner.detect_static_ssl',
                      lambda path: banner_result)
            result = self._run(info)
        assert result.static_openssl is False
        assert result.openssl_direct is True
        assert 'SSL_CTX_new' in result.openssl_symbols

    def test_dynamic_link_without_banner_not_static(self):
        """DT_NEEDED libssl.so, no banner -> static_openssl=False (baseline)."""
        info = self._make_info(
            needed_libs=['libssl.so', 'libcrypto.so', 'libc.so'],
            und_names=['SSL_connect', 'ERR_get_error'],
            def_names=['main'],
        )
        with pytest.MonkeyPatch.context() as m:
            from openssl_scanner.static_detector import StaticSSLResult
            m.setattr('openssl_scanner.scanner.detect_static_ssl',
                      lambda path: StaticSSLResult())
            result = self._run(info)
        assert result.static_openssl is False
        assert result.openssl_direct is True

    def test_pure_static_no_dt_needed_is_static(self):
        """No DT_NEEDED + banner -> static_openssl=True (legitimate static)."""
        info = self._make_info(
            needed_libs=['libc.so'],
            und_names=['malloc', 'free'],
            def_names=['SSL_CTX_new', 'EVP_sha256'],
        )
        with pytest.MonkeyPatch.context() as m:
            from openssl_scanner.static_detector import StaticSSLResult
            banner_result = StaticSSLResult(
                detected=True, library='OpenSSL', version='3.0.9',
                signals=['version_banner_strict'],
            )
            m.setattr('openssl_scanner.scanner.detect_static_ssl',
                      lambda path: banner_result)
            result = self._run(info)
        assert result.static_openssl is True
        assert result.static_openssl_version == '3.0.9'

    def test_hidden_static_no_dt_needed_no_exports(self):
        """No DT_NEEDED + banner + no OpenSSL exports -> hidden_static path."""
        info = self._make_info(
            needed_libs=['libc.so'],
            und_names=['malloc'],
            def_names=['my_func'],
        )
        with pytest.MonkeyPatch.context() as m:
            from openssl_scanner.static_detector import StaticSSLResult
            banner_result = StaticSSLResult(
                detected=True, library='BoringSSL', version=None,
                signals=['boringssl_banner', 'fvisibility_hidden'],
            )
            m.setattr('openssl_scanner.scanner.detect_static_ssl',
                      lambda path: banner_result)
            m.setattr('openssl_scanner.scanner.scan_hidden_static_symbols',
                      lambda path, exports: ['SSL_CTX_new', 'SSL_connect'])
            result = self._run(info)
        assert result.static_openssl is True
        assert result.openssl_direct is True

    def test_dt_needed_libcrypto_variant_patterns(self):
        """Various DT_NEEDED naming patterns all suppress static detection."""
        variants = [
            'libcrypto.so.3',
            'libssl.so.1.1',
            'libcrypto-ohos.so',
            'libssl_openssl_ohos.so',
        ]
        for lib in variants:
            info = self._make_info(
                needed_libs=[lib, 'libc.so'],
                und_names=['SSL_CTX_new'],
                def_names=['app_main'],
            )
            with pytest.MonkeyPatch.context() as m:
                from openssl_scanner.static_detector import StaticSSLResult
                m.setattr('openssl_scanner.scanner.detect_static_ssl',
                          lambda path: StaticSSLResult(
                              detected=True, library='OpenSSL', version='3.0.9',
                              signals=['version_banner_strict']))
                result = self._run(info)
            assert result.static_openssl is False, \
                f"DT_NEEDED {lib} should suppress static detection"
