"""Tests for source code analyzer (tree-sitter AST-based)."""

import os
import tempfile

import pytest

tree_sitter = pytest.importorskip("tree_sitter")

from openssl_scanner.source_analyzer import (
    CallSite,
    SourceAnalyzer,
    SourceScanResult,
    _categorize_symbol,
    _scan_file_ast,
)
from openssl_scanner.constants import SYMBOL_CATEGORIES

OSSL_SYMBOLS = {
    "SSL_new", "SSL_free", "SSL_connect", "SSL_read", "SSL_write",
    "SSL_CTX_new", "SSL_CTX_free",
    "EVP_DigestInit_ex", "EVP_DigestUpdate", "EVP_DigestFinal_ex",
    "EVP_MD_CTX_new", "EVP_MD_CTX_free", "EVP_sha256",
    "ERR_print_errors_fp",
    "BN_new", "BN_free",
    "X509_new", "X509_free",
}


def _write_temp(content: str, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content.encode('utf-8'))
    os.close(fd)
    return path


class TestCDirectCall:
    def test_single_call_in_function(self):
        src = 'int main() { SSL_connect(ssl); }'
        path = _write_temp(src, '.c')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 1
            assert sites[0].ossl_symbol == "SSL_connect"
            assert sites[0].caller_function == "main"
            assert sites[0].line_number == 1
            assert sites[0].language == "c"
        finally:
            os.unlink(path)

    def test_non_openssl_call_filtered(self):
        src = 'int main() { printf("hello"); }'
        path = _write_temp(src, '.c')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 0
        finally:
            os.unlink(path)

    def test_multiple_calls_in_function(self):
        src = '''void do_tls(SSL_CTX *ctx) {
    SSL *ssl = SSL_new(ctx);
    SSL_connect(ssl);
    SSL_free(ssl);
}
'''
        path = _write_temp(src, '.c')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 3
            symbols = [s.ossl_symbol for s in sites]
            assert "SSL_new" in symbols
            assert "SSL_connect" in symbols
            assert "SSL_free" in symbols
            for s in sites:
                assert s.caller_function == "do_tls"
        finally:
            os.unlink(path)

    def test_multiline_args(self):
        src = '''void f() {
    EVP_DigestInit_ex(
        ctx,
        EVP_sha256(),
        NULL
    );
}
'''
        path = _write_temp(src, '.c')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            digest_sites = [s for s in sites if s.ossl_symbol == "EVP_DigestInit_ex"]
            assert len(digest_sites) == 1
            assert "ctx" in digest_sites[0].call_args
            assert "NULL" in digest_sites[0].call_args
            assert "\n" not in digest_sites[0].call_args
        finally:
            os.unlink(path)

    def test_file_scope_call(self):
        src = 'SSL_CTX *ctx = SSL_CTX_new(NULL);'
        path = _write_temp(src, '.c')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 1
            assert sites[0].caller_function == "<file_scope>"
        finally:
            os.unlink(path)

    def test_category_assignment(self):
        src = 'void f() { SSL_connect(ssl); }'
        path = _write_temp(src, '.c')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 1
            assert sites[0].category == "ssl_core"
        finally:
            os.unlink(path)


class TestCppCall:
    def test_cpp_extension(self):
        src = 'void f() { SSL_connect(ssl); }'
        path = _write_temp(src, '.cpp')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 1
            assert sites[0].ossl_symbol == "SSL_connect"
            assert sites[0].language == "cpp"
        finally:
            os.unlink(path)


class TestRustDirectCall:
    def test_direct_call(self):
        src = '''fn do_tls() {
    unsafe { SSL_connect(ssl); }
}
'''
        path = _write_temp(src, '.rs')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 1
            assert sites[0].ossl_symbol == "SSL_connect"
            assert sites[0].caller_function == "do_tls"
            assert sites[0].language == "rust"
        finally:
            os.unlink(path)


class TestRustScopedCall:
    def test_scoped_call(self):
        src = '''fn do_tls() {
    unsafe { openssl_sys::SSL_connect(ssl); }
}
'''
        path = _write_temp(src, '.rs')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 1
            assert sites[0].ossl_symbol == "SSL_connect"
            assert sites[0].caller_function == "do_tls"
        finally:
            os.unlink(path)

    def test_deep_scoped_call(self):
        src = '''fn f() {
    unsafe { openssl_sys::ffi::EVP_sha256(); }
}
'''
        path = _write_temp(src, '.rs')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 1
            assert sites[0].ossl_symbol == "EVP_sha256"
        finally:
            os.unlink(path)


class TestEdgeCases:
    def test_empty_file(self):
        path = _write_temp('', '.c')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 0
        finally:
            os.unlink(path)

    def test_binary_file(self):
        fd, path = tempfile.mkstemp(suffix='.c')
        os.write(fd, b'\x00\x01\x02\xff\xfe\xfd')
        os.close(fd)
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 0
        finally:
            os.unlink(path)

    def test_unsupported_extension(self):
        path = _write_temp('SSL_connect(ssl);', '.py')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 0
        finally:
            os.unlink(path)


class TestDirectoryScan:
    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            c_file = os.path.join(tmpdir, 'test.c')
            with open(c_file, 'w') as f:
                f.write('void f() { SSL_connect(ssl); EVP_sha256(); }')

            rs_file = os.path.join(tmpdir, 'test.rs')
            with open(rs_file, 'w') as f:
                f.write('fn g() { unsafe { BN_new(); } }')

            txt_file = os.path.join(tmpdir, 'readme.txt')
            with open(txt_file, 'w') as f:
                f.write('not a source file')

            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            result = analyzer.scan_directory(tmpdir, workers=1)

            assert isinstance(result, SourceScanResult)
            assert result.total_files_scanned == 2
            assert result.files_with_calls == 2
            assert result.total_call_sites == 3

    def test_scan_directory_no_recursive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            c_file = os.path.join(tmpdir, 'top.c')
            with open(c_file, 'w') as f:
                f.write('void f() { SSL_connect(ssl); }')

            subdir = os.path.join(tmpdir, 'sub')
            os.makedirs(subdir)
            sub_file = os.path.join(subdir, 'deep.c')
            with open(sub_file, 'w') as f:
                f.write('void g() { SSL_free(ssl); }')

            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            result = analyzer.scan_directory(tmpdir, recursive=False, workers=1)
            assert result.total_files_scanned == 1
            assert result.total_call_sites == 1


class TestDlsymSourceDetection:

    def test_dlsym_openssl_symbol(self):
        """dlsym(handle, "SSL_CTX_new") should be detected."""
        code = '''
void load_ssl(void *handle) {
    void *fn = dlsym(handle, "SSL_CTX_new");
}
'''
        path = _write_temp(code, '.c')
        try:
            sites, err = _scan_file_ast(path, 'c', OSSL_SYMBOLS,
                                         SYMBOL_CATEGORIES)
            assert err is None
            assert len(sites) == 1
            assert sites[0].ossl_symbol == 'SSL_CTX_new'
            assert sites[0].detection_method == 'dlsym'
            assert 'dlsym' in sites[0].call_args
        finally:
            os.unlink(path)

    def test_dlsym_non_openssl_filtered(self):
        """dlsym(handle, "printf") should not be reported."""
        code = '''
void load_lib(void *handle) {
    void *fn = dlsym(handle, "printf");
}
'''
        path = _write_temp(code, '.c')
        try:
            sites, err = _scan_file_ast(path, 'c', OSSL_SYMBOLS,
                                         SYMBOL_CATEGORIES)
            assert err is None
            assert len(sites) == 0
        finally:
            os.unlink(path)

    def test_dlsym_detection_method_field(self):
        """detection_method should be "dlsym" for dlsym calls."""
        code = '''
void init(void *h) {
    void *f1 = dlsym(h, "EVP_sha256");
}
'''
        path = _write_temp(code, '.c')
        try:
            sites, err = _scan_file_ast(path, 'c', OSSL_SYMBOLS,
                                         SYMBOL_CATEGORIES)
            assert len(sites) == 1
            assert sites[0].detection_method == 'dlsym'
        finally:
            os.unlink(path)

    def test_dlsym_category_assigned(self):
        """Correct category should be assigned for dlsym-detected symbols."""
        code = '''
void init(void *h) {
    dlsym(h, "EVP_DigestInit_ex");
}
'''
        path = _write_temp(code, '.c')
        try:
            sites, err = _scan_file_ast(path, 'c', OSSL_SYMBOLS,
                                         SYMBOL_CATEGORIES)
            assert len(sites) == 1
            assert sites[0].category == 'crypto_evp'
        finally:
            os.unlink(path)

    def test_mixed_direct_and_dlsym(self):
        """Both direct calls and dlsym calls in one file."""
        code = '''
void setup(void *h) {
    SSL_CTX_new(TLS_method());
    void *fn = dlsym(h, "EVP_sha256");
}
'''
        path = _write_temp(code, '.c')
        try:
            sites, err = _scan_file_ast(path, 'c', OSSL_SYMBOLS,
                                         SYMBOL_CATEGORIES)
            assert len(sites) == 2
            direct = [s for s in sites if s.detection_method == 'direct']
            dlsym = [s for s in sites if s.detection_method == 'dlsym']
            assert len(direct) == 1
            assert len(dlsym) == 1
            assert direct[0].ossl_symbol == 'SSL_CTX_new'
            assert dlsym[0].ossl_symbol == 'EVP_sha256'
        finally:
            os.unlink(path)

    def test_multiple_dlsym_calls(self):
        """Multiple dlsym calls should all be detected."""
        code = '''
void init(void *h) {
    dlsym(h, "SSL_connect");
    dlsym(h, "SSL_read");
    dlsym(h, "SSL_write");
}
'''
        path = _write_temp(code, '.c')
        try:
            sites, err = _scan_file_ast(path, 'c', OSSL_SYMBOLS,
                                         SYMBOL_CATEGORIES)
            syms = {s.ossl_symbol for s in sites}
            assert 'SSL_connect' in syms
            assert 'SSL_read' in syms
            assert 'SSL_write' in syms
            assert all(s.detection_method == 'dlsym' for s in sites)
        finally:
            os.unlink(path)


class TestCategorizeSymbol:
    def test_ssl_core(self):
        assert _categorize_symbol("SSL_connect", SYMBOL_CATEGORIES) == "ssl_core"

    def test_crypto_evp(self):
        assert _categorize_symbol("EVP_DigestInit_ex", SYMBOL_CATEGORIES) == "crypto_evp"

    def test_crypto_bn(self):
        assert _categorize_symbol("BN_new", SYMBOL_CATEGORIES) == "crypto_bn"

    def test_other(self):
        assert _categorize_symbol("some_random_func", SYMBOL_CATEGORIES) == "other"
