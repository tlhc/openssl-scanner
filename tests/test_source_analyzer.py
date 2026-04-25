"""Tests for source code analyzer (tree-sitter AST-based)."""

import os
import tempfile

import pytest

import openssl_scanner.source_analyzer as source_analyzer
from openssl_scanner.constants import SYMBOL_CATEGORIES
from openssl_scanner.source_analyzer import (
    SourceAnalyzer,
    SourceScanResult,
    _categorize_symbol,
    _make_query_executor,
    _scan_file_ast,
    _walk_tree,
)

tree_sitter = pytest.importorskip("tree_sitter")

OSSL_SYMBOLS = {
    "SSL_new", "SSL_free", "SSL_connect", "SSL_read", "SSL_write",
    "SSL_CTX_new", "SSL_CTX_free",
    "EVP_DigestInit_ex", "EVP_DigestUpdate", "EVP_DigestFinal_ex",
    "EVP_MD_CTX_new", "EVP_MD_CTX_free", "EVP_sha256",
    "ERR_error_string", "ERR_print_errors_fp",
    "BN_new", "BN_free",
    "X509_new", "X509_free",
}


def _write_temp(content: str, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content.encode('utf-8'))
    os.close(fd)
    return path


def _write_temp_bytes(content: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content)
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

    def test_local_same_name_definition_not_reported(self):
        src = '''static int CMAC_Final(void *ctx) {
    return 0;
}

int wrapper(void *ctx) {
    return CMAC_Final(ctx);
}
'''
        path = _write_temp(src, '.cpp')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS | {"CMAC_Final"})
            sites = analyzer.scan_file(path)
            assert len(sites) == 0
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

    def test_local_same_name_definition_not_reported(self):
        src = '''fn EVP_sha256() -> i32 {
    0
}

fn do_tls() {
    EVP_sha256();
}
'''
        path = _write_temp(src, '.rs')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert len(sites) == 0
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

    def test_walk_tree_handles_deep_nesting_without_recursion_error(self):
        class FakeNode:
            def __init__(self, children=None):
                self.children = children or []

        root = FakeNode()
        current = root
        for _ in range(2000):
            child = FakeNode()
            current.children = [child]
            current = child

        walked = list(_walk_tree(root))
        assert len(walked) == 2001

    def test_parser_diagnostic_recovery_is_disabled_by_default(self):
        src = '''void f(void) {
    ERR_error_string(
#if OPENSSL_IS_BORINGSSL
        (uint32_t)
#else
        (unsigned long)
#endif
        code);
}
'''
        path = _write_temp(src, '.c')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS)
            sites = analyzer.scan_file(path)
            assert [site.ossl_symbol for site in sites] == []
        finally:
            os.unlink(path)

    def test_parser_diagnostic_recovery_finds_symbol_in_recovery_region(self):
        src = '''void f(void) {
    ERR_error_string(
#if OPENSSL_IS_BORINGSSL
        (uint32_t)
#else
        (unsigned long)
#endif
        code);
}
'''
        path = _write_temp(src, '.c')
        try:
            analyzer = SourceAnalyzer(OSSL_SYMBOLS, recover_parser_diagnostics=True)
            sites = analyzer.scan_file(path)
            assert len(sites) == 1
            assert sites[0].ossl_symbol == "ERR_error_string"
            assert sites[0].extraction_source == "parser-diagnostic-text"
            assert sites[0].confidence == "fallback"
            assert sites[0].parser_diagnostic_class == "preprocessor-fragment"
        finally:
            os.unlink(path)


class TestTreeSitterCompatibility:
    """Compatibility behavior for older tree-sitter APIs."""

    def test_make_query_executor_uses_querycursor_when_available(self, monkeypatch):
        class FakeCursor:
            def __init__(self, query):
                self.query = query

        monkeypatch.setattr(
            source_analyzer, "_get_query_cursor_class", lambda: FakeCursor
        )
        query = object()
        executor = _make_query_executor(query)
        assert isinstance(executor, FakeCursor)
        assert executor.query is query

    def test_make_query_executor_falls_back_to_query_object(self, monkeypatch):
        monkeypatch.setattr(
            source_analyzer, "_get_query_cursor_class", lambda: None
        )

        class FakeQuery:
            pass

        query = FakeQuery()
        executor = _make_query_executor(query)
        assert executor is query

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


class TestQueryCaching:
    def test_c_queries_reused_across_files(self, monkeypatch):
        code1 = 'void f(void *h) { SSL_connect(ssl); dlsym(h, "SSL_CTX_new"); }'
        code2 = 'void g(void *h) { SSL_free(ssl); dlsym(h, "SSL_read"); }'
        path1 = _write_temp(code1, '.c')
        path2 = _write_temp(code2, '.c')
        query_builds = 0
        original_query = tree_sitter.Query

        def counting_query(*args, **kwargs):
            nonlocal query_builds
            query_builds += 1
            return original_query(*args, **kwargs)

        monkeypatch.setattr(tree_sitter, 'Query', counting_query)
        if hasattr(source_analyzer, '_LANG_RUNTIME_CACHE'):
            source_analyzer._LANG_RUNTIME_CACHE.clear()

        try:
            sites1, err1 = _scan_file_ast(path1, 'c', OSSL_SYMBOLS,
                                          SYMBOL_CATEGORIES)
            sites2, err2 = _scan_file_ast(path2, 'c', OSSL_SYMBOLS,
                                          SYMBOL_CATEGORIES)
            assert err1 is None
            assert err2 is None
            assert len(sites1) == 1
            assert len(sites2) == 1
            assert query_builds == 1
        finally:
            os.unlink(path1)
            os.unlink(path2)


class TestNonUtf8TextSources:
    def test_non_utf8_comment_is_still_scanned(self):
        src = (
            b"/* Moritz R\xf6hrich */\n"
            b"int main(void) {\n"
            b"    SSL_free(ssl);\n"
            b"    return 0;\n"
            b"}\n"
        )
        path = _write_temp_bytes(src, '.c')
        try:
            sites, err = _scan_file_ast(path, 'c', OSSL_SYMBOLS,
                                        SYMBOL_CATEGORIES)
            assert err is None
            assert len(sites) == 1
            assert sites[0].ossl_symbol == 'SSL_free'
        finally:
            os.unlink(path)

    def test_generated_text_with_extended_bytes_is_not_rejected(self):
        src = (
            b"#define FLAGS \"abc\"\n"
            b"/* extended bytes: \xff\xa1\xfe */\n"
            b"void use_tls(void) {\n"
            b"    SSL_CTX_new(0);\n"
            b"}\n"
        )
        path = _write_temp_bytes(src, '.h')
        try:
            sites, err = _scan_file_ast(path, 'c', OSSL_SYMBOLS,
                                        SYMBOL_CATEGORIES)
            assert err is None
            assert len(sites) == 1
            assert sites[0].ossl_symbol == 'SSL_CTX_new'
        finally:
            os.unlink(path)

    def test_source_dlsym_string_is_not_reported(self):
        code = '''
void load_lib(void *handle) {
    void *fn = dlsym(handle, "SSL_CTX_new");
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

    def test_mixed_direct_and_dlsym_reports_only_direct_call(self):
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
            assert err is None
            assert [site.ossl_symbol for site in sites] == ['SSL_CTX_new']
        finally:
            os.unlink(path)


class TestLocalFunctionFiltering:
    def test_local_openssl_named_function_definition_is_not_reported(self):
        code = '''
int SSL_read(void *ssl, void *buf, int len) {
    return len;
}

void use_ssl(void *ssl) {
    SSL_write(ssl, "x", 1);
}
'''
        path = _write_temp(code, '.c')
        try:
            sites, err = _scan_file_ast(path, 'c', OSSL_SYMBOLS,
                                        SYMBOL_CATEGORIES)
            assert err is None
            assert [site.ossl_symbol for site in sites] == ['SSL_write']
        finally:
            os.unlink(path)

    def test_local_openssl_named_function_call_is_filtered(self):
        code = '''
int SSL_read(void *ssl, void *buf, int len) {
    return len;
}

void use_local(void *ssl) {
    SSL_read(ssl, 0, 0);
}
'''
        path = _write_temp(code, '.c')
        try:
            sites, err = _scan_file_ast(path, 'c', OSSL_SYMBOLS,
                                        SYMBOL_CATEGORIES)
            assert err is None
            assert sites == []
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
