"""Tests for source-probe command (OpenSSL directory discovery)."""

import os
import tempfile

import pytest

from openssl_scanner.__main__ import (
    _probe_phase1_rg,
    _probe_phase2_consolidate,
)


OSSL_SYMBOLS = {
    "SSL_new", "SSL_free", "SSL_connect", "SSL_read", "SSL_write",
    "SSL_CTX_new", "SSL_CTX_free",
    "EVP_DigestInit_ex", "EVP_DigestUpdate", "EVP_DigestFinal_ex",
    "EVP_MD_CTX_new", "EVP_MD_CTX_free", "EVP_sha256",
    "ERR_print_errors_fp",
    "BN_new", "BN_free",
    "X509_new", "X509_free",
}

SOURCE_EXTS = {'.c', '.h', '.cpp', '.hpp', '.cc', '.cxx', '.hxx', '.rs'}


def _make_tree(root, layout):
    """Create a directory tree with files.

    layout: dict mapping relative path to file content.
    Directories are created automatically.
    """
    for relpath, content in layout.items():
        fpath = os.path.join(root, relpath)
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        with open(fpath, 'w') as f:
            f.write(content)


class _LogCapture:
    """Minimal logger that captures messages."""
    def __init__(self):
        self.messages = []

    def debug(self, msg, *args):
        self.messages.append(('DEBUG', msg % args if args else msg))

    def info(self, msg, *args):
        self.messages.append(('INFO', msg % args if args else msg))

    def warning(self, msg, *args):
        self.messages.append(('WARNING', msg % args if args else msg))


class TestPhase2Consolidate:
    """Test subtree-fork consolidation algorithm.

    _probe_phase2_consolidate calls os.listdir on real paths, so we create
    actual directory trees in tempdir.
    """

    def _mkdirs(self, root, *relpaths):
        """Create directories under root."""
        for rp in relpaths:
            os.makedirs(os.path.join(root, rp), exist_ok=True)

    def test_single_project(self):
        """Single project with multiple subdirs -> project root."""
        with tempfile.TemporaryDirectory() as root:
            self._mkdirs(root, "curl/lib", "curl/src", "curl/tests")
            matched = {
                os.path.join(root, "curl/lib"),
                os.path.join(root, "curl/src"),
                os.path.join(root, "curl/tests"),
            }
            result = _probe_phase2_consolidate(root, matched)
            assert result == [os.path.join(root, "curl")]

    def test_two_independent_projects(self):
        """Two separate projects -> both reported."""
        with tempfile.TemporaryDirectory() as root:
            self._mkdirs(root, "curl/lib", "curl/src",
                         "nginx/src/http", "nginx/src/core")
            matched = {
                os.path.join(root, "curl/lib"),
                os.path.join(root, "curl/src"),
                os.path.join(root, "nginx/src/http"),
                os.path.join(root, "nginx/src/core"),
            }
            result = _probe_phase2_consolidate(root, matched)
            assert result == [os.path.join(root, "curl"),
                              os.path.join(root, "nginx/src")]

    def test_single_chain_drill_down(self):
        """Single-chain directory -> drill to deepest fork."""
        with tempfile.TemporaryDirectory() as root:
            self._mkdirs(root, "project/src/deep/core")
            matched = {os.path.join(root, "project/src/deep/core")}
            result = _probe_phase2_consolidate(root, matched)
            assert result == [os.path.join(root, "project/src/deep/core")]

    def test_direct_plus_child(self):
        """Direct match in parent + child subtree -> parent is boundary."""
        with tempfile.TemporaryDirectory() as root:
            self._mkdirs(root, "proj/lib")
            matched = {
                os.path.join(root, "proj"),
                os.path.join(root, "proj/lib"),
            }
            result = _probe_phase2_consolidate(root, matched)
            assert result == [os.path.join(root, "proj")]

    def test_empty_input(self):
        """No matched dirs -> empty result."""
        with tempfile.TemporaryDirectory() as root:
            result = _probe_phase2_consolidate(root, set())
            assert result == []

    def test_single_leaf(self):
        """Single leaf directory -> returned as-is."""
        with tempfile.TemporaryDirectory() as root:
            self._mkdirs(root, "proj/src")
            matched = {os.path.join(root, "proj/src")}
            result = _probe_phase2_consolidate(root, matched)
            assert result == [os.path.join(root, "proj/src")]

    def test_probe_root_always_recurses(self):
        """Probe root with matches should recurse into children."""
        with tempfile.TemporaryDirectory() as root:
            self._mkdirs(root, "a/src", "b/lib")
            matched = {
                os.path.join(root, "a/src"),
                os.path.join(root, "b/lib"),
            }
            result = _probe_phase2_consolidate(root, matched)
            assert os.path.join(root, "a/src") in result
            assert os.path.join(root, "b/lib") in result
            assert root not in result

    def test_deep_fork(self):
        """Fork happens deep in the tree."""
        with tempfile.TemporaryDirectory() as root:
            self._mkdirs(root, "proj/vendor/openssl/crypto",
                         "proj/vendor/openssl/ssl")
            matched = {
                os.path.join(root, "proj/vendor/openssl/crypto"),
                os.path.join(root, "proj/vendor/openssl/ssl"),
            }
            result = _probe_phase2_consolidate(root, matched)
            assert result == [os.path.join(root, "proj/vendor/openssl")]


class TestPhase1Rg:
    """Test rg-based phase 1 detection."""

    @pytest.fixture(autouse=True)
    def check_rg(self):
        from openssl_scanner._vendor.rg import get_rg_path
        rg = get_rg_path()
        if not rg:
            pytest.skip("rg not available")

    def test_detect_openssl_symbol(self):
        from openssl_scanner.__main__ import _probe_phase1_rg
        import logging
        logger = logging.getLogger("test_probe_rg")

        with tempfile.TemporaryDirectory() as root:
            _make_tree(root, {
                "proj/main.c": 'int main() { SSL_connect(ssl); }\n',
                "other/util.c": 'void f() { printf("hi"); }\n',
            })
            globs = ['*.c', '*.h', '*.cpp', '*.hpp', '*.cc', '*.cxx', '*.rs']
            result = _probe_phase1_rg(root, OSSL_SYMBOLS, globs, logger)
            assert result is not None
            matched, first, count, engine = result
            assert engine == 'rg'
            assert os.path.join(root, "proj") in matched
            assert os.path.join(root, "other") not in matched

    def test_no_false_positive(self):
        from openssl_scanner.__main__ import _probe_phase1_rg
        import logging
        logger = logging.getLogger("test_probe_rg")

        with tempfile.TemporaryDirectory() as root:
            _make_tree(root, {
                "proj/main.c": 'int main() { SSL_my_custom_func(); }\n',
            })
            globs = ['*.c', '*.h']
            result = _probe_phase1_rg(root, OSSL_SYMBOLS, globs, logger)
            assert result is not None
            matched, first, count, engine = result
            assert len(matched) == 0

    def test_multiple_projects(self):
        from openssl_scanner.__main__ import _probe_phase1_rg
        import logging
        logger = logging.getLogger("test_probe_rg")

        with tempfile.TemporaryDirectory() as root:
            _make_tree(root, {
                "a/tls.c": 'void f() { SSL_CTX_new(NULL); }\n',
                "b/hash.c": 'void g() { EVP_sha256(); }\n',
                "c/util.c": 'void h() { memcpy(a, b, n); }\n',
            })
            globs = ['*.c', '*.h', '*.cpp', '*.hpp', '*.cc', '*.cxx', '*.rs']
            result = _probe_phase1_rg(root, OSSL_SYMBOLS, globs, logger)
            assert result is not None
            matched, first, count, engine = result
            assert os.path.join(root, "a") in matched
            assert os.path.join(root, "b") in matched
            assert os.path.join(root, "c") not in matched


class TestIntegration:
    """End-to-end source-probe tests (rg-based)."""

    @pytest.fixture(autouse=True)
    def check_rg(self):
        from openssl_scanner._vendor.rg import get_rg_path
        rg = get_rg_path()
        if not rg:
            pytest.skip("rg not available")

    def test_full_pipeline(self):
        """Phase 1 (rg) + Phase 2 combined."""
        import logging
        logger = logging.getLogger("test_integration")

        with tempfile.TemporaryDirectory() as root:
            _make_tree(root, {
                "proj_a/src/tls.c": 'void f() { SSL_connect(ssl); }\n',
                "proj_a/src/crypto.c": 'void g() { EVP_DigestInit_ex(c,m,0); }\n',
                "proj_a/tests/test.c": 'void t() { SSL_CTX_new(NULL); }\n',
                "proj_b/lib/x509.c": 'void h() { X509_new(); }\n',
                "unrelated/main.c": 'int main() { return 0; }\n',
            })
            globs = ['*.c', '*.h', '*.cpp', '*.hpp', '*.cc', '*.cxx', '*.hxx', '*.rs']
            result = _probe_phase1_rg(root, OSSL_SYMBOLS, globs, logger)
            assert result is not None
            matched, first, count, engine = result

            assert len(matched) >= 3

            report = _probe_phase2_consolidate(root, matched)

            assert len(report) == 2
            assert os.path.join(root, "proj_a") in report
            assert os.path.join(root, "proj_b/lib") in report
            assert os.path.join(root, "unrelated") not in report

    def test_full_pipeline_single_project(self):
        """All matches under one project."""
        import logging
        logger = logging.getLogger("test_integration")

        with tempfile.TemporaryDirectory() as root:
            _make_tree(root, {
                "mylib/src/core/ssl.c": 'void f() { SSL_new(ctx); }\n',
                "mylib/src/util/bio.c": 'void g() { BN_new(); }\n',
                "mylib/include/api.h": 'void h() { SSL_read(s, b, n); }\n',
            })
            globs = ['*.c', '*.h', '*.cpp', '*.hpp', '*.cc', '*.cxx', '*.hxx', '*.rs']
            result = _probe_phase1_rg(root, OSSL_SYMBOLS, globs, logger)
            assert result is not None
            matched, first, count, engine = result

            report = _probe_phase2_consolidate(root, matched)

            assert len(report) == 1
            assert report[0] == os.path.join(root, "mylib")
