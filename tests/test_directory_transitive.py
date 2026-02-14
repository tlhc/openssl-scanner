
import pytest
from unittest.mock import MagicMock
from openssl_scanner.scanner import Scanner, FileResult, ScanResult
from openssl_scanner.openssl_matcher import OpenSSLMatcher


class TestDirectoryTransitive:
    """Test transitive dependency marking in directory scan mode."""

    def test_directory_transitive_marking(self):
        """
        Verify that _compute_dependency_graph correctly marks transitive deps.

        Scenario:
        app -> libmiddle.so -> libcrypto.so

        All files are in the scanned directory.
        """
        scanner = Scanner()

        fr_crypto = FileResult(
            path="/opt/lib/libcrypto.so",
            file_type="shared_library",
            arch="x86_64",
            direct_deps=[],
            openssl_direct=False,
            openssl_transitive=False,
            openssl_libs=[],
            openssl_symbols=[],
        )

        fr_middle = FileResult(
            path="/opt/lib/libmiddle.so",
            file_type="shared_library",
            arch="x86_64",
            direct_deps=["libcrypto.so"],
            openssl_direct=True,
            openssl_transitive=False,
            openssl_libs=["libcrypto.so"],
            openssl_symbols=["EVP_encrypt"],
        )

        fr_app = FileResult(
            path="/opt/bin/app",
            file_type="executable",
            arch="x86_64",
            direct_deps=["libmiddle.so", "libc.so"],
            openssl_direct=False,
            openssl_transitive=False,
            openssl_libs=[],
            openssl_symbols=[],
        )

        file_results = [fr_crypto, fr_middle, fr_app]

        result = ScanResult(
            target="/opt",
            scan_time="now",
            tool_version="1.0",
            arch="x86_64",
            files_detail=file_results,
        )

        openssl_libs = {"/opt/lib/libcrypto.so", "libcrypto.so"}

        scanner._matcher = MagicMock(spec=OpenSSLMatcher)
        scanner._matcher.is_openssl_library.side_effect = lambda x: "crypto" in x

        scanner._compute_dependency_graph(result, file_results, openssl_libs)

        assert fr_middle.openssl_transitive is False
        assert fr_app.openssl_transitive is True, "App should be marked transitive"

    def test_broken_chain(self):
        """
        Scenario: app -> libmissing.so -> libcrypto.so
        libmissing.so is NOT in the scan results.
        Transitive link should fail (DependencyGraph limitation).
        """
        scanner = Scanner()

        fr_app = FileResult(
            path="/opt/bin/app",
            file_type="executable",
            arch="x86_64",
            direct_deps=["libmissing.so"],
            openssl_direct=False,
            openssl_transitive=False,
            openssl_libs=[],
            openssl_symbols=[],
        )

        file_results = [fr_app]
        result = ScanResult(
            target="/opt",
            scan_time="now",
            tool_version="1.0",
            arch="x86_64",
            files_detail=file_results,
        )

        openssl_libs = {"libcrypto.so"}

        scanner._matcher = MagicMock()
        scanner._matcher.is_openssl_library.return_value = False

        scanner._compute_dependency_graph(result, file_results, openssl_libs)

        assert fr_app.openssl_transitive is False
