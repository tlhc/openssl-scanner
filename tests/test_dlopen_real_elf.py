"""
Integration tests with GCC-compiled ELF binaries (Linux aarch64).

These tests scan real shared libraries produced by gcc on Linux.
When the fixture binaries are not available (e.g., on macOS CI),
tests are skipped automatically.

The binaries are built by tests/fixtures/build_dlopen_test_binaries.py
and should be present at tests/fixtures/dlopen_binaries/.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openssl_scanner.dlopen_analyzer import detect_dlopen_openssl


OSSL_EXPORTS = {
    'SSL_CTX_new', 'SSL_connect', 'SSL_read', 'SSL_write',
    'SSL_CTX_free', 'SSL_free', 'SSL_new', 'SSL_set_fd',
    'EVP_DigestInit_ex', 'EVP_DigestUpdate', 'EVP_DigestFinal_ex',
    'EVP_sha256', 'EVP_MD_CTX_new', 'EVP_MD_CTX_free',
    'BIO_new', 'BIO_free', 'BIO_read', 'BIO_write',
    'OPENSSL_init_ssl', 'OPENSSL_init_crypto',
    'X509_get_subject_name', 'RSA_generate_key_ex',
    'EVP_EncryptInit_ex', 'EVP_DecryptInit_ex',
    'EVP_PKEY_new', 'EVP_PKEY_free',
}

BINARIES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'dlopen_binaries')

def _bin(name):
    return os.path.join(BINARIES_DIR, name)


def _need_elf_binaries():
    """Check that compiled ELF test binaries exist and are ELF format."""
    marker = _bin('build_info.txt')
    if not os.path.exists(marker):
        return False
    with open(marker) as f:
        for line in f:
            if line.startswith('os=') and 'linux' not in line:
                return False
    return True


needs_elf = pytest.mark.skipif(
    not _need_elf_binaries(),
    reason="Compiled ELF binaries not available (run build_dlopen_test_binaries.py on Linux)"
)


@needs_elf
class TestRealDlopenCluster:
    """Scenario 2: gcc-compiled dlopen+dlsym with clustered symbols."""

    def test_detects_dlopen_and_dlsym(self):
        result = detect_dlopen_openssl(_bin('dlopen_cluster.so'), OSSL_EXPORTS)
        assert result is not None
        assert result.uses_dlopen
        assert result.uses_dlsym

    def test_finds_clustered_symbols(self):
        result = detect_dlopen_openssl(_bin('dlopen_cluster.so'), OSSL_EXPORTS)
        assert 'SSL_CTX_new' in result.dlsym_symbols
        assert 'SSL_connect' in result.dlsym_symbols
        assert 'EVP_sha256' in result.dlsym_symbols
        assert len(result.dlsym_symbols) >= 3

    def test_finds_library_pattern(self):
        result = detect_dlopen_openssl(_bin('dlopen_cluster.so'), OSSL_EXPORTS)
        assert 'libcrypto.so.3' in result.dlopen_libs

    def test_layer_c_disasm_resolves_symbols(self):
        """Real gcc output: Layer C should resolve at least some dlsym args."""
        result = detect_dlopen_openssl(_bin('dlopen_cluster.so'), OSSL_EXPORTS)
        assert len(result.dlsym_symbols) >= 3


@needs_elf
class TestRealDlopenSparse:
    """Scenario 3: Sparse symbols with large padding."""

    def test_detects_dlopen(self):
        result = detect_dlopen_openssl(_bin('dlopen_sparse.so'), OSSL_EXPORTS)
        assert result is not None
        assert result.uses_dlopen
        assert result.uses_dlsym

    def test_finds_sparse_symbols(self):
        result = detect_dlopen_openssl(_bin('dlopen_sparse.so'), OSSL_EXPORTS)
        assert 'SSL_CTX_new' in result.dlsym_symbols
        assert 'EVP_sha256' in result.dlsym_symbols


@needs_elf
class TestRealStaticLink:
    """Scenario 4: Exports OpenSSL-named symbols (simulated static build)."""

    def test_no_dlopen_detected(self):
        result = detect_dlopen_openssl(_bin('static_ossl.so'), OSSL_EXPORTS)
        assert result is not None
        assert not result.uses_dlopen
        assert not result.uses_dlsym
        assert result.dlsym_symbols == []

    def test_no_library_detected(self):
        result = detect_dlopen_openssl(_bin('static_ossl.so'), OSSL_EXPORTS)
        assert result.dlopen_libs == []


@needs_elf
class TestRealNoOpenSSL:
    """Scenario 6: No OpenSSL at all."""

    def test_empty_results(self):
        result = detect_dlopen_openssl(_bin('no_openssl.so'), OSSL_EXPORTS)
        assert result is not None
        assert not result.uses_dlopen
        assert not result.uses_dlsym
        assert result.dlsym_symbols == []
        assert result.dlopen_libs == []


@needs_elf
class TestRealDirectLink:
    """Scenario 1: UND OpenSSL symbols (no actual libcrypto)."""

    def test_no_dlopen_detected(self):
        result = detect_dlopen_openssl(_bin('direct_link.so'), OSSL_EXPORTS)
        assert result is not None
        assert not result.uses_dlopen


@needs_elf
class TestRealMixed:
    """Scenario 5: Direct UND + dlopen."""

    def test_detects_dlopen(self):
        result = detect_dlopen_openssl(_bin('mixed.so'), OSSL_EXPORTS)
        assert result is not None
        assert result.uses_dlopen
        assert result.uses_dlsym

    def test_layer_a_with_exclude(self):
        """With exclude_symbols, direct-linked symbols are filtered out."""
        exclude = {'SSL_CTX_new', 'SSL_connect'}
        result = detect_dlopen_openssl(_bin('mixed.so'), OSSL_EXPORTS,
                                       exclude_symbols=exclude)
        assert 'SSL_CTX_new' not in result.dlsym_symbols
        assert 'SSL_connect' not in result.dlsym_symbols


@needs_elf
class TestRealHMPlugin:
    """Scenario 7: HarmonyOS-style plugin."""

    def test_detects_hm_lib(self):
        result = detect_dlopen_openssl(_bin('hm_plugin.so'), OSSL_EXPORTS)
        assert result is not None
        assert result.uses_dlopen
        assert result.uses_dlsym
        assert 'libcrypto_openssl.z.so' in result.dlopen_libs

    def test_finds_hm_symbols(self):
        result = detect_dlopen_openssl(_bin('hm_plugin.so'), OSSL_EXPORTS)
        assert 'SSL_CTX_new' in result.dlsym_symbols
        assert 'EVP_sha256' in result.dlsym_symbols
        assert len(result.dlsym_symbols) >= 5
