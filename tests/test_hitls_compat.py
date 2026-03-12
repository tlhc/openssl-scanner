"""Tests for HiTLS compatibility mapping loader and lookup."""

import pytest
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openssl_scanner.hitls_compat import HiTLSCompat

FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), 'fixtures', 'test_hitls_compat.json'
)


class TestHiTLSCompat:

    def setup_method(self):
        self.compat = HiTLSCompat()

    def test_load_custom_path(self):
        count = self.compat.load(FIXTURE_PATH)
        assert count == 10
        assert self.compat.is_loaded()

    def test_load_missing_file(self):
        with pytest.raises(FileNotFoundError):
            self.compat.load('/nonexistent/path/hitls_compat.json')

    def test_load_invalid_json_structure(self):
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump({"version": "1.0"}, f)
            f.flush()
            try:
                with pytest.raises(ValueError, match="mapping"):
                    self.compat.load(f.name)
            finally:
                os.unlink(f.name)

    def test_lookup_available(self):
        self.compat.load(FIXTURE_PATH)
        status, hitls = self.compat.lookup('SSL_CTX_new')
        assert status == 'available'
        assert hitls == 'HITLS_CFG_NewTLSConfig'

    def test_lookup_partial(self):
        self.compat.load(FIXTURE_PATH)
        status, hitls = self.compat.lookup('SSL_read')
        assert status == 'partial'
        assert hitls == 'HITLS_Read'

    def test_lookup_not_available(self):
        self.compat.load(FIXTURE_PATH)
        status, hitls = self.compat.lookup('ENGINE_load_builtin_engines')
        assert status == 'not_available'
        assert hitls is None

    def test_lookup_unknown_symbol(self):
        self.compat.load(FIXTURE_PATH)
        status, hitls = self.compat.lookup('NONEXISTENT_func')
        assert status == 'unknown'
        assert hitls is None

    def test_lookup_not_loaded(self):
        status, hitls = self.compat.lookup('SSL_CTX_new')
        assert status == 'unknown'
        assert hitls is None

    def test_coverage_stats(self):
        self.compat.load(FIXTURE_PATH)
        symbols = {
            'SSL_CTX_new', 'SSL_connect', 'SSL_read', 'SSL_write',
            'EVP_DigestInit_ex', 'EVP_sha256',
            'ENGINE_load_builtin_engines', 'ENGINE_init',
            'RSA_public_encrypt', 'BN_new',
            'UNKNOWN_symbol',
        }
        stats = self.compat.get_coverage_stats(symbols)
        assert stats['available'] == 4
        assert stats['partial'] == 3
        assert stats['not_available'] == 3
        assert stats['unknown'] == 1

    def test_coverage_stats_not_loaded(self):
        stats = self.compat.get_coverage_stats({'SSL_CTX_new', 'EVP_sha256'})
        assert stats['unknown'] == 2
        assert stats['available'] == 0

    def test_get_all_mappings(self):
        self.compat.load(FIXTURE_PATH)
        mappings = self.compat.get_all_mappings()
        assert len(mappings) == 10
        assert 'SSL_CTX_new' in mappings
        assert mappings['SSL_CTX_new']['status'] == 'available'

    def test_get_all_mappings_returns_copy(self):
        self.compat.load(FIXTURE_PATH)
        mappings = self.compat.get_all_mappings()
        mappings['INJECTED'] = {'status': 'available'}
        assert 'INJECTED' not in self.compat.get_all_mappings()

    def test_empty_mapping(self):
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump({"version": "1.0", "mapping": {}}, f)
            f.flush()
            try:
                count = self.compat.load(f.name)
                assert count == 0
                assert self.compat.is_loaded()
                status, hitls = self.compat.lookup('SSL_CTX_new')
                assert status == 'unknown'
                assert hitls is None
            finally:
                os.unlink(f.name)

    def test_load_builtin(self):
        """GAP-6: Verify built-in data/hitls_compat.json loads correctly."""
        count = self.compat.load()
        assert count == 6248
        assert self.compat.is_loaded()
        status, hitls = self.compat.lookup('SSL_CTX_new')
        assert status == 'partial'

    def test_partial_with_null_hitls(self):
        """Partial entries with null hitls should return ('partial', None)."""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump({"version": "1.0", "mapping": {
                "EVP_DigestSignUpdate": {
                    "status": "partial",
                    "hitls": None,
                    "notes": "No streaming sign"
                }
            }}, f)
            f.flush()
            try:
                self.compat.load(f.name)
                status, hitls = self.compat.lookup('EVP_DigestSignUpdate')
                assert status == 'partial'
                assert hitls is None
            finally:
                os.unlink(f.name)


class TestProductionDataInvariants:
    """GAP-NEW: Validate structural invariants of the built-in mapping."""

    def setup_method(self):
        self.compat = HiTLSCompat()
        self.compat.load()

    def test_all_statuses_valid(self):
        mapping = self.compat.get_all_mappings()
        valid = {'available', 'partial', 'not_available'}
        for sym, entry in mapping.items():
            assert entry['status'] in valid, f"{sym}: invalid status '{entry['status']}'"

    def test_available_has_hitls(self):
        mapping = self.compat.get_all_mappings()
        for sym, entry in mapping.items():
            if entry['status'] == 'available':
                assert entry.get('hitls') is not None, (
                    f"{sym}: available but hitls is null")

    def test_not_available_has_null_hitls(self):
        mapping = self.compat.get_all_mappings()
        for sym, entry in mapping.items():
            if entry['status'] == 'not_available':
                assert entry.get('hitls') is None, (
                    f"{sym}: not_available but hitls is {entry['hitls']}")

    def test_total_count(self):
        mapping = self.compat.get_all_mappings()
        assert len(mapping) == 6248
