"""Tests for custom pattern matching in HAP ELF scanning."""

import json
import os
import struct
import tempfile

import pytest

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openssl_scanner.custom_matcher import (
    CustomMatch,
    CustomResult,
    CustomMatcher,
)


DATA_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'src', 'openssl_scanner', 'data')


class TestCustomMatcherLoad:
    """Loading custom pattern groups from JSON."""

    def test_load_builtin(self):
        m = CustomMatcher()
        count = m.load_patterns()
        assert count > 0
        assert 'openHiTLS' in m.groups
        assert 'wolfSSL' in m.groups
        assert 'mbedTLS' in m.groups
        assert 'libsodium' in m.groups

    def test_load_from_path(self, tmp_path):
        pf = tmp_path / 'patterns.json'
        pf.write_text(json.dumps({
            'version': '1.0',
            'groups': {
                'testLib': ['test_init', 'test_free'],
            },
        }))
        m = CustomMatcher()
        count = m.load_patterns(str(pf))
        assert count == 2
        assert 'testLib' in m.groups
        assert m.groups['testLib'] == {'test_init', 'test_free'}

    def test_load_missing_file(self):
        m = CustomMatcher()
        count = m.load_patterns('/nonexistent/path.json')
        assert count == 0
        assert m.groups == {}

    def test_load_empty_groups(self, tmp_path):
        pf = tmp_path / 'empty.json'
        pf.write_text(json.dumps({'version': '1.0', 'groups': {}}))
        m = CustomMatcher()
        count = m.load_patterns(str(pf))
        assert count == 0

    def test_all_patterns_set(self):
        m = CustomMatcher()
        m.load_patterns()
        all_p = m.all_patterns
        assert 'HITLS_Connect' in all_p
        assert 'wolfSSL_Init' in all_p
        assert 'mbedtls_ssl_init' in all_p
        assert 'sodium_init' in all_p
        assert len(all_p) == sum(len(v) for v in m.groups.values())

    def test_load_malformed_json(self, tmp_path):
        pf = tmp_path / 'bad.json'
        pf.write_text('not json')
        m = CustomMatcher()
        count = m.load_patterns(str(pf))
        assert count == 0


class TestCustomMatcherScanBytes:
    """Matching patterns against raw bytes (unit-level, no ELF parsing)."""

    def setup_method(self):
        self.matcher = CustomMatcher()
        self.matcher.groups = {
            'openHiTLS': {'HITLS_Init', 'HITLS_Connect', 'HITLS_Read'},
            'wolfSSL': {'wolfSSL_Init', 'wolfSSL_CTX_new'},
        }
        self.matcher._rebuild_all_patterns()

    def test_match_in_strings(self):
        strings = {'HITLS_Init', 'some_other_func', 'HITLS_Connect'}
        matches = self.matcher.match_strings(strings)
        assert 'openHiTLS' in matches
        assert matches['openHiTLS'] == {'HITLS_Init', 'HITLS_Connect'}
        assert 'wolfSSL' not in matches or len(matches.get('wolfSSL', set())) == 0

    def test_no_match(self):
        strings = {'foo_init', 'bar_free', 'unrelated_func'}
        matches = self.matcher.match_strings(strings)
        assert all(len(v) == 0 for v in matches.values())

    def test_cross_group_match(self):
        strings = {'HITLS_Init', 'wolfSSL_Init'}
        matches = self.matcher.match_strings(strings)
        assert 'HITLS_Init' in matches.get('openHiTLS', set())
        assert 'wolfSSL_Init' in matches.get('wolfSSL', set())

    def test_empty_strings(self):
        matches = self.matcher.match_strings(set())
        assert all(len(v) == 0 for v in matches.values())


class TestCustomResult:
    """CustomResult formatting and aggregation."""

    def test_summary_text_single_group(self):
        r = CustomResult()
        r.matches = {'wolfSSL': {'wolfSSL_Init', 'wolfSSL_free', 'wolfSSL_CTX_new'}}
        assert r.summary_text() == 'wolfSSL (3)'

    def test_summary_text_multiple_groups(self):
        r = CustomResult()
        r.matches = {
            'openHiTLS': {'HITLS_Init', 'HITLS_Connect'},
            'wolfSSL': {'wolfSSL_Init'},
        }
        text = r.summary_text()
        assert 'openHiTLS (2)' in text
        assert 'wolfSSL (1)' in text

    def test_summary_text_empty(self):
        r = CustomResult()
        r.matches = {}
        assert r.summary_text() == ''

    def test_summary_text_zero_matches(self):
        r = CustomResult()
        r.matches = {'wolfSSL': set(), 'openHiTLS': set()}
        assert r.summary_text() == ''

    def test_has_matches(self):
        r = CustomResult()
        r.matches = {'wolfSSL': {'wolfSSL_Init'}}
        assert r.has_matches is True

    def test_has_no_matches(self):
        r = CustomResult()
        r.matches = {'wolfSSL': set()}
        assert r.has_matches is False

    def test_details_preserved(self):
        r = CustomResult()
        r.details = [
            CustomMatch('libfoo.so', 'wolfSSL', 'wolfSSL_Init', 'dynsym_und'),
        ]
        assert len(r.details) == 1
        assert r.details[0].group == 'wolfSSL'
        assert r.details[0].location == 'dynsym_und'


class TestExtractRodataStrings:
    """Test the public extract_rodata_strings in elf_analyzer."""

    def test_import_exists(self):
        from openssl_scanner.elf_analyzer import extract_rodata_strings
        assert callable(extract_rodata_strings)

    def test_non_elf_returns_empty(self, tmp_path):
        from openssl_scanner.elf_analyzer import extract_rodata_strings
        f = tmp_path / 'notelf.bin'
        f.write_bytes(b'not an elf file')
        result = extract_rodata_strings(str(f))
        assert result == set()

    def test_missing_file_returns_empty(self):
        from openssl_scanner.elf_analyzer import extract_rodata_strings
        result = extract_rodata_strings('/nonexistent/file.so')
        assert result == set()

    def test_extracts_strings_from_rodata(self, tmp_path):
        from openssl_scanner.elf_analyzer import extract_rodata_strings
        from tests.fixtures.elf_builder import ELFBuilder

        rodata = b'wolfSSL_Init\x00HITLS_Connect\x00ab\x00long_enough\x00'
        elf = ELFBuilder().set_rodata(rodata).build()
        f = tmp_path / 'test.so'
        f.write_bytes(elf)
        result = extract_rodata_strings(str(f))
        assert 'wolfSSL_Init' in result
        assert 'HITLS_Connect' in result
        assert 'long_enough' in result
        assert 'ab' not in result  # below min_len=4


class TestScanFile:
    """Direct tests for CustomMatcher.scan_file() -- the core detection method."""

    def setup_method(self):
        self.matcher = CustomMatcher()
        self.matcher.groups = {
            'openHiTLS': {'HITLS_Init', 'HITLS_Connect', 'HITLS_Read'},
            'wolfSSL': {'wolfSSL_Init', 'wolfSSL_CTX_new'},
        }
        self.matcher._rebuild_all_patterns()

    def test_scan_file_non_elf(self, tmp_path):
        f = tmp_path / 'notelf.bin'
        f.write_bytes(b'not an elf file at all')
        matches, details = self.matcher.scan_file(str(f))
        assert all(len(v) == 0 for v in matches.values())
        assert details == []

    def test_scan_file_no_patterns_loaded(self, tmp_path):
        """Early return when all_patterns is empty."""
        m = CustomMatcher()
        m.groups = {'testLib': set()}
        m._rebuild_all_patterns()
        f = tmp_path / 'dummy.so'
        f.write_bytes(b'\x7fELF' + b'\x00' * 100)
        matches, details = m.scan_file(str(f))
        assert 'testLib' in matches
        assert len(matches['testLib']) == 0
        assert details == []

    def test_scan_file_dynsym_und(self, tmp_path):
        """UND symbols matched and tagged as dynsym_und."""
        from tests.fixtures.elf_builder import ELFBuilder
        elf = (ELFBuilder()
               .add_dynsym('HITLS_Init', defined=False)
               .add_dynsym('HITLS_Connect', defined=False)
               .add_dynsym('printf', defined=False)
               .build())
        f = tmp_path / 'libtest.so'
        f.write_bytes(elf)
        matches, details = self.matcher.scan_file(str(f))
        assert matches['openHiTLS'] == {'HITLS_Init', 'HITLS_Connect'}
        assert len(matches['wolfSSL']) == 0
        und_details = [d for d in details if d.location == 'dynsym_und']
        assert len(und_details) == 2
        assert all(d.group == 'openHiTLS' for d in und_details)

    def test_scan_file_dynsym_def(self, tmp_path):
        """DEF symbols matched and tagged as dynsym_def."""
        from tests.fixtures.elf_builder import ELFBuilder
        elf = (ELFBuilder()
               .add_dynsym('wolfSSL_Init', defined=True)
               .add_dynsym('wolfSSL_CTX_new', defined=True)
               .build())
        f = tmp_path / 'libwolf.so'
        f.write_bytes(elf)
        matches, details = self.matcher.scan_file(str(f))
        assert matches['wolfSSL'] == {'wolfSSL_Init', 'wolfSSL_CTX_new'}
        def_details = [d for d in details if d.location == 'dynsym_def']
        assert len(def_details) == 2

    def test_scan_file_rodata(self, tmp_path):
        """Rodata-only matches tagged as rodata."""
        from tests.fixtures.elf_builder import ELFBuilder
        rodata = b'HITLS_Read\x00some_other_string\x00'
        elf = ELFBuilder().set_rodata(rodata).build()
        f = tmp_path / 'librodata.so'
        f.write_bytes(elf)
        matches, details = self.matcher.scan_file(str(f))
        assert 'HITLS_Read' in matches['openHiTLS']
        rodata_details = [d for d in details if d.location == 'rodata']
        assert len(rodata_details) == 1
        assert rodata_details[0].pattern == 'HITLS_Read'

    def test_scan_file_dedup_und_over_def(self, tmp_path):
        """UND takes priority over DEF -- same symbol not duplicated."""
        from tests.fixtures.elf_builder import ELFBuilder
        elf = (ELFBuilder()
               .add_dynsym('wolfSSL_Init', defined=False)
               .add_dynsym('wolfSSL_Init', defined=True)
               .build())
        f = tmp_path / 'libdedup.so'
        f.write_bytes(elf)
        matches, details = self.matcher.scan_file(str(f))
        assert matches['wolfSSL'] == {'wolfSSL_Init'}
        assert len(details) == 1
        assert details[0].location == 'dynsym_und'

    def test_scan_file_dedup_dynsym_over_rodata(self, tmp_path):
        """Symbols found in .dynsym suppress .rodata matches."""
        from tests.fixtures.elf_builder import ELFBuilder
        rodata = b'HITLS_Init\x00HITLS_Read\x00'
        elf = (ELFBuilder()
               .add_dynsym('HITLS_Init', defined=False)
               .set_rodata(rodata)
               .build())
        f = tmp_path / 'libprio.so'
        f.write_bytes(elf)
        matches, details = self.matcher.scan_file(str(f))
        assert matches['openHiTLS'] == {'HITLS_Init', 'HITLS_Read'}
        locations = {d.pattern: d.location for d in details}
        assert locations['HITLS_Init'] == 'dynsym_und'
        assert locations['HITLS_Read'] == 'rodata'

    def test_scan_file_cross_group(self, tmp_path):
        """Multiple groups matched in the same file."""
        from tests.fixtures.elf_builder import ELFBuilder
        elf = (ELFBuilder()
               .add_dynsym('HITLS_Init', defined=False)
               .add_dynsym('wolfSSL_Init', defined=False)
               .build())
        f = tmp_path / 'libmulti.so'
        f.write_bytes(elf)
        matches, details = self.matcher.scan_file(str(f))
        assert 'HITLS_Init' in matches['openHiTLS']
        assert 'wolfSSL_Init' in matches['wolfSSL']
        groups = {d.group for d in details}
        assert groups == {'openHiTLS', 'wolfSSL'}

    def test_scan_file_basename_in_details(self, tmp_path):
        """Details use basename, not full path."""
        from tests.fixtures.elf_builder import ELFBuilder
        elf = (ELFBuilder()
               .add_dynsym('HITLS_Init', defined=False)
               .build())
        f = tmp_path / 'libentry.so'
        f.write_bytes(elf)
        _, details = self.matcher.scan_file(str(f))
        assert details[0].file == 'libentry.so'


class TestScanDirectory:
    """Tests for scan_directory() -- multi-file aggregation."""

    def setup_method(self):
        self.matcher = CustomMatcher()
        self.matcher.groups = {
            'openHiTLS': {'HITLS_Init', 'HITLS_Connect'},
            'wolfSSL': {'wolfSSL_Init', 'wolfSSL_CTX_new'},
        }
        self.matcher._rebuild_all_patterns()

    def test_scan_directory_aggregation(self, tmp_path):
        """Multiple .so files, matches aggregated per group."""
        from tests.fixtures.elf_builder import ELFBuilder
        elf1 = (ELFBuilder()
                .add_dynsym('HITLS_Init', defined=False)
                .build())
        elf2 = (ELFBuilder()
                .add_dynsym('HITLS_Connect', defined=False)
                .add_dynsym('wolfSSL_Init', defined=False)
                .build())
        (tmp_path / 'liba.so').write_bytes(elf1)
        (tmp_path / 'libb.so').write_bytes(elf2)
        result = self.matcher.scan_directory(str(tmp_path))
        assert result.has_matches
        assert result.matches['openHiTLS'] == {'HITLS_Init', 'HITLS_Connect'}
        assert result.matches['wolfSSL'] == {'wolfSSL_Init'}
        assert len(result.details) == 3

    def test_scan_directory_skips_non_so(self, tmp_path):
        """Non-.so files are ignored."""
        from tests.fixtures.elf_builder import ELFBuilder
        elf = ELFBuilder().add_dynsym('HITLS_Init', defined=False).build()
        (tmp_path / 'libtest.so').write_bytes(elf)
        (tmp_path / 'config.json').write_text('{}')
        (tmp_path / 'readme.txt').write_text('hello')
        result = self.matcher.scan_directory(str(tmp_path))
        assert result.has_matches
        assert len(result.details) == 1

    def test_scan_directory_no_patterns(self, tmp_path):
        """Empty all_patterns returns immediately."""
        m = CustomMatcher()
        result = m.scan_directory(str(tmp_path))
        assert not result.has_matches

    def test_scan_directory_summary_text(self, tmp_path):
        """summary_text reflects aggregated matches."""
        from tests.fixtures.elf_builder import ELFBuilder
        elf = (ELFBuilder()
               .add_dynsym('HITLS_Init', defined=False)
               .add_dynsym('wolfSSL_Init', defined=False)
               .build())
        (tmp_path / 'lib.so').write_bytes(elf)
        result = self.matcher.scan_directory(str(tmp_path))
        text = result.summary_text()
        assert 'openHiTLS (1)' in text
        assert 'wolfSSL (1)' in text

    def test_scan_directory_handles_corrupt_elf(self, tmp_path):
        """Corrupt .so files are skipped without crashing."""
        (tmp_path / 'bad.so').write_bytes(b'\x7fELF' + b'\xff' * 20)
        from tests.fixtures.elf_builder import ELFBuilder
        elf = ELFBuilder().add_dynsym('HITLS_Init', defined=False).build()
        (tmp_path / 'good.so').write_bytes(elf)
        result = self.matcher.scan_directory(str(tmp_path))
        assert 'HITLS_Init' in result.matches.get('openHiTLS', set())


class TestCustomMatcherIntegration:
    """Integration: load patterns + match against symbol sets."""

    def setup_method(self):
        self.matcher = CustomMatcher()
        self.matcher.load_patterns()

    def test_match_hitls_symbols(self):
        syms = {'HITLS_Connect', 'HITLS_Read', 'some_func', 'printf'}
        matches = self.matcher.match_strings(syms)
        assert 'HITLS_Connect' in matches.get('openHiTLS', set())
        assert 'HITLS_Read' in matches.get('openHiTLS', set())

    def test_match_wolfssl_symbols(self):
        syms = {'wolfSSL_Init', 'wolfSSL_CTX_new', 'malloc', 'free'}
        matches = self.matcher.match_strings(syms)
        assert 'wolfSSL_Init' in matches.get('wolfSSL', set())
        assert 'wolfSSL_CTX_new' in matches.get('wolfSSL', set())

    def test_match_mbedtls_symbols(self):
        syms = {'mbedtls_ssl_init', 'mbedtls_aes_init', 'malloc', 'free'}
        matches = self.matcher.match_strings(syms)
        assert 'mbedtls_ssl_init' in matches.get('mbedTLS', set())
        assert 'mbedtls_aes_init' in matches.get('mbedTLS', set())

    def test_match_libsodium_symbols(self):
        syms = {'sodium_init', 'crypto_secretbox_easy', 'malloc', 'free'}
        matches = self.matcher.match_strings(syms)
        assert 'sodium_init' in matches.get('libsodium', set())
        assert 'crypto_secretbox_easy' in matches.get('libsodium', set())

    def test_no_false_positives(self):
        syms = {'SSL_CTX_new', 'EVP_sha256', 'printf', 'malloc'}
        matches = self.matcher.match_strings(syms)
        assert all(len(v) == 0 for v in matches.values())

    def test_scan_directory_empty(self, tmp_path):
        result = self.matcher.scan_directory(str(tmp_path))
        assert result.has_matches is False
        assert result.summary_text() == ''


class TestHapSummaryCustomColumn:
    """Verify Custom Match column in HAP summary."""

    def test_column_defined(self):
        from openssl_scanner.hap_report import _HAP_SUMMARY_COLUMNS
        col_keys = [c[0] for c in _HAP_SUMMARY_COLUMNS]
        assert 'custom_match' in col_keys

    def test_build_row_with_custom(self):
        from openssl_scanner.hap_report import build_hap_summary_row
        from unittest.mock import MagicMock

        result = MagicMock()
        result.package_info = {
            'bundle_name': 'com.test.app',
            'module_name': 'entry',
            'module_type': 'entry',
            'version_name': '1.0.0',
            'version_code': 1,
            'scanned_abi': 'arm64-v8a',
            'native_libs_count': 2,
            'bundled_openssl': False,
            'package_type': 'hap',
        }
        result.symbols_by_category = {}
        result.dlopen_libs_detected = []

        custom = CustomResult()
        custom.matches = {'wolfSSL': {'wolfSSL_Init', 'wolfSSL_free'}}
        custom.details = []

        row = build_hap_summary_row(
            result, '/tmp/test.hap', 'none', set(), set(), set(),
            'No-OpenSSL', custom_result=custom)
        assert row['custom_match'] == 'wolfSSL (2)'

    def test_build_row_without_custom(self):
        from openssl_scanner.hap_report import build_hap_summary_row
        from unittest.mock import MagicMock

        result = MagicMock()
        result.package_info = {
            'bundle_name': 'com.test.app',
            'module_name': 'entry',
            'module_type': 'entry',
            'version_name': '1.0.0',
            'version_code': 1,
            'scanned_abi': 'arm64-v8a',
            'native_libs_count': 2,
            'bundled_openssl': False,
            'package_type': 'hap',
        }
        result.symbols_by_category = {}
        result.dlopen_libs_detected = []

        row = build_hap_summary_row(
            result, '/tmp/test.hap', 'none', set(), set(), set(),
            'No-OpenSSL')
        assert row['custom_match'] == ''

    def test_build_row_fallback_from_package_info(self):
        """When no custom_result object, read from package_info (hap-summary path)."""
        from openssl_scanner.hap_report import build_hap_summary_row
        from unittest.mock import MagicMock

        result = MagicMock()
        result.package_info = {
            'bundle_name': 'com.test.app',
            'module_name': 'entry',
            'module_type': 'entry',
            'version_name': '1.0.0',
            'version_code': 1,
            'scanned_abi': 'arm64-v8a',
            'native_libs_count': 2,
            'bundled_openssl': False,
            'package_type': 'hap',
            'custom_match': 'openHiTLS (3)',
        }
        result.symbols_by_category = {}
        result.dlopen_libs_detected = []

        row = build_hap_summary_row(
            result, '/tmp/test.hap', 'none', set(), set(), set(),
            'No-OpenSSL')
        assert row['custom_match'] == 'openHiTLS (3)'


class TestGenerateHapSummaryCustom:
    """Verify generate_hap_summary passes custom_results to rows."""

    def test_summary_with_custom_results(self, tmp_path):
        from openssl_scanner.hap_report import generate_hap_summary
        from unittest.mock import MagicMock

        result = MagicMock()
        result.package_info = {
            'bundle_name': 'com.test.app',
            'module_name': 'entry',
            'module_type': 'entry',
            'version_name': '1.0.0',
            'version_code': 1,
            'scanned_abi': 'arm64-v8a',
            'native_libs_count': 1,
            'bundled_openssl': False,
            'package_type': 'hap',
        }
        result.symbols_by_category = {}
        result.dlopen_libs_detected = []

        custom = CustomResult()
        custom.matches = {'wolfSSL': {'wolfSSL_Init'}}
        custom.details = []

        path = generate_hap_summary(
            [result], ['test.hap'], str(tmp_path),
            custom_results=[custom])
        assert path is not None
        assert os.path.exists(path)

    def test_summary_without_custom_results(self, tmp_path):
        from openssl_scanner.hap_report import generate_hap_summary
        from unittest.mock import MagicMock

        result = MagicMock()
        result.package_info = {
            'bundle_name': 'com.test.app',
            'module_name': 'entry',
            'module_type': 'entry',
            'version_name': '1.0.0',
            'version_code': 1,
            'scanned_abi': 'arm64-v8a',
            'native_libs_count': 1,
            'bundled_openssl': False,
            'package_type': 'hap',
        }
        result.symbols_by_category = {}
        result.dlopen_libs_detected = []

        path = generate_hap_summary(
            [result], ['test.hap'], str(tmp_path))
        assert path is not None
        assert os.path.exists(path)
