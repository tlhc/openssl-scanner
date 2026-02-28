
import json
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openssl_scanner.reporter import Reporter
from openssl_scanner.scanner import ScanResult, FileResult
from openssl_scanner.dependency_resolver import DependencyNode
from openssl_scanner.dependency_graph import ImportChain, DepthInfo


def _make_scan_result(**overrides):
    """Build a ScanResult with reasonable defaults, overridable per-field."""
    defaults = dict(
        target='/usr/bin/test_app',
        scan_time='2026-02-27T12:00:00',
        tool_version='1.0.0',
        arch='aarch64',
        total_files_scanned=3,
        total_elf_files=2,
        files_with_openssl=1,
        openssl_libs_found=['libcrypto.so.3', 'libssl.so.3'],
        symbols_by_file={
            '/usr/bin/test_app': ['SSL_connect', 'EVP_sha256'],
        },
        symbols_by_category={
            'ssl_core': ['SSL_connect'],
            'crypto_evp': ['EVP_sha256'],
        },
        all_unique_symbols=['SSL_connect', 'EVP_sha256'],
    )
    defaults.update(overrides)
    return ScanResult(**defaults)


def _make_file_result(**overrides):
    defaults = dict(
        path='/usr/bin/test_app',
        file_type='executable',
        arch='aarch64',
        direct_deps=['libcrypto.so.3', 'libc.so'],
        openssl_direct=True,
        openssl_transitive=False,
        openssl_libs=['libcrypto.so.3'],
        openssl_symbols=['SSL_connect', 'EVP_sha256'],
    )
    defaults.update(overrides)
    return FileResult(**defaults)


class TestReporterGenerateJson:
    """Tests for Reporter.generate_json()."""

    def setup_method(self):
        self.reporter = Reporter()

    def test_produces_valid_json(self):
        result = _make_scan_result()
        output = self.reporter.generate_json(result)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_json_schema_meta(self):
        result = _make_scan_result()
        data = json.loads(self.reporter.generate_json(result))

        assert data['meta']['tool_version'] == '1.0.0'
        assert data['meta']['report_type'] == 'single'
        assert data['meta']['scan_root'] == '/usr/bin/test_app'
        assert data['meta']['target_arch'] == 'aarch64'
        assert data['meta']['scan_time'] == '2026-02-27T12:00:00'

    def test_json_schema_summary(self):
        result = _make_scan_result()
        data = json.loads(self.reporter.generate_json(result))

        s = data['summary']
        assert s['total_files_scanned'] == 3
        assert s['total_elf_files'] == 2
        assert s['files_with_openssl_deps'] == 1
        assert s['total_openssl_symbols'] == 2
        assert s['unique_openssl_symbols'] == 2
        assert s['openssl_libs_found'] == ['libcrypto.so.3', 'libssl.so.3']

    def test_json_symbols_by_file(self):
        result = _make_scan_result()
        data = json.loads(self.reporter.generate_json(result))

        by_file = data['openssl_symbols']['by_file']
        assert '/usr/bin/test_app' in by_file
        entry = by_file['/usr/bin/test_app']
        assert entry['count'] == 2
        assert set(entry['symbols']) == {'SSL_connect', 'EVP_sha256'}

    def test_json_symbols_by_category(self):
        result = _make_scan_result()
        data = json.loads(self.reporter.generate_json(result))

        by_cat = data['openssl_symbols']['by_category']
        assert by_cat['ssl_core']['count'] == 1
        assert 'SSL_connect' in by_cat['ssl_core']['symbols']
        assert by_cat['crypto_evp']['count'] == 1

    def test_json_compact_mode(self):
        result = _make_scan_result()
        compact = self.reporter.generate_json(result, pretty=False)
        assert '\n' not in compact
        data = json.loads(compact)
        assert data['meta']['tool_version'] == '1.0.0'

    def test_json_pretty_mode(self):
        result = _make_scan_result()
        pretty = self.reporter.generate_json(result, pretty=True)
        assert '\n' in pretty

    def test_json_empty_result(self):
        result = _make_scan_result(
            total_files_scanned=0,
            total_elf_files=0,
            files_with_openssl=0,
            openssl_libs_found=[],
            symbols_by_file={},
            symbols_by_category={},
            all_unique_symbols=[],
            files_detail=[],
        )
        data = json.loads(self.reporter.generate_json(result))

        assert data['summary']['total_openssl_symbols'] == 0
        assert data['summary']['unique_openssl_symbols'] == 0
        assert data['openssl_symbols']['by_file'] == {}
        assert data['openssl_symbols']['all_unique'] == []

    def test_json_files_detail(self):
        fr = _make_file_result()
        result = _make_scan_result(files_detail=[fr])
        data = json.loads(self.reporter.generate_json(result))

        details = data['files_detail']
        assert len(details) == 1
        d = details[0]
        assert d['path'] == '/usr/bin/test_app'
        assert d['type'] == 'executable'
        assert d['arch'] == 'aarch64'
        assert d['openssl_deps']['direct'] is True
        assert d['openssl_deps']['transitive'] is False
        assert d['static_openssl'] is False

    def test_json_static_openssl_file(self):
        fr = _make_file_result(
            static_openssl=True,
            static_openssl_version='3.0.9',
            static_ssl_library='OpenSSL',
            static_openssl_confidence='high',
            static_openssl_confidence_reason='version_banner',
        )
        result = _make_scan_result(files_detail=[fr])
        data = json.loads(self.reporter.generate_json(result))

        d = data['files_detail'][0]
        assert d['static_openssl'] is True
        assert d['static_openssl_version'] == '3.0.9'
        assert d['static_ssl_library'] == 'OpenSSL'
        assert d['static_openssl_confidence'] == 'high'

    def test_json_dlopen_file(self):
        fr = _make_file_result(
            uses_dlopen=True,
            dlsym_symbols=['AES_encrypt'],
            dlopen_libs=['libcrypto.so'],
            dlopen_confidence='high',
        )
        result = _make_scan_result(
            files_detail=[fr],
            files_with_dlopen=1,
            dlsym_symbols_by_file={'/usr/bin/test_app': ['AES_encrypt']},
            all_dlsym_symbols=['AES_encrypt'],
            dlopen_libs_detected=['libcrypto.so'],
        )
        data = json.loads(self.reporter.generate_json(result))

        d = data['files_detail'][0]
        assert d['dlopen_detection']['uses_dlopen'] is True
        assert 'AES_encrypt' in d['dlopen_detection']['dlopen_symbols']

        assert 'dlopen_analysis' in data
        assert data['dlopen_analysis']['files_with_dlopen'] == 1

    def test_json_no_dlopen_section_when_zero(self):
        result = _make_scan_result(files_with_dlopen=0)
        data = json.loads(self.reporter.generate_json(result))
        assert 'dlopen_analysis' not in data

    def test_json_dependency_tree(self):
        root = DependencyNode(
            name='test_app', path='/usr/bin/test_app',
            is_openssl_lib=False,
            children=[
                DependencyNode(
                    name='libcrypto.so.3', path='/usr/lib/libcrypto.so.3',
                    is_openssl_lib=True,
                    openssl_symbols=['SSL_connect'],
                ),
            ],
        )
        result = _make_scan_result(dependency_tree=root)
        data = json.loads(self.reporter.generate_json(result))

        tree = data['dependency_tree']
        assert tree['name'] == 'test_app'
        assert tree['is_openssl_lib'] is False
        assert len(tree['children']) == 1
        child = tree['children'][0]
        assert child['name'] == 'libcrypto.so.3'
        assert child['is_openssl_lib'] is True
        assert child['openssl_symbols_count'] == 1

    def test_json_process_info(self):
        result = _make_scan_result(
            process_info={'name': 'nginx', 'pid': 1234, 'cmdline': '/usr/sbin/nginx'}
        )
        data = json.loads(self.reporter.generate_json(result))
        assert data['meta']['process']['name'] == 'nginx'
        assert data['meta']['process']['pid'] == 1234

    def test_json_package_info(self):
        result = _make_scan_result(
            package_info={'package_type': 'hap', 'bundle_name': 'com.example.app'}
        )
        data = json.loads(self.reporter.generate_json(result))
        assert data['meta']['package']['package_type'] == 'hap'

    def test_json_depth_info_format(self):
        result = _make_scan_result(
            depth_info={
                0: DepthInfo(count=2, symbols=['SSL_connect', 'EVP_sha256'],
                             files=['/usr/bin/test_app']),
                1: DepthInfo(count=1, symbols=['BIO_new'], files=['/usr/lib/libmy.so']),
            }
        )
        data = json.loads(self.reporter.generate_json(result))

        by_depth = data['openssl_symbols']['by_depth']
        assert 'depth_0' in by_depth
        assert by_depth['depth_0']['count'] == 2
        assert by_depth['depth_0']['files'] == ['/usr/bin/test_app']
        assert 'depth_1' in by_depth

    def test_json_symbols_by_depth_fallback(self):
        result = _make_scan_result(
            symbols_by_depth={
                0: ['SSL_connect'],
                1: ['EVP_sha256'],
            }
        )
        data = json.loads(self.reporter.generate_json(result))

        by_depth = data['openssl_symbols']['by_depth']
        assert by_depth['depth_0']['count'] == 1
        assert 'files' not in by_depth['depth_0']

    def test_json_import_chains_detail_format(self):
        result = _make_scan_result(
            import_chains_detail={
                'SSL_connect': [
                    ImportChain(source_file='/usr/bin/app',
                                chain='app -> libcrypto.so.3', depth=1),
                ],
            }
        )
        data = json.loads(self.reporter.generate_json(result))

        chains = data['openssl_symbols']['import_chains']
        assert 'SSL_connect' in chains
        c = chains['SSL_connect'][0]
        assert c['source_file'] == '/usr/bin/app'
        assert c['depth'] == 1

    def test_json_import_chains_legacy_fallback(self):
        result = _make_scan_result(
            import_chains={'SSL_connect': ['app -> libcrypto.so.3']}
        )
        data = json.loads(self.reporter.generate_json(result))

        chains = data['openssl_symbols']['import_chains']
        assert chains == {'SSL_connect': ['app -> libcrypto.so.3']}

    def test_json_unicode_in_paths(self):
        result = _make_scan_result(target='/usr/bin/test_app')
        output = self.reporter.generate_json(result)
        assert 'ensure_ascii' not in output
        data = json.loads(output)
        assert data['meta']['scan_root'] == '/usr/bin/test_app'

    def test_json_errors_field(self):
        result = _make_scan_result(
            errors=[
                {'file': '/usr/lib/broken.so', 'error': 'Not an ELF file',
                 'severity': 'warning'},
            ]
        )
        data = json.loads(self.reporter.generate_json(result))
        assert len(data['errors']) == 1
        assert data['errors'][0]['file'] == '/usr/lib/broken.so'


class TestReporterGenerateSummary:
    """Tests for Reporter.generate_summary()."""

    def setup_method(self):
        self.reporter = Reporter()

    def test_summary_contains_header(self):
        result = _make_scan_result()
        output = self.reporter.generate_summary(result)
        assert 'OpenSSL Symbol Dependency Scanner' in output
        assert '1.0.0' in output

    def test_summary_contains_target(self):
        result = _make_scan_result()
        output = self.reporter.generate_summary(result)
        assert '/usr/bin/test_app' in output

    def test_summary_scan_statistics(self):
        result = _make_scan_result()
        output = self.reporter.generate_summary(result)
        assert 'Total Files Scanned:       3' in output
        assert 'ELF Files Found:           2' in output
        assert 'Files with OpenSSL Deps:   1' in output

    def test_summary_openssl_libs(self):
        result = _make_scan_result()
        output = self.reporter.generate_summary(result)
        assert 'libcrypto.so.3' in output
        assert 'libssl.so.3' in output

    def test_summary_category_bars(self):
        result = _make_scan_result()
        output = self.reporter.generate_summary(result)
        assert 'ssl_core' in output
        assert 'crypto_evp' in output

    def test_summary_top10_symbols(self):
        result = _make_scan_result(
            symbols_by_file={
                '/usr/bin/a': ['SSL_connect', 'EVP_sha256'],
                '/usr/bin/b': ['SSL_connect'],
            }
        )
        output = self.reporter.generate_summary(result)
        assert 'SSL_connect' in output
        assert '2 files' in output

    def test_summary_empty_result(self):
        result = _make_scan_result(
            total_files_scanned=0,
            total_elf_files=0,
            files_with_openssl=0,
            openssl_libs_found=[],
            symbols_by_file={},
            symbols_by_category={},
            all_unique_symbols=[],
        )
        output = self.reporter.generate_summary(result)
        assert 'Total OpenSSL Symbols Referenced: 0' in output
        assert 'Unique Symbols: 0' in output

    def test_summary_process_info(self):
        result = _make_scan_result(
            process_info={
                'name': 'nginx',
                'pid': 1234,
                'cmdline': '/usr/sbin/nginx',
                'mapped_libraries_count': 42,
                'runtime_loaded_count': 0,
            }
        )
        output = self.reporter.generate_summary(result)
        assert 'nginx' in output
        assert '1234' in output
        assert '42 loaded' in output

    def test_summary_process_info_with_dlopen_libs(self):
        result = _make_scan_result(
            process_info={
                'name': 'nginx',
                'pid': 1234,
                'mapped_libraries_count': 42,
                'runtime_loaded_count': 5,
            }
        )
        output = self.reporter.generate_summary(result)
        assert '42 loaded (5 via dlopen)' in output

    def test_summary_package_info(self):
        result = _make_scan_result(
            package_info={
                'package_type': 'hap',
                'bundle_name': 'com.example.app',
                'module_name': 'entry',
                'module_type': 'entry',
                'version_name': '1.0.0',
                'version_code': '100',
                'scanned_abi': 'arm64-v8a',
                'native_libs_count': 3,
            }
        )
        output = self.reporter.generate_summary(result)
        assert 'HAP' in output
        assert 'com.example.app' in output
        assert 'entry' in output
        assert 'arm64-v8a' in output

    def test_summary_package_info_abi_list(self):
        result = _make_scan_result(
            package_info={
                'package_type': 'hap',
                'bundle_name': 'com.example.app',
                'module_name': 'entry',
                'module_type': 'entry',
                'version_name': '1.0.0',
                'version_code': '100',
                'scanned_abi': ['arm64-v8a', 'armeabi-v7a'],
                'native_libs_count': 6,
            }
        )
        output = self.reporter.generate_summary(result)
        assert 'arm64-v8a, armeabi-v7a' in output

    def test_summary_static_openssl_shown(self):
        result = _make_scan_result(files_with_static_openssl=2)
        output = self.reporter.generate_summary(result)
        assert 'Static OpenSSL Link:       2' in output

    def test_summary_static_openssl_hidden_when_zero(self):
        result = _make_scan_result(files_with_static_openssl=0)
        output = self.reporter.generate_summary(result)
        assert 'Static OpenSSL' not in output

    def test_summary_dlopen_info(self):
        result = _make_scan_result(
            files_with_dlopen=2,
            all_dlsym_symbols=['AES_encrypt', 'EVP_sha256'],
            dlopen_libs_detected=['libcrypto.so'],
        )
        output = self.reporter.generate_summary(result)
        assert 'Files using dlopen:        2' in output
        assert 'dlopen OpenSSL Symbols:    2 unique' in output
        assert 'libcrypto.so' in output

    def test_summary_dependency_tree(self):
        root = DependencyNode(
            name='test_app', path='/usr/bin/test_app',
            children=[
                DependencyNode(
                    name='libcrypto.so.3', path='/usr/lib/libcrypto.so.3',
                    is_openssl_lib=True,
                    openssl_symbols=['SSL_connect'],
                ),
            ],
        )
        result = _make_scan_result(dependency_tree=root)
        output = self.reporter.generate_summary(result)
        assert 'DEPENDENCY TREE' in output
        assert 'test_app' in output
        assert 'libcrypto.so.3*' in output
        assert '(* = OpenSSL library)' in output

    def test_summary_depth_info(self):
        result = _make_scan_result(
            symbols_by_depth={
                0: ['SSL_connect', 'EVP_sha256'],
                1: ['BIO_new'],
            }
        )
        output = self.reporter.generate_summary(result)
        assert 'root' in output
        assert 'depth 1' in output

    def test_summary_errors_section(self):
        result = _make_scan_result(
            errors=[
                {'file': '/lib/bad.so', 'error': 'parse error', 'severity': 'warning'},
                {'file': '/lib/bad2.so', 'error': 'missing', 'severity': 'error'},
            ]
        )
        output = self.reporter.generate_summary(result)
        assert 'WARNINGS' in output
        assert '[WARNING] /lib/bad.so: parse error' in output
        assert '[ERROR] /lib/bad2.so: missing' in output

    def test_summary_errors_truncated_at_10(self):
        errors = [
            {'file': f'/lib/bad{i}.so', 'error': f'err{i}', 'severity': 'warning'}
            for i in range(15)
        ]
        result = _make_scan_result(errors=errors)
        output = self.reporter.generate_summary(result)
        assert '... and 5 more warnings' in output

    def test_summary_tree_with_error_node(self):
        root = DependencyNode(
            name='test_app', path='/usr/bin/test_app',
            children=[
                DependencyNode(
                    name='libmissing.so', path=None,
                    error='not found',
                ),
            ],
        )
        result = _make_scan_result(dependency_tree=root)
        output = self.reporter.generate_summary(result)
        assert 'libmissing.so' in output
        assert 'not found' in output

    def test_summary_other_category_displayed(self):
        result = _make_scan_result(
            symbols_by_category={
                'ssl_core': ['SSL_connect'],
                'other': ['SOME_unknown_sym'],
            }
        )
        output = self.reporter.generate_summary(result)
        assert 'other' in output


class TestFileResultToDict:
    """Tests for Reporter._file_result_to_dict()."""

    def setup_method(self):
        self.reporter = Reporter()

    def test_basic_serialization(self):
        fr = _make_file_result()
        d = self.reporter._file_result_to_dict(fr)

        assert d['path'] == '/usr/bin/test_app'
        assert d['type'] == 'executable'
        assert d['arch'] == 'aarch64'
        assert d['openssl_deps']['direct'] is True
        assert d['openssl_deps']['transitive'] is False
        assert d['static_openssl'] is False
        assert d['error'] is None

    def test_dlopen_detection_included(self):
        fr = _make_file_result(
            uses_dlopen=True,
            dlsym_symbols=['AES_encrypt'],
            dlopen_libs=['libcrypto.so'],
            dlopen_confidence='high',
        )
        d = self.reporter._file_result_to_dict(fr)

        assert 'dlopen_detection' in d
        assert d['dlopen_detection']['uses_dlopen'] is True
        assert d['dlopen_detection']['dlopen_symbols'] == ['AES_encrypt']
        assert d['dlopen_detection']['confidence'] == 'high'

    def test_no_dlopen_key_when_not_used(self):
        fr = _make_file_result(uses_dlopen=False)
        d = self.reporter._file_result_to_dict(fr)
        assert 'dlopen_detection' not in d

    def test_error_field(self):
        fr = _make_file_result(error='Not an ELF file')
        d = self.reporter._file_result_to_dict(fr)
        assert d['error'] == 'Not an ELF file'

    def test_exported_symbols(self):
        fr = _make_file_result(openssl_exported=['EVP_sha256', 'AES_encrypt'])
        d = self.reporter._file_result_to_dict(fr)
        assert d['openssl_exported'] == ['EVP_sha256', 'AES_encrypt']


class TestTreeToDict:
    """Tests for Reporter._tree_to_dict()."""

    def setup_method(self):
        self.reporter = Reporter()

    def test_leaf_node(self):
        node = DependencyNode(name='libc.so', path='/usr/lib/libc.so')
        d = self.reporter._tree_to_dict(node)
        assert d['name'] == 'libc.so'
        assert d['is_openssl_lib'] is False
        assert 'children' not in d
        assert 'error' not in d

    def test_node_with_error(self):
        node = DependencyNode(name='libmissing.so', path=None, error='not found')
        d = self.reporter._tree_to_dict(node)
        assert d['error'] == 'not found'

    def test_nested_tree(self):
        root = DependencyNode(
            name='app', path='/usr/bin/app',
            children=[
                DependencyNode(
                    name='libssl.so', path='/usr/lib/libssl.so',
                    is_openssl_lib=True,
                    openssl_symbols=['SSL_connect', 'SSL_read'],
                    children=[
                        DependencyNode(
                            name='libcrypto.so', path='/usr/lib/libcrypto.so',
                            is_openssl_lib=True,
                            openssl_symbols=['EVP_sha256'],
                        ),
                    ],
                ),
            ],
        )
        d = self.reporter._tree_to_dict(root)
        assert len(d['children']) == 1
        ssl = d['children'][0]
        assert ssl['is_openssl_lib'] is True
        assert ssl['openssl_symbols_count'] == 2
        assert len(ssl['children']) == 1
        crypto = ssl['children'][0]
        assert crypto['openssl_symbols_count'] == 1
