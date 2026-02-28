
import json
import os
import sys
import tempfile
import shutil
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openssl_scanner.aggregator import (
    Aggregator, AggregatedReporter,
    AggregatedResult, ComponentStats, ExecutableDetail, ImportChainEntry,
)


def _make_report(scan_root='/usr/bin/test_app', all_unique=None,
                 by_category=None, import_chains=None, by_depth=None,
                 report_type='single', tool_version='1.0.0'):
    """Build a minimal valid scan report dict."""
    if all_unique is None:
        all_unique = ['SSL_connect', 'EVP_sha256']
    if by_category is None:
        by_category = {
            'ssl_core': {'count': 1, 'symbols': ['SSL_connect']},
            'crypto_evp': {'count': 1, 'symbols': ['EVP_sha256']},
        }
    report = {
        'meta': {
            'tool_version': tool_version,
            'report_type': report_type,
            'scan_root': scan_root,
            'scan_time': '2026-02-27T12:00:00',
        },
        'openssl_symbols': {
            'all_unique': all_unique,
            'by_category': by_category,
            'import_chains': import_chains or {},
            'by_depth': by_depth or {},
        },
    }
    return report


def _write_report(tmpdir, filename, report_dict):
    """Write a report dict as JSON to tmpdir, return path."""
    path = os.path.join(tmpdir, filename)
    with open(path, 'w') as f:
        json.dump(report_dict, f)
    return path


class TestAggregatorBasic:
    """Basic aggregation tests."""

    def test_aggregate_single_report(self, tmp_path):
        report = _make_report(scan_root='/usr/bin/app')
        _write_report(str(tmp_path), 'app.json', report)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert result.source_reports_count == 1
        assert result.total_components == 1
        assert 'app' in result.components
        assert 'SSL_connect' in result.global_unique_symbols
        assert 'EVP_sha256' in result.global_unique_symbols

    def test_aggregate_multiple_reports(self, tmp_path):
        r1 = _make_report(
            scan_root='/usr/bin/app1',
            all_unique=['SSL_connect'],
            by_category={'ssl_core': {'count': 1, 'symbols': ['SSL_connect']}},
        )
        r2 = _make_report(
            scan_root='/usr/bin/app2',
            all_unique=['EVP_sha256', 'BIO_new'],
            by_category={
                'crypto_evp': {'count': 1, 'symbols': ['EVP_sha256']},
                'crypto_bio': {'count': 1, 'symbols': ['BIO_new']},
            },
        )
        _write_report(str(tmp_path), 'app1.json', r1)
        _write_report(str(tmp_path), 'app2.json', r2)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert result.source_reports_count == 2
        assert result.total_components == 2
        assert len(result.global_unique_symbols) == 3

    def test_aggregate_deduplication(self, tmp_path):
        r1 = _make_report(
            scan_root='/usr/bin/a',
            all_unique=['SSL_connect', 'EVP_sha256'],
        )
        r2 = _make_report(
            scan_root='/usr/bin/b',
            all_unique=['SSL_connect', 'BIO_new'],
        )
        _write_report(str(tmp_path), 'a.json', r1)
        _write_report(str(tmp_path), 'b.json', r2)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert len(result.global_unique_symbols) == 3

    def test_aggregate_empty_directory(self, tmp_path):
        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert result.source_reports_count == 0
        assert result.total_components == 0
        assert len(result.global_unique_symbols) == 0

    def test_aggregate_skips_invalid_json(self, tmp_path):
        _write_report(str(tmp_path), 'valid.json',
                      _make_report(scan_root='/usr/bin/valid'))

        invalid_path = os.path.join(str(tmp_path), 'invalid.json')
        with open(invalid_path, 'w') as f:
            f.write('{ this is not valid json }}}')

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert result.source_reports_count == 1

    def test_aggregate_skips_non_single_report(self, tmp_path):
        aggregated_report = _make_report(
            scan_root='/usr/bin/agg', report_type='aggregated'
        )
        _write_report(str(tmp_path), 'aggregated.json', aggregated_report)

        single_report = _make_report(scan_root='/usr/bin/app')
        _write_report(str(tmp_path), 'app.json', single_report)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert result.source_reports_count == 1

    def test_aggregate_skips_non_json_files(self, tmp_path):
        _write_report(str(tmp_path), 'app.json',
                      _make_report(scan_root='/usr/bin/app'))

        txt_path = os.path.join(str(tmp_path), 'readme.txt')
        with open(txt_path, 'w') as f:
            f.write('not a report')

        xlsx_path = os.path.join(str(tmp_path), 'report.xlsx')
        with open(xlsx_path, 'w') as f:
            f.write('binary')

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert result.source_reports_count == 1

    def test_aggregate_skips_json_without_tool_version(self, tmp_path):
        bad = {'meta': {}, 'openssl_symbols': {}}
        _write_report(str(tmp_path), 'bad.json', bad)

        _write_report(str(tmp_path), 'good.json',
                      _make_report(scan_root='/usr/bin/good'))

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert result.source_reports_count == 1


class TestAggregatorMapping:
    """Tests for component mapping functionality."""

    def test_mapping_groups_components(self, tmp_path):
        mapping = {
            'network': ['/usr/bin/curl', '/usr/bin/wget'],
            'web_server': ['/usr/sbin/nginx'],
        }
        mapping_path = os.path.join(str(tmp_path), 'mapping.json')
        with open(mapping_path, 'w') as f:
            json.dump(mapping, f)

        r1 = _make_report(scan_root='/usr/bin/curl',
                          all_unique=['SSL_connect'])
        r2 = _make_report(scan_root='/usr/sbin/nginx',
                          all_unique=['EVP_sha256'])
        _write_report(str(tmp_path), 'curl.json', r1)
        _write_report(str(tmp_path), 'nginx.json', r2)

        agg = Aggregator(mapping_file=mapping_path)
        result = agg.aggregate(str(tmp_path))

        assert 'network' in result.components
        assert 'web_server' in result.components
        assert 'SSL_connect' in result.components['network'].unique_symbols

    def test_mapping_unclassified(self, tmp_path):
        mapping = {'network': ['/usr/bin/curl']}
        mapping_path = os.path.join(str(tmp_path), 'mapping.json')
        with open(mapping_path, 'w') as f:
            json.dump(mapping, f)

        r1 = _make_report(scan_root='/usr/bin/curl',
                          all_unique=['SSL_connect'])
        r2 = _make_report(scan_root='/usr/bin/unknown',
                          all_unique=['EVP_sha256'])
        _write_report(str(tmp_path), 'curl.json', r1)
        _write_report(str(tmp_path), 'unknown.json', r2)

        agg = Aggregator(mapping_file=mapping_path)
        result = agg.aggregate(str(tmp_path))

        assert 'curl' not in result.unclassified.executables
        assert 'unknown' in result.unclassified.executables
        assert 'EVP_sha256' in result.unclassified.unique_symbols

    def test_mapping_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            Aggregator(mapping_file='/nonexistent/mapping.json')


class TestAggregatorMergeImportChains:
    """Tests for import chain merging."""

    def test_import_chains_dict_format(self, tmp_path):
        report = _make_report(
            scan_root='/usr/bin/app',
            import_chains={
                'SSL_connect': [
                    {'chain': 'app -> libssl.so -> libcrypto.so', 'depth': 2},
                ],
            },
        )
        _write_report(str(tmp_path), 'app.json', report)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert 'SSL_connect' in result.import_chains
        entry = result.import_chains['SSL_connect'][0]
        assert isinstance(entry, ImportChainEntry)
        assert entry.chain == 'app -> libssl.so -> libcrypto.so'
        assert entry.depth == 2
        assert entry.component == 'app'

    def test_import_chains_string_format(self, tmp_path):
        report = _make_report(
            scan_root='/usr/bin/app',
            import_chains={
                'SSL_connect': ['app -> libssl.so -> libcrypto.so'],
            },
        )
        _write_report(str(tmp_path), 'app.json', report)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        entry = result.import_chains['SSL_connect'][0]
        assert entry.chain == 'app -> libssl.so -> libcrypto.so'
        assert entry.depth == 2

    def test_import_chains_merged_across_reports(self, tmp_path):
        r1 = _make_report(
            scan_root='/usr/bin/a',
            import_chains={'SSL_connect': [{'chain': 'a -> libssl.so', 'depth': 1}]},
        )
        r2 = _make_report(
            scan_root='/usr/bin/b',
            import_chains={'SSL_connect': [{'chain': 'b -> libssl.so', 'depth': 1}]},
        )
        _write_report(str(tmp_path), 'a.json', r1)
        _write_report(str(tmp_path), 'b.json', r2)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert len(result.import_chains['SSL_connect']) == 2


class TestAggregatorMergeByDepth:
    """Tests for by_depth merging."""

    def test_by_depth_merged(self, tmp_path):
        r1 = _make_report(
            scan_root='/usr/bin/a',
            by_depth={
                'depth_0': {'symbols': ['SSL_connect'], 'count': 1},
                'depth_1': {'symbols': ['BIO_new'], 'count': 1},
            },
        )
        r2 = _make_report(
            scan_root='/usr/bin/b',
            by_depth={
                'depth_0': {'symbols': ['EVP_sha256'], 'count': 1},
            },
        )
        _write_report(str(tmp_path), 'a.json', r1)
        _write_report(str(tmp_path), 'b.json', r2)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert 0 in result.by_depth
        assert 'SSL_connect' in result.by_depth[0]['symbols']
        assert 'EVP_sha256' in result.by_depth[0]['symbols']
        assert 1 in result.by_depth
        assert 'BIO_new' in result.by_depth[1]['symbols']

    def test_by_depth_invalid_key_skipped(self, tmp_path):
        report = _make_report(
            scan_root='/usr/bin/app',
            by_depth={'depth_abc': {'symbols': ['SSL_connect'], 'count': 1}},
        )
        _write_report(str(tmp_path), 'app.json', report)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert len(result.by_depth) == 0


class TestAggregatorMergeByCategory:
    """Tests for global category merging."""

    def test_global_by_category_merged(self, tmp_path):
        r1 = _make_report(
            scan_root='/usr/bin/a',
            by_category={
                'ssl_core': {'count': 1, 'symbols': ['SSL_connect']},
            },
        )
        r2 = _make_report(
            scan_root='/usr/bin/b',
            by_category={
                'ssl_core': {'count': 1, 'symbols': ['SSL_read']},
                'crypto_evp': {'count': 1, 'symbols': ['EVP_sha256']},
            },
        )
        _write_report(str(tmp_path), 'a.json', r1)
        _write_report(str(tmp_path), 'b.json', r2)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert 'SSL_connect' in result.global_by_category['ssl_core']
        assert 'SSL_read' in result.global_by_category['ssl_core']
        assert 'EVP_sha256' in result.global_by_category['crypto_evp']


class TestComponentStats:
    """Tests for ComponentStats dataclass."""

    def test_add_executable(self):
        cs = ComponentStats(name='network')
        cs.add_executable(
            'curl', '/usr/bin/curl',
            ['SSL_connect', 'EVP_sha256'],
            {'ssl_core': ['SSL_connect'], 'crypto_evp': ['EVP_sha256']},
        )

        assert 'curl' in cs.executables
        assert 'SSL_connect' in cs.unique_symbols
        assert 'EVP_sha256' in cs.unique_symbols
        assert 'SSL_connect' in cs.by_category['ssl_core']

        detail = cs.executables_detail['curl']
        assert isinstance(detail, ExecutableDetail)
        assert detail.path == '/usr/bin/curl'
        assert 'SSL_connect' in detail.unique_symbols

    def test_add_executable_dedup(self):
        cs = ComponentStats(name='network')
        cs.add_executable('curl', '/usr/bin/curl', ['SSL_connect'],
                          {'ssl_core': ['SSL_connect']})
        cs.add_executable('curl', '/usr/bin/curl', ['EVP_sha256'],
                          {'crypto_evp': ['EVP_sha256']})

        assert cs.executables.count('curl') == 1
        assert len(cs.unique_symbols) == 2

    def test_add_symbols_legacy(self):
        cs = ComponentStats(name='web')
        cs.add_symbols(
            ['SSL_connect'],
            {'ssl_core': ['SSL_connect']},
        )
        assert 'SSL_connect' in cs.unique_symbols
        assert 'SSL_connect' in cs.by_category['ssl_core']

    def test_multiple_executables_merge_symbols(self):
        cs = ComponentStats(name='net')
        cs.add_executable('a', '/a', ['SSL_connect'],
                          {'ssl_core': ['SSL_connect']})
        cs.add_executable('b', '/b', ['SSL_connect', 'EVP_sha256'],
                          {'ssl_core': ['SSL_connect'], 'crypto_evp': ['EVP_sha256']})

        assert len(cs.unique_symbols) == 2
        assert len(cs.executables) == 2


class TestAggregatedReporter:
    """Tests for AggregatedReporter."""

    def _make_result(self, **overrides):
        defaults = dict(
            aggregation_time='2026-02-27T12:00:00',
            tool_version='1.0.0',
            source_reports_count=2,
            mapping_file=None,
            total_components=2,
            total_executables=3,
        )
        defaults.update(overrides)
        result = AggregatedResult(**{k: v for k, v in defaults.items()
                                     if k in AggregatedResult.__dataclass_fields__})
        return result

    def test_generate_json_valid(self):
        result = self._make_result()
        result.global_unique_symbols = {'SSL_connect', 'EVP_sha256'}

        cs = ComponentStats(name='network')
        cs.add_executable('curl', '/usr/bin/curl', ['SSL_connect'],
                          {'ssl_core': ['SSL_connect']})
        result.components['network'] = cs

        reporter = AggregatedReporter()
        output = reporter.generate_json(result)
        data = json.loads(output)

        assert data['meta']['report_type'] == 'aggregated'
        assert data['meta']['tool_version'] == '1.0.0'
        assert data['summary']['total_components'] == 2

    def test_generate_json_ranking(self):
        result = self._make_result()
        result.global_unique_symbols = {'SSL_connect', 'EVP_sha256', 'BIO_new'}

        cs1 = ComponentStats(name='big')
        cs1.unique_symbols = {'SSL_connect', 'EVP_sha256', 'BIO_new'}
        result.components['big'] = cs1

        cs2 = ComponentStats(name='small')
        cs2.unique_symbols = {'SSL_connect'}
        result.components['small'] = cs2

        reporter = AggregatedReporter()
        data = json.loads(reporter.generate_json(result))

        ranking = data['ranking']
        assert ranking[0]['component'] == 'big'
        assert ranking[0]['unique_symbols_count'] == 3
        assert ranking[1]['component'] == 'small'
        assert ranking[1]['unique_symbols_count'] == 1

    def test_generate_json_unclassified(self):
        result = self._make_result()
        result.global_unique_symbols = {'SSL_connect'}
        result.unclassified.executables.append('unknown_app')
        result.unclassified.unique_symbols.add('SSL_connect')

        reporter = AggregatedReporter()
        data = json.loads(reporter.generate_json(result))

        assert data['unclassified'] is not None
        assert 'unknown_app' in data['unclassified']['executables']
        assert data['unclassified']['unique_symbols_count'] == 1

    def test_generate_json_no_unclassified(self):
        result = self._make_result()
        result.global_unique_symbols = set()

        reporter = AggregatedReporter()
        data = json.loads(reporter.generate_json(result))

        assert data['unclassified'] is None

    def test_generate_json_compact(self):
        result = self._make_result()
        result.global_unique_symbols = set()

        reporter = AggregatedReporter()
        output = reporter.generate_json(result, pretty=False)
        assert '\n' not in output

    def test_generate_json_import_chains(self):
        result = self._make_result()
        result.global_unique_symbols = {'SSL_connect'}
        result.import_chains = {
            'SSL_connect': [
                ImportChainEntry(
                    component='network', binary='curl',
                    chain='curl -> libssl.so', depth=1,
                ),
            ],
        }

        reporter = AggregatedReporter()
        data = json.loads(reporter.generate_json(result))

        chains = data['openssl_symbols']['import_chains']
        assert 'SSL_connect' in chains
        assert chains['SSL_connect'][0]['component'] == 'network'

    def test_generate_json_by_depth(self):
        result = self._make_result()
        result.global_unique_symbols = {'SSL_connect'}
        result.by_depth = {
            0: {'symbols': {'SSL_connect'}, 'files': {'curl'},
                'components': {'network'}},
        }

        reporter = AggregatedReporter()
        data = json.loads(reporter.generate_json(result))

        bd = data['openssl_symbols']['by_depth']
        assert 'depth_0' in bd
        assert bd['depth_0']['count'] == 1

    def test_generate_json_by_category(self):
        result = self._make_result()
        result.global_unique_symbols = {'SSL_connect'}
        result.global_by_category = {
            'ssl_core': {'SSL_connect'},
        }

        reporter = AggregatedReporter()
        data = json.loads(reporter.generate_json(result))

        bc = data['openssl_symbols']['by_category']
        assert 'ssl_core' in bc
        assert bc['ssl_core']['count'] == 1

    def test_generate_json_executables_detail(self):
        result = self._make_result()
        result.global_unique_symbols = {'SSL_connect'}

        cs = ComponentStats(name='net')
        cs.add_executable(
            'curl', '/usr/bin/curl',
            ['SSL_connect'],
            {'ssl_core': ['SSL_connect']},
        )
        result.components['net'] = cs

        reporter = AggregatedReporter()
        data = json.loads(reporter.generate_json(result))

        detail = data['components']['net']['executables_detail']['curl']
        assert detail['name'] == 'curl'
        assert detail['path'] == '/usr/bin/curl'
        assert detail['unique_symbols_count'] == 1

    def test_generate_summary_basic(self):
        result = self._make_result()
        result.global_unique_symbols = {'SSL_connect', 'EVP_sha256'}

        cs = ComponentStats(name='network')
        cs.unique_symbols = {'SSL_connect', 'EVP_sha256'}
        result.components['network'] = cs

        reporter = AggregatedReporter()
        output = reporter.generate_summary(result)

        assert 'Aggregation Report' in output
        assert 'Source Reports:   2' in output
        assert 'Total Components:        2' in output
        assert 'network' in output

    def test_generate_summary_ranking_percentage(self):
        result = self._make_result()
        result.global_unique_symbols = {'SSL_connect', 'EVP_sha256', 'BIO_new', 'RSA_sign'}

        cs = ComponentStats(name='big')
        cs.unique_symbols = {'SSL_connect', 'EVP_sha256', 'BIO_new', 'RSA_sign'}
        result.components['big'] = cs

        reporter = AggregatedReporter()
        output = reporter.generate_summary(result)

        assert '100.0%' in output

    def test_generate_summary_unclassified(self):
        result = self._make_result()
        result.global_unique_symbols = {'SSL_connect'}
        result.unclassified.executables.append('mystery_app')
        result.unclassified.unique_symbols.add('SSL_connect')

        reporter = AggregatedReporter()
        output = reporter.generate_summary(result)

        assert 'UNCLASSIFIED' in output
        assert 'Executables: 1' in output

    def test_generate_summary_no_unclassified(self):
        result = self._make_result()
        result.global_unique_symbols = set()

        reporter = AggregatedReporter()
        output = reporter.generate_summary(result)

        assert 'UNCLASSIFIED' not in output

    def test_generate_summary_mapping_file(self):
        result = self._make_result(mapping_file='/etc/mapping.json')
        result.global_unique_symbols = set()

        reporter = AggregatedReporter()
        output = reporter.generate_summary(result)

        assert 'Mapping File:     /etc/mapping.json' in output


class TestAggregatorFinalize:
    """Tests for _finalize_result calculations."""

    def test_totals_computed(self, tmp_path):
        r1 = _make_report(scan_root='/usr/bin/a', all_unique=['SSL_connect'])
        r2 = _make_report(scan_root='/usr/bin/b', all_unique=['EVP_sha256'])
        r3 = _make_report(scan_root='/usr/bin/c', all_unique=['BIO_new'])
        _write_report(str(tmp_path), 'a.json', r1)
        _write_report(str(tmp_path), 'b.json', r2)
        _write_report(str(tmp_path), 'c.json', r3)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert result.total_components == 3
        assert result.total_executables == 3
        assert len(result.global_unique_symbols) == 3

    def test_totals_with_mapping_and_unclassified(self, tmp_path):
        mapping = {'web': ['/usr/bin/a', '/usr/bin/b']}
        mapping_path = os.path.join(str(tmp_path), 'mapping.json')
        with open(mapping_path, 'w') as f:
            json.dump(mapping, f)

        r1 = _make_report(scan_root='/usr/bin/a')
        r2 = _make_report(scan_root='/usr/bin/b')
        r3 = _make_report(scan_root='/usr/bin/orphan')
        _write_report(str(tmp_path), 'a.json', r1)
        _write_report(str(tmp_path), 'b.json', r2)
        _write_report(str(tmp_path), 'orphan.json', r3)

        agg = Aggregator(mapping_file=mapping_path)
        result = agg.aggregate(str(tmp_path))

        assert result.total_components == 1
        assert result.total_executables == 3
        assert len(result.unclassified.executables) == 1


class TestAggregatorEdgeCases:
    """Edge case tests."""

    def test_report_with_empty_symbols(self, tmp_path):
        report = _make_report(
            scan_root='/usr/bin/clean',
            all_unique=[],
            by_category={},
        )
        _write_report(str(tmp_path), 'clean.json', report)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert result.source_reports_count == 1
        assert len(result.global_unique_symbols) == 0
        assert 'clean' in result.components
        assert len(result.components['clean'].unique_symbols) == 0

    def test_report_missing_fields_graceful(self, tmp_path):
        minimal = {
            'meta': {'tool_version': '1.0.0', 'report_type': 'single'},
            'openssl_symbols': {},
        }
        _write_report(str(tmp_path), 'minimal.json', minimal)

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert result.source_reports_count == 1

    def test_multiple_executables_in_same_component(self, tmp_path):
        mapping = {'web': ['/usr/bin/curl', '/usr/bin/wget']}
        mapping_path = os.path.join(str(tmp_path), 'mapping.json')
        with open(mapping_path, 'w') as f:
            json.dump(mapping, f)

        r1 = _make_report(
            scan_root='/usr/bin/curl',
            all_unique=['SSL_connect'],
            by_category={'ssl_core': {'count': 1, 'symbols': ['SSL_connect']}},
        )
        r2 = _make_report(
            scan_root='/usr/bin/wget',
            all_unique=['SSL_connect', 'EVP_sha256'],
            by_category={
                'ssl_core': {'count': 1, 'symbols': ['SSL_connect']},
                'crypto_evp': {'count': 1, 'symbols': ['EVP_sha256']},
            },
        )
        _write_report(str(tmp_path), 'curl.json', r1)
        _write_report(str(tmp_path), 'wget.json', r2)

        agg = Aggregator(mapping_file=mapping_path)
        result = agg.aggregate(str(tmp_path))

        web = result.components['web']
        assert len(web.executables) == 2
        assert len(web.unique_symbols) == 2
        assert 'curl' in web.executables_detail
        assert 'wget' in web.executables_detail

    def test_corrupt_report_skipped_gracefully(self, tmp_path):
        good = _make_report(scan_root='/usr/bin/good')
        _write_report(str(tmp_path), 'good.json', good)

        bad_path = os.path.join(str(tmp_path), 'bad.json')
        with open(bad_path, 'w') as f:
            f.write('')

        agg = Aggregator()
        result = agg.aggregate(str(tmp_path))

        assert result.source_reports_count == 1
