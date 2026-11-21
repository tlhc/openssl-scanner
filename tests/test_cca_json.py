"""Excel import and JSON-backed CCA reports."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from openssl_scanner import _vendor  # noqa: F401
from openpyxl import Workbook, load_workbook

from openssl_scanner.cca_compat import CCACompat, annotate_workbook


def _data():
    return {
        'schema_version': 1,
        'source_file': 'cca_compat.xlsx',
        'conclusions': [{'code': 8, 'text': '需要适配'}, {'code': 2, 'text': '无感知'}],
        'interfaces': [
            {'symbol': 'SSL_read', 'compatibility': '需要适配', 'sheet': 'TLS', 'row': 3,
             'products': '产品A\n产品B', 'scenarios': '=literal'},
            {'symbol': 'SSL_new', 'compatibility': '无感知', 'sheet': 'TLS', 'row': 2,
             'products': '产品C', 'scenarios': '建立连接'},
        ],
    }


def _json(tmp_path, data):
    path = tmp_path / 'cca_compat.json'
    path.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
    return path


def test_json_load_uses_persisted_codes_without_reading_excel(tmp_path, monkeypatch):
    data = _data()
    data['interfaces'].reverse()
    path = _json(tmp_path, data)

    def no_excel(*args, **kwargs):
        pytest.fail('JSON loading must not read Excel')

    monkeypatch.setattr('openpyxl.load_workbook', no_excel)
    compat = CCACompat(hidden=True)
    assert compat.load(path) == 2
    assert compat.lookup('SSL_read')[0].products == '产品A\n产品B'
    wb = Workbook()
    compat.write_sheet(wb, ['SSL_read'])
    assert wb['CCA Compatibility']['B2'].value == 8
    codebook = Path(compat.export_codes(tmp_path / 'report.xlsx'))
    assert codebook.read_text(encoding='utf-8').splitlines() == [
        'Code\tConclusion', '2\t无感知', '8\t需要适配',
    ]
    wb.close()


def test_json_attributes_reach_report_without_becoming_formulas(tmp_path):
    compat = CCACompat(hidden=True)
    compat.load(_json(tmp_path, _data()))
    report = tmp_path / 'report.xlsx'
    wb = Workbook()
    wb.active.append(['OpenSSL Symbol', 'Category'])
    wb.active.append(['SSL_read', 'ssl_core'])
    wb.active.append(['SSL_new', 'CUSTOM'])
    wb.active.append(['SSL_free', 'ssl_core'])
    wb.save(report)
    wb.close()
    output = tmp_path / 'output.xlsx'

    assert annotate_workbook(report, output, compat) == 2
    wb = load_workbook(output)
    ws = wb['CCA Compatibility']
    assert list(ws.values) == [
        ('OpenSSL接口', 'CCA兼容性情况', '匹配状态', '来源sheet', '来源行', '使用产品', '使用场景'),
        ('SSL_free', None, '未匹配', None, None, None, None),
        ('SSL_read', 8, '已匹配', 'TLS', 3, '产品A\n产品B', '=literal'),
    ]
    assert ws['G3'].data_type == 's'
    wb.close()


@pytest.mark.parametrize('change', [
    {'schema_version': 2},
    {'schema_version': True},
    {'interfaces': {}},
    {'conclusions': [{'code': 0, 'text': '需要适配'}]},
    {'conclusions': [{'code': 1, 'text': '需要适配'}, {'code': 1, 'text': '无感知'}]},
    {'conclusions': [{'code': 1, 'text': '需要适配'}, {'code': 2, 'text': '需要适配'}]},
    {'conclusions': []},
    {'interfaces': [{'symbol': 'SSL_new'}]},
])
def test_invalid_json_is_rejected_without_replacing_loaded_mapping(tmp_path, change):
    compat = CCACompat()
    compat.load(_json(tmp_path, _data()))
    data = deepcopy(_data())
    data.update(change)
    with pytest.raises(ValueError, match='CCA JSON'):
        compat.load(_json(tmp_path, data))
    assert compat.symbols == {'SSL_new', 'SSL_read'}


def test_import_extracts_requested_fields_from_all_sheets(tmp_path):
    from openssl_scanner.cca_import import convert_workbook

    source = tmp_path / 'input.xlsx'
    wb = Workbook()
    ws = wb.active
    ws.title = 'TLS'
    ws.append(['TLS 评估'])
    ws.append(['OpenSSL API', 'CCA兼容性情况', '使用产品', '使用场景', '备注'])
    ws.append(['SSL_new / SSL_free', '接口一致无感知', '产品A\n产品B', '建立连接', '忽略'])
    ws.append(['int SSL_read(SSL *s, void *buf, int n)', '需要适配', None, '数据收发'])
    ws = wb.create_sheet('摘要')
    ws.append(['使用场景', '兼容性结论', 'OpenSSL接口', '使用产品'])
    ws.append(['数据收发', '不支持', 'SSL_read', '产品C'])
    ws.append(['摘要计算', None, 'EVP_sha256', None])
    wb.create_sheet('说明').append(['说明文字'])
    wb.save(source)
    wb.close()
    original = source.read_bytes()
    output = tmp_path / 'nested' / 'cca_compat.json'

    assert convert_workbook(source, output) == 4
    assert source.read_bytes() == original
    data = json.loads(output.read_text(encoding='utf-8'))
    assert data['schema_version'] == 1
    assert data['source_file'] == 'input.xlsx'
    assert data['conclusions'] == [
        {'code': 1, 'text': '接口一致无感知'},
        {'code': 2, 'text': '需要适配'},
        {'code': 3, 'text': '不支持'},
    ]
    assert data['interfaces'][0] == {
        'symbol': 'SSL_new', 'compatibility': '接口一致无感知',
        'sheet': 'TLS', 'row': 3,
        'products': '产品A\n产品B', 'scenarios': '建立连接',
    }
    compat = CCACompat()
    assert compat.load(output) == 4
    assert [entry.conclusion for entry in compat.lookup('SSL_read')] == ['需要适配', '不支持']
    assert compat.lookup('SSL_read')[0].products is None
    assert compat.lookup('SSL_read')[0].scenarios == '数据收发'
    assert compat.lookup('EVP_sha256')[0].conclusion is None


def test_import_script_runs_outside_repository(tmp_path):
    source = tmp_path / 'input.xlsx'
    wb = Workbook()
    wb.active.append(['OpenSSL API', 'Compatibility Conclusion'])
    wb.active.append(['SSL_new', '接口一致无感知'])
    wb.save(source)
    wb.close()
    script = Path(__file__).resolve().parents[1] / 'import_cca.py'
    output = tmp_path / 'cca_compat.json'
    result = subprocess.run(
        [sys.executable, str(script), str(source), '-o', str(output)],
        cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert CCACompat().load(output) == 1


def test_bad_import_keeps_existing_json(tmp_path):
    from openssl_scanner.cca_import import convert_workbook

    output = _json(tmp_path, _data())
    original = output.read_bytes()
    source = tmp_path / 'input.xlsx'
    wb = Workbook()
    wb.active.append(['名称', '备注'])
    wb.active.append(['SSL_new', 'text'])
    wb.save(source)
    wb.close()
    with pytest.raises(ValueError, match='OpenSSL.*兼容性'):
        convert_workbook(source, output)
    assert output.read_bytes() == original


def test_missing_json_does_not_fall_back_to_excel(tmp_path, monkeypatch):
    from openssl_scanner.__main__ import main

    path = tmp_path / 'cca_compat.json'
    monkeypatch.setattr('openssl_scanner.cca_compat.DEFAULT_CCA_PATH', path)
    report = tmp_path / 'report.xlsx'
    wb = Workbook()
    wb.active.append(['OpenSSL API', 'Compatibility Conclusion'])
    wb.active.append(['SSL_new', '无感知'])
    wb.save(report)
    wb.close()
    output = tmp_path / 'output.xlsx'
    assert main(['cca-compat', str(report), '-o', str(output)]) == 1
    assert not output.exists()


@pytest.mark.parametrize('hidden', [False, True])
def test_source_scan_preserves_usage_fields(tmp_path, monkeypatch, hidden):
    from openssl_scanner.__main__ import main

    mapping = _json(tmp_path, _data())
    monkeypatch.setattr('openssl_scanner.cca_compat.DEFAULT_CCA_PATH', mapping)
    source = tmp_path / 'source.c'
    source.write_text('void f() { SSL_read(0, 0, 0); }\n')
    report = tmp_path / 'report.xlsx'
    assert main(['source', str(source), '-o', str(report), '-j', '1']
                + (['--hidden'] if hidden else [])) == 0
    wb = load_workbook(report)
    assert list(wb['CCA Compatibility'].values)[1] == (
        'SSL_read', 8 if hidden else '需要适配', '已匹配', 'TLS', 3,
        '产品A\n产品B', '=literal',
    )
    wb.close()


@pytest.mark.parametrize('directory_output', [False, True])
def test_source_companion_json_cannot_overwrite_cca_data(tmp_path, monkeypatch, directory_output):
    from openssl_scanner.__main__ import main

    mapping = _json(tmp_path, _data())
    original = mapping.read_bytes()
    monkeypatch.setattr('openssl_scanner.cca_compat.DEFAULT_CCA_PATH', mapping)
    source = tmp_path / 'cca_compat'
    source.mkdir()
    (source / 'a.c').write_text('void f() { SSL_read(0, 0, 0); }\n')
    report = mapping.with_suffix('.xlsx')
    output = tmp_path if directory_output else report
    assert main(['source', str(source), '-o', str(output), '-j', '1']) == 1
    assert mapping.read_bytes() == original
    assert not report.exists()


@pytest.mark.parametrize('json_only', [False, True])
def test_combo_project_json_cannot_overwrite_cca_data(tmp_path, monkeypatch, json_only):
    from openssl_scanner.__main__ import main

    mapping = _json(tmp_path, _data())
    original = mapping.read_bytes()
    monkeypatch.setattr('openssl_scanner.cca_compat.DEFAULT_CCA_PATH', mapping)
    root = tmp_path / 'src'
    for name in ('cca_compat', 'other'):
        project = root / name
        project.mkdir(parents=True)
        (project / 'a.c').write_text('void f() { SSL_read(0, 0, 0); }\n')
    assert main(['combo-scan', str(root), '-o', str(tmp_path), '-j', '1']
                + (['--json-only'] if json_only else [])) == 1
    assert mapping.read_bytes() == original
