"""CCA reports using JSON imported from Excel workbooks."""

import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from openssl_scanner import _vendor  # noqa: F401
from openpyxl import Workbook, load_workbook

from openssl_scanner.cca_compat import CCACompat
from openssl_scanner.cca_import import convert_workbook


@pytest.fixture(autouse=True)
def bundled_cca_path(tmp_path, monkeypatch):
    path = tmp_path / 'cca_compat.json'
    monkeypatch.setattr('openssl_scanner.cca_compat.DEFAULT_CCA_PATH', path,
                        raising=False)
    return path


def _workbook(tmp_path, sheets):
    wb = Workbook()
    wb.remove(wb.active)
    for name, rows in sheets.items():
        ws = wb.create_sheet(name)
        for row in rows:
            ws.append(row)
    path = tmp_path / "cca_compat.xlsx"
    wb.save(path)
    wb.close()
    convert_workbook(path, path.with_suffix('.json'))
    return path


def test_load_all_sheets_with_different_headers(tmp_path):
    path = _workbook(tmp_path, {
        "说明": [["兼容性测试结果"]],
        "TLS": [
            ["TLS 接口评估"],
            ["序号", "OpenSSL 接口", "兼容性结论"],
            [1, "SSL_new", "接口一致无感知"],
        ],
        "摘要": [
            ["结论", "OpenSSL API"],
            ["需要适配", "EVP_DigestInit_ex()"],
        ],
    })
    compat = CCACompat()

    assert compat.load(path.with_suffix('.json')) == 2
    assert compat.lookup("SSL_new")[0].conclusion == "接口一致无感知"
    entry = compat.lookup("EVP_DigestInit_ex")[0]
    assert (entry.conclusion, entry.sheet, entry.row) == ("需要适配", "摘要", 2)
    assert compat.lookup("SSL_free") == []


def test_keep_conflicting_conclusions_and_sources(tmp_path):
    path = _workbook(tmp_path, {
        "A": [["OpenSSL接口", "兼容性结论"], ["SSL_new", "结论甲"]],
        "B": [["OpenSSL接口", "兼容性结论"], ["SSL_new", "结论乙"]],
    })
    compat = CCACompat()

    assert compat.load(path.with_suffix('.json')) == 1
    assert [(entry.conclusion, entry.sheet) for entry in compat.lookup("SSL_new")] == [
        ("结论甲", "A"), ("结论乙", "B"),
    ]


def test_blank_conclusions_are_not_inferred(tmp_path):
    path = _workbook(tmp_path, {
        "API": [
            ["OpenSSL接口", "兼容性结论"],
            ["SSL_new", "接口一致无感知"],
            ["SSL_free", None],
            [None, "需要适配"],
        ],
    })
    compat = CCACompat()
    compat.load(path.with_suffix('.json'))

    assert compat.lookup("SSL_free")[0].conclusion is None
    assert set(compat.symbols) == {"SSL_new", "SSL_free"}


def test_api_lists_and_prototypes_do_not_add_parameter_names(tmp_path):
    path = _workbook(tmp_path, {
        "API": [
            ["OpenSSL接口", "兼容性结论"],
            ["SSL_new\nSSL_free()", "结论甲"],
            ["int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void));", "结论乙"],
        ],
    })
    compat = CCACompat()
    compat.load(path.with_suffix('.json'))

    assert compat.symbols == {"SSL_new", "SSL_free", "CRYPTO_THREAD_run_once"}


def test_workbook_without_matching_columns_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="OpenSSL.*兼容性"):
        _workbook(tmp_path, {"Notes": [["名称", "备注"], ["SSL_new", "text"]]})


@pytest.mark.parametrize("hidden", [False, True])
def test_write_sheet_includes_missing_and_conflicting_results(tmp_path, hidden):
    path = _workbook(tmp_path, {
        "A": [
            ["OpenSSL接口", "兼容性结论"],
            ["SSL_new", "接口一致无感知"],
            ["SSL_read", "需要适配"],
            ["SSL_free", None],
        ],
        "B": [["OpenSSL接口", "兼容性结论"], ["SSL_read", "不支持"]],
    })
    compat = CCACompat(hidden=hidden)
    compat.load(path.with_suffix('.json'))
    wb = Workbook()
    wb.active["A1"] = "original"

    compat.write_sheet(wb, {"SSL_read", "SSL_free", "SSL_unknown"})

    assert wb.active["A1"].value == "original"
    rows = [row[:5] for row in wb["CCA Compatibility"].iter_rows(min_row=2, values_only=True)]
    assert rows == [
        ("SSL_free", None, "结论为空", "A", 4),
        ("SSL_read", 2 if hidden else "需要适配", "结论冲突", "A", 3),
        ("SSL_read", 3 if hidden else "不支持", "结论冲突", "B", 2),
        ("SSL_unknown", None, "未匹配", None, None),
    ]
    assert wb["CCA Compatibility"].sheet_state == "visible"


def test_hidden_codes_cover_all_six_conclusions(tmp_path):
    path = _workbook(tmp_path, {
        "API": [["OpenSSL接口", "兼容性结论"]]
        + [[f"API_{i}", f"结论{i}"] for i in range(1, 7)],
    })
    compat = CCACompat(hidden=True)
    compat.load(path.with_suffix('.json'))
    wb = Workbook()

    compat.write_sheet(wb, compat.symbols)

    assert [row[1] for row in wb["CCA Compatibility"].iter_rows(min_row=2, values_only=True)] == list(range(1, 7))


def test_hidden_supports_more_than_six_conclusions(tmp_path):
    path = _workbook(tmp_path, {
        "API": [["OpenSSL接口", "兼容性结论"]]
        + [[f"API_{i}", f"结论{i}"] for i in range(1, 13)],
    })
    compat = CCACompat(hidden=True)
    assert compat.load(path.with_suffix('.json')) == 12
    wb = Workbook()
    compat.write_sheet(wb, compat.symbols)
    codes = {row[0]: row[1] for row in wb['CCA Compatibility'].iter_rows(
        min_row=2, values_only=True)}
    assert codes == {f'API_{i}': i for i in range(1, 13)}


def _cca_rows(path):
    wb = load_workbook(path, read_only=True)
    try:
        return [row[:5] for row in wb['CCA Compatibility'].iter_rows(min_row=2, values_only=True)]
    finally:
        wb.close()


def _code_rows(report_path):
    path = report_path.with_name(report_path.stem + '_cca_codes.txt')
    with path.open(encoding='utf-8', newline='') as source:
        reader = csv.DictReader(source, delimiter='\t')
        assert reader.fieldnames == ['Code', 'Conclusion']
        return {int(row['Code']): row['Conclusion'] for row in reader}


@pytest.mark.parametrize("hidden", [False, True])
def test_cli_summarizes_workbook_without_changing_input(tmp_path, hidden):
    from openssl_scanner.__main__ import main

    path = _workbook(tmp_path, {
        "TLS": [["OpenSSL接口", "兼容性结论"], ["SSL_new", "接口一致无感知"]],
        "摘要": [["OpenSSL API", "结论"], ["EVP_sha256", "需要适配"]],
    })
    original = path.read_bytes()
    output = tmp_path / "output.xlsx"

    assert main(['cca-compat', str(path), '-o', str(output)]
                + (['--hidden'] if hidden else [])) == 0

    assert path.read_bytes() == original
    assert _cca_rows(output) == [
        ("EVP_sha256", 2 if hidden else "需要适配", "已匹配", "摘要", 2),
        ("SSL_new", 1 if hidden else "接口一致无感知", "已匹配", "TLS", 2),
    ]
    wb = load_workbook(output)
    assert wb.sheetnames == ['TLS', '摘要', 'CCA Compatibility']
    assert wb['TLS']['B2'].value == '接口一致无感知'
    wb.close()


@pytest.mark.parametrize('hidden', [False, True])
def test_cli_scan_and_merge_match_only_used_interfaces(tmp_path, hidden):
    from openssl_scanner.__main__ import main

    _workbook(tmp_path, {
        "TLS": [["OpenSSL接口", "兼容性结论"], ["SSL_new", "接口一致无感知"]],
        "摘要": [["OpenSSL API", "结论"], ["EVP_sha256", "需要适配"]],
    })
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'a.c').write_text('void f() { SSL_new(0); SSL_free(0); }\n')
    report = tmp_path / 'scan.xlsx'
    flags = ['--hidden'] if hidden else []

    assert main(['source', str(src), '-j', '1', '-o', str(report)] + flags) == 0
    rows = _cca_rows(report)
    assert rows == [
        ('SSL_free', None, '未匹配', None, None),
        ('SSL_new', 1 if hidden else '接口一致无感知', '已匹配', 'TLS', 2),
    ]
    assert _code_rows(report) == {1: '接口一致无感知', 2: '需要适配'}

    merged = tmp_path / 'merged.xlsx'
    assert main(['source-merge', str(report), '-o', str(merged)] + flags) == 0
    assert _cca_rows(merged) == rows
    assert _code_rows(merged) == _code_rows(report)


def test_cli_existing_report_uses_bundled_mapping(tmp_path):
    from openssl_scanner.__main__ import main

    _workbook(tmp_path, {
        "TLS": [["OpenSSL接口", "兼容性结论"], ["SSL_new", "接口一致无感知"]],
    })
    report = tmp_path / 'report.xlsx'
    wb = Workbook()
    wb.active.append(['OpenSSL Symbol'])
    wb.active.append(['SSL_new'])
    ws = wb.create_sheet('more')
    ws.append(['Symbol'])
    ws.append(['SSL_free'])
    ws = wb.create_sheet('cca兼容性')
    ws.append(['OpenSSL接口', '兼容性结论'])
    ws.append(['OLD_symbol', '旧结论'])
    ws = wb.create_sheet('CCA Compatibility')
    ws.append(['OpenSSL接口', '兼容性结论'])
    ws.append(['STALE_symbol', '旧结论'])
    wb.save(report)
    wb.close()
    output = tmp_path / 'output.xlsx'

    assert main(['cca-compat', str(report), '--hidden', '-o', str(output)]) == 0

    assert [row[:3] for row in _cca_rows(output)] == [
        ('SSL_free', None, '未匹配'), ('SSL_new', 1, '已匹配'),
    ]
    wb = load_workbook(output)
    assert 'cca兼容性' not in wb.sheetnames
    assert wb.sheetnames.count('CCA Compatibility') == 1
    wb.close()


def test_cli_binary_report_export_adds_cca_sheet(tmp_path):
    from openssl_scanner.__main__ import main
    from tests.test_exporter import _make_single_report

    _workbook(tmp_path, {
        "TLS": [["OpenSSL接口", "兼容性结论"], ["SSL_connect", "接口一致无感知"]],
    })
    report = tmp_path / 'report.json'
    report.write_text(json.dumps(_make_single_report()))
    output = tmp_path / 'output.xlsx'

    assert main(['export', str(report), '-o', str(output), '--hidden']) == 0

    assert [row[:3] for row in _cca_rows(output)] == [
        ('BIO_new', None, '未匹配'),
        ('EVP_sha256', None, '未匹配'),
        ('SSL_connect', 1, '已匹配'),
    ]
    assert _code_rows(output) == {1: '接口一致无感知'}


@pytest.mark.parametrize('hidden', [False, True])
def test_source_and_merges_exclude_custom_interfaces(tmp_path, hidden):
    from openssl_scanner.__main__ import main
    from openssl_scanner.source_exporter import SourceMergeExporter

    mapping = _workbook(tmp_path, {
        'TLS': [['OpenSSL接口', '兼容性结论'],
                ['SSL_new', '接口一致无感知'], ['SSL_free', '需要适配'],
                ['VENDOR_known', '接口一致无感知']],
    })
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'a.c').write_text(
        'void f() { SSL_new(0); SSL_free(0); VENDOR_known(); VENDOR_missing(); }\n')
    interfaces = tmp_path / 'custom.txt'
    interfaces.write_text('SSL_new\nVENDOR_known\nVENDOR_missing\n')
    report = tmp_path / 'report.xlsx'
    flags = ['--hidden'] if hidden else []

    assert main(['source', str(src), '-j', '1', '--add', str(interfaces),
                 '-o', str(report)] + flags) == 0
    expected = [('SSL_free', 2 if hidden else '需要适配', '已匹配', 'TLS', 3)]
    assert _cca_rows(report) == expected
    data = json.loads(report.with_suffix('.json').read_text())
    assert {cs['ossl_symbol'] for cs in data['call_sites']} == {
        'SSL_new', 'SSL_free', 'VENDOR_known', 'VENDOR_missing',
    }
    assert {cs['category'] for cs in data['call_sites']
            if cs['ossl_symbol'] != 'SSL_free'} == {'CUSTOM'}

    merged = tmp_path / 'merged.xlsx'
    assert main(['source-merge', str(report), '-o', str(merged)] + flags) == 0
    assert _cca_rows(merged) == expected

    compat = CCACompat(hidden=hidden)
    compat.load(mapping.with_suffix('.json'))
    SourceMergeExporter().merge_from_json(
        [str(report.with_suffix('.json'))], str(merged), cca_compat=compat)
    assert _cca_rows(merged) == expected


def test_existing_workbook_excludes_only_custom_across_sheets(tmp_path):
    from openssl_scanner.__main__ import main

    _workbook(tmp_path, {
        'TLS': [['OpenSSL接口', '兼容性结论'],
                ['SSL_new', '接口一致无感知'], ['SSL_free', '接口一致无感知'],
                ['SSL_write', '接口一致无感知']],
    })
    report = tmp_path / 'report.xlsx'
    wb = Workbook()
    wb.active.append(['Category', 'OpenSSL Symbol'])
    wb.active.append(['CUSTOM', 'SSL_new'])
    wb.active.append(['ssl_core', 'SSL_free'])
    wb.active.append(['COSTOM', 'SSL_write'])
    summary = wb.create_sheet('Summary')
    summary.append(['OpenSSL Symbol'])
    summary.append(['SSL_new'])
    wb.save(report)
    wb.close()
    output = tmp_path / 'output.xlsx'

    assert main(['cca-compat', str(report), '-o', str(output)]) == 0
    assert [row[0] for row in _cca_rows(output)] == ['SSL_free', 'SSL_write']


@pytest.mark.parametrize('category', ['CUSTOM', 'SELF', ' self '])
def test_binary_export_excludes_custom_category(tmp_path, category):
    from openssl_scanner.__main__ import main
    from tests.test_exporter import _make_single_report

    _workbook(tmp_path, {
        'TLS': [['OpenSSL接口', '兼容性结论'], ['SSL_connect', '接口一致无感知']],
    })
    data = _make_single_report()
    data['openssl_symbols']['by_category'][category] = {
        'count': 1, 'symbols': ['SSL_connect'],
    }
    report = tmp_path / 'report.json'
    report.write_text(json.dumps(data))
    output = tmp_path / 'output.xlsx'

    assert main(['export', str(report), '-o', str(output), '--hidden']) == 0
    assert [row[0] for row in _cca_rows(output)] == ['BIO_new', 'EVP_sha256']


@pytest.mark.parametrize('hidden', [False, True])
def test_launcher_cca_compat_excludes_custom_and_self(tmp_path, hidden):
    mapping = _workbook(tmp_path, {
        'TLS': [['OpenSSL接口', '兼容性结论']]
        + [[symbol, '接口一致无感知'] for symbol in
           ['SSL_new', 'SSL_free', 'SSL_read', 'SSL_write']],
    })
    report = tmp_path / 'report.xlsx'
    wb = Workbook()
    wb.active.append(['Category', 'OpenSSL Symbol'])
    wb.active.append(['CUSTOM', 'SSL_new'])
    wb.active.append(['SELF', 'SSL_write'])
    wb.active.append([' self ', 'SSL_read'])
    wb.active.append(['SELF', 'VENDOR_missing'])
    wb.active.append(['ssl_core', 'SSL_free'])
    summary = wb.create_sheet('Summary')
    summary.append(['OpenSSL Symbol'])
    for symbol in ['SSL_new', 'SSL_write', 'SSL_read', 'VENDOR_missing']:
        summary.append([symbol])
    wb.save(report)
    wb.close()
    original = report.read_bytes()

    tool_root = tmp_path / 'tool'
    (tool_root / 'src').mkdir(parents=True)
    repo = Path(__file__).resolve().parents[1]
    (tool_root / 'src' / 'openssl_scanner').symlink_to(
        repo / 'src' / 'openssl_scanner', target_is_directory=True)
    shutil.copy2(repo / 'scan', tool_root / 'scan')
    shutil.copy2(mapping.with_suffix('.json'), tool_root / 'cca_compat.json')
    result = subprocess.run(
        [str(tool_root / 'scan'), 'cca-compat', 'report.xlsx', '-o', 'report_cca.xlsx']
        + (['--hidden'] if hidden else []),
        cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert report.read_bytes() == original
    assert _cca_rows(tmp_path / 'report_cca.xlsx') == [
        ('SSL_free', 1 if hidden else '接口一致无感知', '已匹配', 'TLS', 3),
    ]
    assert _code_rows(tmp_path / 'report_cca.xlsx') == {1: '接口一致无感知'}


def test_legacy_self_in_source_export_and_merges(tmp_path):
    from openssl_scanner.source_exporter import (
        SourceExcelExporter, SourceJsonExporter, SourceMergeExporter,
    )
    from tests.test_combo_and_merge import _make_call_site, _make_result

    mapping = _workbook(tmp_path, {
        'TLS': [['OpenSSL接口', '兼容性结论'],
                ['SSL_new', '接口一致无感知'], ['SSL_free', '需要适配']],
    })
    compat = CCACompat(hidden=True)
    compat.load(mapping.with_suffix('.json'))
    result = _make_result(call_sites=[
        _make_call_site(symbol='SSL_new', category='SELF'),
        _make_call_site(symbol='SSL_free', category='ssl_core'),
    ])
    report = tmp_path / 'source.xlsx'
    SourceExcelExporter().export(result, str(report), cca_compat=compat)
    expected = [('SSL_free', 2, '已匹配', 'TLS', 3)]
    assert _cca_rows(report) == expected

    merged = tmp_path / 'merged.xlsx'
    SourceMergeExporter().merge([str(report)], str(merged), cca_compat=compat)
    assert _cca_rows(merged) == expected
    json_path = report.with_suffix('.json')
    SourceJsonExporter().export(result, str(json_path))
    SourceMergeExporter().merge_from_json([str(json_path)], str(merged), cca_compat=compat)
    assert _cca_rows(merged) == expected


@pytest.mark.parametrize('rows', [[], [['OpenSSL API', 'Compatibility Conclusion']]])
def test_empty_workbook_does_not_block_scan(tmp_path, rows):
    from openssl_scanner.__main__ import main

    mapping = _workbook(tmp_path, {'Compatibility Data': rows})
    compat = CCACompat(hidden=True)
    assert compat.load(mapping.with_suffix('.json')) == 0
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'a.c').write_text('void f() { SSL_new(0); }\n')
    output = tmp_path / 'report.xlsx'

    assert main(['source', str(src), '-o', str(output), '-j', '1', '--hidden']) == 0
    assert _cca_rows(output) == [('SSL_new', None, '未匹配', None, None)]
    assert _code_rows(output) == {}


@pytest.mark.parametrize('option', ['no_map', 'json_output', 'json_only', 'overwrite_map'])
def test_cli_rejects_invalid_cca_options_before_scanning(tmp_path, option):
    from openssl_scanner.__main__ import main

    mapping = _workbook(tmp_path, {
        'TLS': [['OpenSSL接口', '兼容性结论'], ['SSL_new', '接口一致无感知']],
    })
    mapping = mapping.with_suffix('.json')
    original = mapping.read_bytes()
    output = tmp_path / ('output.json' if option == 'json_output' else 'output.xlsx')
    if option == 'overwrite_map':
        output = mapping
    args = ['source', str(tmp_path), '-o', str(output), '--hidden']
    if option == 'no_map':
        mapping = mapping.rename(tmp_path / 'unconfigured.json')
    if option == 'json_only':
        args += ['--json-only']

    assert main(args) == 1
    assert mapping.read_bytes() == original
    if output != mapping:
        assert not output.exists()


@pytest.mark.parametrize('hidden', [False, True])
@pytest.mark.parametrize('custom', [False, True])
def test_combo_adds_same_codes_to_project_and_merged_reports(tmp_path, hidden, custom):
    mapping = _workbook(tmp_path, {
        'TLS': [['OpenSSL接口', '兼容性结论'],
                ['SSL_new', '接口一致无感知'], ['SSL_free', '需要适配']],
    })
    root = tmp_path / 'src'
    for project, symbol in [('a', 'SSL_new'), ('b', 'SSL_free')]:
        directory = root / project
        directory.mkdir(parents=True)
        (directory / 'a.c').write_text(f'void f() {{ {symbol}(0); }}\n')
    output = tmp_path / 'reports'

    tool_root = tmp_path / 'tool'
    (tool_root / 'src').mkdir(parents=True)
    package = Path(__file__).resolve().parents[1] / 'src' / 'openssl_scanner'
    (tool_root / 'src' / 'openssl_scanner').symlink_to(package, target_is_directory=True)
    shutil.copy2(mapping.with_suffix('.json'), tool_root / 'cca_compat.json')
    flags = ['--hidden'] if hidden else []
    if custom:
        interfaces = tmp_path / 'custom.txt'
        interfaces.write_text('SSL_new\n')
        flags += ['--add', str(interfaces)]
    result = subprocess.run(
        [sys.executable, '-m', 'openssl_scanner', 'combo-scan', str(root),
         '-o', str(output), '-j', '1'] + flags,
        cwd=tmp_path, env=dict(os.environ, PYTHONPATH=str(tool_root / 'src')),
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr

    workbooks = list(output.glob('*.xlsx'))
    assert len(workbooks) >= 2
    all_symbols = set()
    for workbook in workbooks:
        rows = _cca_rows(workbook)
        assert _code_rows(workbook) == {1: '接口一致无感知', 2: '需要适配'}
        if not custom:
            assert rows
        for symbol, code, status, _, _ in rows:
            all_symbols.add(symbol)
            if custom:
                assert symbol != 'SSL_new'
            expected = ({'SSL_new': 1, 'SSL_free': 2} if hidden else
                        {'SSL_new': '接口一致无感知', 'SSL_free': '需要适配'})
            assert code == expected[symbol]
            assert status == '已匹配'
    assert all_symbols == ({'SSL_free'} if custom else {'SSL_new', 'SSL_free'})


def test_codebook_preserves_all_codes_and_multiline_conclusions(tmp_path):
    from openssl_scanner.__main__ import main

    conclusions = {i: f'结论{i}' for i in range(1, 13)}
    conclusions[5] = '结论含换行\n和制表符\t以及"引号"'
    _workbook(tmp_path, {
        'API': [['OpenSSL API', 'Compatibility Conclusion']]
        + [[f'API_{i}', conclusion] for i, conclusion in conclusions.items()],
    })
    report = tmp_path / 'input.xlsx'
    wb = Workbook()
    wb.active.append(['OpenSSL Symbol'])
    wb.active.append(['API_12'])
    wb.save(report)
    wb.close()
    output = tmp_path / 'report' / 'output.xlsx'

    assert main(['cca-compat', str(report), '-o', str(output), '--hidden']) == 0
    assert _cca_rows(output)[0][1] == 12
    assert _code_rows(output) == conclusions


def test_bundled_mapping_does_not_block_json_output(tmp_path):
    from openssl_scanner.__main__ import main

    _workbook(tmp_path, {
        'TLS': [['OpenSSL接口', '兼容性结论'], ['SSL_new', '接口一致无感知']],
    })
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'a.c').write_text('void f() { SSL_new(0); }\n')
    output = tmp_path / 'report.json'

    assert main(['source', str(src), '-o', str(output), '-j', '1']) == 0
    assert json.loads(output.read_text())['summary']['unique_symbols'] == ['SSL_new']


def test_missing_optional_json_keeps_normal_scan(tmp_path):
    from openssl_scanner.__main__ import main

    src = tmp_path / 'src'
    src.mkdir()
    (src / 'a.c').write_text('void f() { SSL_new(0); }\n')
    output = tmp_path / 'report.xlsx'

    assert main(['source', str(src), '-o', str(output), '-j', '1']) == 0
    wb = load_workbook(output)
    assert 'CCA Compatibility' not in wb.sheetnames
    wb.close()


def test_cca_help_does_not_require_mapping_argument():
    from openssl_scanner.__main__ import create_parser

    parser = create_parser()
    subparsers = next(action for action in parser._actions if action.dest == 'command')
    for name in ('source', 'source-merge', 'combo-scan', 'export', 'cca-compat'):
        help_text = subparsers.choices[name].format_help()
        assert '--hidden' in help_text
        assert '--cca-map' not in help_text
