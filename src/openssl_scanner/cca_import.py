"""Convert CCA workbook tables to the scanner's JSON format."""

import argparse
import json
import logging
import os

from .cca_compat import DEFAULT_CCA_PATH, _CONCLUSION_HEADERS, _SYMBOL_HEADERS, _header, _symbols

logger = logging.getLogger(__name__)

_PRODUCT_HEADERS = {'使用产品', '产品', '产品名称', 'product', 'products'}
_SCENARIO_HEADERS = {'使用场景', '应用场景', '场景', 'scenario', 'scenarios', 'usagescenario'}


def _text(value):
    if value is None:
        return None
    return str(value).strip() or None


def convert_workbook(input_path, output_path=DEFAULT_CCA_PATH) -> int:
    """Extract every table; retain duplicate interfaces and blank fields."""
    from . import _vendor  # noqa: F401
    from openpyxl import load_workbook

    if os.path.splitext(os.fspath(input_path))[1].lower() != '.xlsx':
        raise ValueError('CCA input must be an XLSX workbook')
    if os.path.realpath(input_path) == os.path.realpath(output_path):
        raise ValueError('CCA JSON output must differ from the source workbook')
    if os.path.splitext(os.fspath(output_path))[1].lower() != '.json':
        raise ValueError('CCA output must be JSON')

    entries = []
    codes = {}
    has_content = has_table = False
    with open(input_path, 'rb') as source:
        wb = load_workbook(source, read_only=True, data_only=True)
        try:
            for ws in wb.worksheets:
                columns = None
                for row_num, row in enumerate(ws.iter_rows(values_only=True), 1):
                    has_content |= any(_text(value) is not None for value in row)
                    headers = [_header(value) for value in row]
                    found = [next((i for i, h in enumerate(headers) if h in aliases), None)
                             for aliases in (_SYMBOL_HEADERS, _CONCLUSION_HEADERS,
                                             _PRODUCT_HEADERS, _SCENARIO_HEADERS)]
                    if found[0] is not None and found[1] is not None:
                        columns = found
                        has_table = True
                        continue
                    if columns is None:
                        continue
                    values = [_text(row[i]) if i is not None and i < len(row) else None
                              for i in columns]
                    value, conclusion, products, scenarios = values
                    if value is None:
                        continue
                    symbols = _symbols(value)
                    if not symbols:
                        logger.warning('Unrecognized OpenSSL interface at %s:%d', ws.title, row_num)
                        continue
                    if conclusion is not None and conclusion not in codes:
                        codes[conclusion] = len(codes) + 1
                    for symbol in symbols:
                        entries.append({
                            'symbol': symbol, 'compatibility': conclusion,
                            'products': products, 'scenarios': scenarios,
                            'sheet': ws.title, 'row': row_num,
                        })
                if columns is None:
                    logger.debug('No CCA table headers in sheet %s', ws.title)
        finally:
            wb.close()

    if not entries and has_content and not has_table:
        raise ValueError('未找到 OpenSSL 接口和兼容性结论数据；请检查表头')
    data = {
        'schema_version': 1,
        'source_file': os.path.basename(input_path),
        'conclusions': [{'code': code, 'text': text} for text, code in codes.items()],
        'interfaces': entries,
    }
    content = json.dumps(data, ensure_ascii=False, indent=2) + '\n'
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as output:
        output.write(content)
    return len({entry['symbol'] for entry in entries})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Import CCA compatibility and usage fields from Excel')
    parser.add_argument('workbook', nargs='?', default=os.path.splitext(DEFAULT_CCA_PATH)[0] + '.xlsx',
                        help='Input XLSX (default: cca_compat.xlsx beside scan)')
    parser.add_argument('-o', '--output', default=DEFAULT_CCA_PATH,
                        help='Output JSON (default: cca_compat.json beside scan)')
    args = parser.parse_args(argv)
    try:
        count = convert_workbook(args.workbook, args.output)
    except Exception as exc:
        parser.exit(1, f'CCA import failed: {exc}\n')
    print(f'Imported {count} CCA interfaces -> {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
