"""Load CCA interface data from JSON and append comparison reports."""

import csv
import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

DEFAULT_CCA_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'cca_compat.json'))
CCA_SHEET_NAME = 'CCA Compatibility'
_CCA_SHEET_NAMES = (CCA_SHEET_NAME, 'cca兼容性')

_SYMBOL_HEADERS = {
    "openssl接口", "openssl接口名", "openssl接口名称", "openssl函数",
    "openssl函数名", "opensslapi", "opensslapiname", "opensslsymbol",
    "接口", "接口名", "接口名称", "函数名", "函数名称",
}
_CONCLUSION_HEADERS = {
    "cca兼容性情况", "兼容性情况",
    "cca兼容性结论", "兼容性结论", "兼容性分析结论", "cca兼容性",
    "兼容性", "结论", "compatibilityconclusion", "ccacompatibility",
}


@dataclass(frozen=True)
class CCAEntry:
    symbol: str
    conclusion: Optional[str]
    sheet: str
    row: int
    products: Optional[str] = None
    scenarios: Optional[str] = None


def _header(value) -> str:
    return re.sub(r"[\s_\-]+", "", str(value or "")).lower()


def is_custom_category(category) -> bool:
    return str(category or '').strip().upper() in {'CUSTOM', 'SELF'}


def codebook_path(report_path) -> str:
    return os.path.splitext(os.fspath(report_path))[0] + '_cca_codes.txt'


def _symbols(value) -> List[str]:
    text = str(value).strip()
    parts = []
    start = depth = 0
    for index, char in enumerate(text):
        if char == '(':
            depth += 1
        elif char == ')':
            depth = max(0, depth - 1)
        elif depth == 0 and char in ',，;；/、\n\r':
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    symbols = []
    for part in parts:
        function = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", part)
        if function:
            symbols.append(function.group(1))
        else:
            tokens = part.split()
            if all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token) for token in tokens):
                symbols.extend(tokens)
    return list(dict.fromkeys(symbols))


class CCACompat:
    """Keep compatibility, usage fields and source locations."""

    def __init__(self, hidden: bool = False) -> None:
        self._mapping: Dict[str, List[CCAEntry]] = {}
        self._codes: Dict[str, int] = {}
        self.hidden = hidden

    @property
    def symbols(self) -> Set[str]:
        return set(self._mapping)

    def lookup(self, symbol: str) -> List[CCAEntry]:
        return list(self._mapping.get(symbol, []))

    def load(self, path) -> int:
        def invalid(message):
            raise ValueError(f'Invalid CCA JSON {path}: {message}')

        try:
            with open(path, encoding='utf-8-sig') as source:
                data = json.load(source)
        except ValueError as exc:
            invalid(str(exc))

        if (not isinstance(data, dict) or type(data.get('schema_version')) is not int
                or data['schema_version'] != 1):
            invalid('schema_version must be 1')
        if not isinstance(data.get('conclusions'), list):
            invalid('conclusions must be a list')
        if not isinstance(data.get('interfaces'), list):
            invalid('interfaces must be a list')

        mapping: Dict[str, List[CCAEntry]] = {}
        codes: Dict[str, int] = {}
        used_codes = set()
        for index, item in enumerate(data['conclusions']):
            if not isinstance(item, dict):
                invalid(f'conclusions[{index}] must be an object')
            code, text = item.get('code'), item.get('text')
            if type(code) is not int or code < 1 or code in used_codes:
                invalid(f'conclusions[{index}].code must be a unique positive integer')
            if not isinstance(text, str) or not text.strip() or text in codes:
                invalid(f'conclusions[{index}].text must be unique nonempty text')
            codes[text] = code
            used_codes.add(code)

        for index, item in enumerate(data['interfaces']):
            if not isinstance(item, dict):
                invalid(f'interfaces[{index}] must be an object')
            symbol = item.get('symbol')
            if not isinstance(symbol, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', symbol):
                invalid(f'interfaces[{index}].symbol must be an API name')
            for name in ('compatibility', 'products', 'scenarios'):
                if name not in item or (item[name] is not None and not isinstance(item[name], str)):
                    invalid(f'interfaces[{index}].{name} must be text or null')
            conclusion = item['compatibility']
            if conclusion is not None and conclusion not in codes:
                invalid(f'interfaces[{index}].compatibility has no conclusion code')
            sheet, row = item.get('sheet'), item.get('row')
            if not isinstance(sheet, str) or not sheet.strip() or type(row) is not int or row < 1:
                invalid(f'interfaces[{index}] must have a source sheet and positive row')
            mapping.setdefault(symbol, []).append(CCAEntry(
                symbol, conclusion, sheet, row, item['products'], item['scenarios']))

        self._mapping = mapping
        self._codes = dict(sorted(codes.items(), key=lambda item: item[1]))
        logger.info("Loaded %d CCA interfaces from %s", len(mapping), path)
        return len(mapping)

    def export_codes(self, report_path) -> str:
        path = codebook_path(report_path)
        with open(path, 'w', encoding='utf-8', newline='') as output:
            writer = csv.writer(output, delimiter='\t', lineterminator='\n')
            writer.writerow(['Code', 'Conclusion'])
            for conclusion, code in self._codes.items():
                writer.writerow([code, conclusion])
        logger.info("CCA codebook saved to: %s", path)
        return path

    def write_sheet(self, wb, symbols, excluded_symbols=()) -> None:
        from openpyxl.styles import Alignment, Font, PatternFill

        for title in _CCA_SHEET_NAMES:
            if title in wb.sheetnames:
                del wb[title]
        ws = wb.create_sheet(CCA_SHEET_NAME)
        ws.append(["OpenSSL接口", "CCA兼容性情况", "匹配状态", "来源sheet", "来源行",
                   "使用产品", "使用场景"])
        for cell, width in zip(ws[1], (40, 60, 16, 30, 12, 30, 60)):
            cell.font = Font(bold=True)
            cell.fill = PatternFill("solid", fgColor="E8F4FC")
            ws.column_dimensions[cell.column_letter].width = width
        row_index = 2
        for symbol in sorted(set(symbols) - set(excluded_symbols)):
            entries = self.lookup(symbol)
            if not entries:
                ws.append([symbol, None, "未匹配", None, None])
                row_index += 1
                continue
            conclusions = {e.conclusion for e in entries if e.conclusion is not None}
            for entry in entries:
                conclusion = entry.conclusion
                status = "已匹配"
                if conclusion is None:
                    status = "结论为空"
                elif len(conclusions) > 1:
                    status = "结论冲突"
                if self.hidden and conclusion is not None:
                    conclusion = self._codes[conclusion]
                ws.append([symbol, conclusion, status, entry.sheet, entry.row,
                           entry.products, entry.scenarios])
                for column in (2, 4, 6, 7):
                    cell = ws.cell(row_index, column)
                    if isinstance(cell.value, str):
                        cell.data_type = "s"
                    cell.alignment = Alignment(wrap_text=True, vertical="top")
                row_index += 1
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions


def annotate_workbook(input_path, output_path, compat: CCACompat) -> int:
    """Append conclusions for interfaces found in an existing workbook."""
    from . import _vendor  # noqa: F401
    from openpyxl import load_workbook

    if os.path.splitext(str(input_path))[1].lower() != '.xlsx':
        raise ValueError('Input report must be an XLSX workbook')
    if os.path.splitext(str(output_path))[1].lower() != '.xlsx':
        raise ValueError('Output report must be an XLSX workbook')
    with open(input_path, 'rb') as source:
        wb = load_workbook(source)
    try:
        symbols: Set[str] = set()
        excluded_symbols: Set[str] = set()
        for ws in wb.worksheets:
            if ws.title in _CCA_SHEET_NAMES:
                continue
            column = None
            category_column = None
            for row in ws.iter_rows(values_only=True):
                headers = [_header(value) for value in row]
                found = next((i for i, h in enumerate(headers)
                              if h in _SYMBOL_HEADERS or h == 'symbol'), None)
                if found is not None:
                    column = found
                    category_column = next((i for i, h in enumerate(headers)
                                            if h in {'category', '分类', '类别', '接口分类'}), None)
                    continue
                if column is not None and column < len(row) and row[column] is not None:
                    row_symbols = _symbols(row[column])
                    symbols.update(row_symbols)
                    if (category_column is not None and category_column < len(row)
                            and is_custom_category(row[category_column])):
                        excluded_symbols.update(row_symbols)
        if not symbols:
            raise ValueError('未找到 OpenSSL 接口列中的接口')
        compat.write_sheet(wb, symbols, excluded_symbols=excluded_symbols)
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        wb.save(output_path)
        compat.export_codes(output_path)
        return len(symbols - excluded_symbols)
    finally:
        wb.close()
