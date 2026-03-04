"""
Export source scan results to XLSX or JSON.

Single-sheet XLSX with call site details, matching existing exporter styling.
Multi-sheet merge: combine multiple XLSX reports into one workbook.
"""

import json
import logging
import os
from typing import Dict, List, Optional, Tuple

from .source_analyzer import SourceScanResult

logger = logging.getLogger(__name__)

COLUMNS = [
    ('file_path',         60, 'File Path'),
    ('file_name',         25, 'File Name'),
    ('caller_function',   30, 'Caller Function'),
    ('line_number',       12, 'Line'),
    ('ossl_symbol',       35, 'OpenSSL Symbol'),
    ('category',          20, 'Category'),
    ('call_args',         60, 'Call Arguments'),
    ('detection_method',  12, 'Detection'),
]

LAST_COL_LETTER = chr(64 + len(COLUMNS))


SUMMARY_SHEET_COLUMNS = [
    ('ossl_symbol',  35, 'OpenSSL Symbol'),
    ('category',     20, 'Category'),
    ('call_count',   12, 'Calls'),
    ('file_count',   12, 'Files'),
    ('file_list',    80, 'File List'),
]

MERGE_SUMMARY_SHEET_COLUMNS = [
    ('ossl_symbol',    35, 'OpenSSL Symbol'),
    ('category',       20, 'Category'),
    ('call_count',     12, 'Calls'),
    ('file_count',     12, 'Files'),
    ('file_list',      80, 'File List'),
    ('project_count',  12, 'Projects'),
    ('project_list',   40, 'Project List'),
]


class SourceExcelExporter:
    """Export SourceScanResult to XLSX with call sites and symbol summary."""

    def export(self, result: SourceScanResult, output_path: str) -> None:
        from . import _vendor  # noqa: F401
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill

        wb = Workbook()
        ws = wb.active
        ws.title = "OpenSSL Call Sites"

        header_font = Font(bold=True)
        header_fill = PatternFill(
            start_color="E8F4FC", end_color="E8F4FC", fill_type="solid"
        )

        for col_idx, (_, width, title) in enumerate(COLUMNS, 1):
            cell = ws.cell(row=1, column=col_idx, value=title)
            cell.font = header_font
            cell.fill = header_fill
            ws.column_dimensions[
                chr(64 + col_idx) if col_idx <= 26
                else 'A' + chr(64 + col_idx - 26)
            ].width = width

        for row_idx, cs in enumerate(result.call_sites, 2):
            ws.cell(row=row_idx, column=1, value=cs.file_path)
            ws.cell(row=row_idx, column=2, value=cs.file_name)
            ws.cell(row=row_idx, column=3, value=cs.caller_function)
            ws.cell(row=row_idx, column=4, value=cs.line_number)
            ws.cell(row=row_idx, column=5, value=cs.ossl_symbol)
            ws.cell(row=row_idx, column=6, value=cs.category)
            ws.cell(row=row_idx, column=7, value=cs.call_args)
            ws.cell(row=row_idx, column=8,
                    value=getattr(cs, 'detection_method', 'dynamic-link'))

        if result.call_sites:
            last_row = len(result.call_sites) + 1
            ws.auto_filter.ref = f"A1:{LAST_COL_LETTER}{last_row}"

        self._write_symbol_summary(wb, result, header_font, header_fill)

        wb.save(output_path)
        logger.info("XLSX report saved to: %s", output_path)

    def _write_symbol_summary(self, wb, result: SourceScanResult,
                              header_font, header_fill) -> None:
        """Write Symbol Summary sheet: one row per unique symbol."""
        ws = wb.create_sheet(title="Symbol Summary")

        for col_idx, (_, width, title) in enumerate(SUMMARY_SHEET_COLUMNS, 1):
            cell = ws.cell(row=1, column=col_idx, value=title)
            cell.font = header_font
            cell.fill = header_fill
            ws.column_dimensions[
                chr(64 + col_idx) if col_idx <= 26
                else 'A' + chr(64 + col_idx - 26)
            ].width = width

        sym_data: Dict[str, Dict] = {}
        for cs in result.call_sites:
            if cs.ossl_symbol not in sym_data:
                sym_data[cs.ossl_symbol] = {
                    'category': cs.category,
                    'calls': 0,
                    'files': set(),
                }
            sym_data[cs.ossl_symbol]['calls'] += 1
            sym_data[cs.ossl_symbol]['files'].add(cs.file_name)

        rows = sorted(sym_data.items(),
                       key=lambda x: (x[1]['category'], x[0]))

        for row_idx, (symbol, info) in enumerate(rows, 2):
            file_list = ', '.join(sorted(info['files']))
            ws.cell(row=row_idx, column=1, value=symbol)
            ws.cell(row=row_idx, column=2, value=info['category'])
            ws.cell(row=row_idx, column=3, value=info['calls'])
            ws.cell(row=row_idx, column=4, value=len(info['files']))
            ws.cell(row=row_idx, column=5, value=file_list)

        if rows:
            ws.auto_filter.ref = f"A1:E{len(rows) + 1}"


class SourceJsonExporter:
    """Export SourceScanResult to JSON."""

    def export(self, result: SourceScanResult,
               output_path: Optional[str] = None) -> str:
        data = {
            'meta': {
                'tool_version': result.tool_version,
                'report_type': 'source_scan',
                'scan_time': result.scan_time,
                'target': result.target,
            },
            'summary': {
                'total_files_scanned': result.total_files_scanned,
                'files_with_calls': result.files_with_calls,
                'total_call_sites': result.total_call_sites,
                'unique_symbols_count': len(result.unique_symbols),
                'unique_symbols': result.unique_symbols,
                'symbols_by_category': result.symbols_by_category,
            },
            'call_sites': [
                {
                    'file_path': cs.file_path,
                    'file_name': cs.file_name,
                    'caller_function': cs.caller_function,
                    'line_number': cs.line_number,
                    'column': cs.column,
                    'ossl_symbol': cs.ossl_symbol,
                    'category': cs.category,
                    'call_args': cs.call_args,
                    'language': cs.language,
                    'detection_method': getattr(cs, 'detection_method', 'dynamic-link'),
                }
                for cs in result.call_sites
            ],
            'errors': result.errors,
        }

        json_str = json.dumps(data, indent=2, ensure_ascii=False)

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
            logger.info("JSON report saved to: %s", output_path)

        return json_str


SUMMARY_COLUMNS = [
    ('Project',         30),
    ('Files Scanned',   15),
    ('Files with Calls', 16),
    ('Call Sites',      12),
    ('Unique Symbols',  15),
    ('Top Category',    20),
    ('Top Cat Symbols', 15),
]


class SourceMergeExporter:
    """Merge multiple source scan XLSX reports into one multi-sheet workbook."""

    def merge(self, input_paths: List[str], output_path: str) -> Dict:
        """Read XLSX reports and write a merged workbook.

        Returns:
            Dict with per-project stats for console summary.
        """
        input_paths = list(input_paths)
        project_data = self._load_projects(input_paths, self._read_xlsx)
        for pdata, path in zip(project_data, input_paths):
            pdata['source'] = path
        return self._merge_to_workbook(project_data, output_path)

    def merge_from_json(self, input_paths: List[str],
                        output_path: str) -> Dict:
        """Read JSON reports and write a merged XLSX (or JSON) workbook.

        Unlike merge() which reads XLSX, this reads the faster JSON format
        and preserves total_files_scanned (not '--').
        """
        project_data = self._load_projects(input_paths, self._read_json)
        return self._merge_to_workbook(project_data, output_path)

    def _load_projects(self, input_paths, reader):
        """Load project data from input files using the given reader.

        Args:
            input_paths: List of file paths to read.
            reader: Callable returning (name, files_scanned, rows).
        """
        project_data = []
        for path in input_paths:
            name, files_scanned, rows = reader(path)
            project_data.append({
                'name': name, 'files_scanned': files_scanned, 'rows': rows,
            })
        return project_data

    def _merge_to_workbook(self, project_data: List[Dict],
                           output_path: str) -> Dict:
        """Shared implementation for all XLSX merge paths.

        Args:
            project_data: List of dicts with keys:
                name (str), files_scanned (int or '--'), rows (List[List])
                Optional: source (str) - preserved in stats for merge() callers
        """
        from . import _vendor  # noqa: F401
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill

        header_font = Font(bold=True)
        header_fill = PatternFill(
            start_color="E8F4FC", end_color="E8F4FC", fill_type="solid"
        )
        summary_fill = PatternFill(
            start_color="F0F8E8", end_color="F0F8E8", fill_type="solid"
        )

        names = self._resolve_sheet_names([p['name'] for p in project_data])

        wb = Workbook()
        ws_summary = wb.active
        ws_summary.title = "Summary"

        for col_idx, (title, width) in enumerate(SUMMARY_COLUMNS, 1):
            cell = ws_summary.cell(row=1, column=col_idx, value=title)
            cell.font = header_font
            cell.fill = summary_fill
            ws_summary.column_dimensions[chr(64 + col_idx)].width = width

        stats = []
        all_symbols = set()
        all_rows: List[List] = []
        has_files_scanned = any(
            p['files_scanned'] != '--' for p in project_data)

        for idx, pdata in enumerate(project_data):
            sheet_name = names[idx]
            rows = pdata['rows']
            files_scanned = pdata['files_scanned']

            ws = wb.create_sheet(title=sheet_name)
            for col_idx, (_, width, title) in enumerate(COLUMNS, 1):
                cell = ws.cell(row=1, column=col_idx, value=title)
                cell.font = header_font
                cell.fill = header_fill
                ws.column_dimensions[
                    chr(64 + col_idx) if col_idx <= 26
                    else 'A' + chr(64 + col_idx - 26)
                ].width = width

            for row_idx, row_data in enumerate(rows, 2):
                for col_idx, value in enumerate(row_data, 1):
                    ws.cell(row=row_idx, column=col_idx, value=value)

            if rows:
                ws.auto_filter.ref = f"A1:{LAST_COL_LETTER}{len(rows) + 1}"

            cat_counts = self._count_categories(rows)
            top_cat, top_count = '', 0
            if cat_counts:
                top_cat = max(cat_counts, key=cat_counts.get)
                top_count = cat_counts[top_cat]

            symbols = set()
            files_with_calls = set()
            for row in rows:
                symbols.add(row[4])
                files_with_calls.add(row[0])
                all_rows.append(list(row) + [sheet_name])
                all_symbols.add(row[4])

            info = {
                'project': sheet_name,
                'files_scanned': files_scanned,
                'call_sites': len(rows),
                'unique_symbols': len(symbols),
                'files_with_calls': len(files_with_calls),
                'top_category': top_cat,
                'top_cat_symbols': top_count,
            }
            if 'source' in pdata:
                info['source'] = pdata['source']
            stats.append(info)

            row_num = idx + 2
            ws_summary.cell(row=row_num, column=1, value=sheet_name)
            ws_summary.cell(row=row_num, column=2, value=files_scanned)
            ws_summary.cell(row=row_num, column=3, value=len(files_with_calls))
            ws_summary.cell(row=row_num, column=4, value=len(rows))
            ws_summary.cell(row=row_num, column=5, value=len(symbols))
            ws_summary.cell(row=row_num, column=6, value=top_cat)
            ws_summary.cell(row=row_num, column=7, value=top_count)

        total_row = len(project_data) + 2
        total_font = Font(bold=True)
        ws_summary.cell(row=total_row, column=1, value="TOTAL").font = total_font
        if has_files_scanned:
            ws_summary.cell(row=total_row, column=2,
                            value=sum(s['files_scanned'] for s in stats
                                      if s['files_scanned'] != '--')).font = total_font
        ws_summary.cell(row=total_row, column=3,
                        value=sum(s['files_with_calls'] for s in stats)).font = total_font
        ws_summary.cell(row=total_row, column=4,
                        value=sum(s['call_sites'] for s in stats)).font = total_font
        ws_summary.cell(row=total_row, column=5,
                        value=len(all_symbols)).font = total_font

        self._write_symbol_summary_from_rows(
            wb, "Symbol Summary", all_rows, header_font, header_fill)

        wb.save(output_path)
        logger.info("Merged XLSX report saved to: %s", output_path)
        return {'sheets': stats, 'total_symbols': len(all_symbols)}

    def _read_xlsx(self, path: str) -> Tuple[str, str, List[List]]:
        """Read call site rows from a source scan XLSX.

        Returns:
            (project_name, files_scanned_placeholder, list_of_row_values)
        """
        from . import _vendor  # noqa: F401
        from openpyxl import load_workbook

        wb = load_workbook(path, read_only=True, data_only=True)
        ws = wb.active
        rows = []
        for row_idx, row in enumerate(ws.iter_rows(values_only=True)):
            if row_idx == 0:
                continue
            if any(v is not None for v in row):
                rows.append(list(row[:len(COLUMNS)]))
        wb.close()

        name = os.path.splitext(os.path.basename(path))[0]
        return name, '--', rows

    def _read_json(self, path: str) -> Tuple[str, int, List[List]]:
        """Read call site rows from a source scan JSON.

        Returns:
            (project_name, files_scanned, list_of_row_values)
        Row format matches XLSX: [file_path, file_name, caller_function,
            line_number, ossl_symbol, category, call_args]
        """
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        files_scanned = data.get('summary', {}).get('total_files_scanned', 0)
        rows = []
        for cs in data.get('call_sites', []):
            rows.append([
                cs.get('file_path', ''),
                cs.get('file_name', ''),
                cs.get('caller_function', ''),
                cs.get('line_number', 0),
                cs.get('ossl_symbol', ''),
                cs.get('category', ''),
                cs.get('call_args', ''),
                cs.get('detection_method', 'dynamic-link'),
            ])

        name = os.path.splitext(os.path.basename(path))[0]
        return name, files_scanned, rows

    def _resolve_sheet_names(self, names: List[str]) -> List[str]:
        """Ensure unique sheet names within Excel's 31-char limit."""
        result = []
        seen = {}
        for name in names:
            short = name[:31]
            if short in seen:
                seen[short] += 1
                suffix = f"_{seen[short]}"
                short = short[:31 - len(suffix)] + suffix
            else:
                seen[short] = 0
            result.append(short)
        return result

    def _count_categories(self, rows: List[List]) -> Dict[str, int]:
        """Count unique symbols per category from raw rows."""
        cat_syms: Dict[str, set] = {}
        for row in rows:
            cat = row[5] if len(row) > 5 else ''
            sym = row[4] if len(row) > 4 else ''
            if cat:
                if cat not in cat_syms:
                    cat_syms[cat] = set()
                cat_syms[cat].add(sym)
        return {cat: len(syms) for cat, syms in cat_syms.items()}

    def _write_symbol_summary_from_rows(self, wb, sheet_name: str,
                                        rows: List[List],
                                        header_font, header_fill) -> None:
        """Write Symbol Summary sheet from tagged call site rows.

        Each row is expected to have a project name appended as the last
        element by the merge() caller.
        """
        ws = wb.create_sheet(title=sheet_name)

        columns = MERGE_SUMMARY_SHEET_COLUMNS
        for col_idx, (_, width, title) in enumerate(columns, 1):
            cell = ws.cell(row=1, column=col_idx, value=title)
            cell.font = header_font
            cell.fill = header_fill
            ws.column_dimensions[
                chr(64 + col_idx) if col_idx <= 26
                else 'A' + chr(64 + col_idx - 26)
            ].width = width

        sym_data: Dict[str, Dict] = {}
        for row in rows:
            if len(row) < 6:
                continue
            sym = row[4]
            cat = row[5]
            fname = row[0] if len(row) > 0 else ''
            project = row[-1] if len(row) > len(COLUMNS) else ''
            if sym not in sym_data:
                sym_data[sym] = {
                    'category': cat, 'calls': 0,
                    'files': set(), 'projects': set(),
                }
            sym_data[sym]['calls'] += 1
            if fname:
                sym_data[sym]['files'].add(fname)
            if project:
                sym_data[sym]['projects'].add(project)

        sorted_rows = sorted(sym_data.items(),
                              key=lambda x: (x[1]['category'], x[0]))

        for row_idx, (symbol, info) in enumerate(sorted_rows, 2):
            file_list = ', '.join(sorted(info['files']))
            project_list = ', '.join(sorted(info['projects']))
            ws.cell(row=row_idx, column=1, value=symbol)
            ws.cell(row=row_idx, column=2, value=info['category'])
            ws.cell(row=row_idx, column=3, value=info['calls'])
            ws.cell(row=row_idx, column=4, value=len(info['files']))
            ws.cell(row=row_idx, column=5, value=file_list)
            ws.cell(row=row_idx, column=6, value=len(info['projects']))
            ws.cell(row=row_idx, column=7, value=project_list)

        if sorted_rows:
            ws.auto_filter.ref = f"A1:G{len(sorted_rows) + 1}"

    def merge_from_results(self, named_results: List[Tuple[str, 'SourceScanResult']],
                           output_path: str) -> Dict:
        """Merge from in-memory SourceScanResult objects.

        Args:
            named_results: List of (project_name, SourceScanResult) tuples
            output_path: Path to write merged XLSX (or JSON if .json)

        Returns:
            Dict with per-project stats for console summary.
        """
        ext = os.path.splitext(output_path)[1].lower()
        if ext == '.json':
            return self._merge_to_json(named_results, output_path)

        project_data = []
        for name, result in named_results:
            rows = self._result_to_rows(result)
            project_data.append({
                'name': name,
                'files_scanned': result.total_files_scanned,
                'rows': rows,
            })
        return self._merge_to_workbook(project_data, output_path)

    def _result_to_rows(self, result: 'SourceScanResult') -> List[List]:
        """Convert SourceScanResult.call_sites to row lists."""
        return [
            [cs.file_path, cs.file_name, cs.caller_function,
             cs.line_number, cs.ossl_symbol, cs.category, cs.call_args,
             getattr(cs, 'detection_method', 'dynamic-link')]
            for cs in result.call_sites
        ]

    def _merge_to_json(self, named_results, output_path):
        """Merge results to a single JSON file."""
        projects = []
        all_symbols = set()
        stats = []

        for name, result in named_results:
            entry = {
                'project': name,
                'target': result.target,
                'total_files_scanned': result.total_files_scanned,
                'files_with_calls': result.files_with_calls,
                'total_call_sites': result.total_call_sites,
                'unique_symbols': result.unique_symbols,
                'symbols_by_category': result.symbols_by_category,
                'call_sites': [
                    {
                        'file_path': cs.file_path,
                        'file_name': cs.file_name,
                        'caller_function': cs.caller_function,
                        'line_number': cs.line_number,
                        'ossl_symbol': cs.ossl_symbol,
                        'category': cs.category,
                        'call_args': cs.call_args,
                        'detection_method': getattr(cs, 'detection_method',
                                                    'dynamic-link'),
                    }
                    for cs in result.call_sites
                ],
            }
            projects.append(entry)
            all_symbols.update(result.unique_symbols)

            cat_syms: Dict[str, set] = {}
            for cs in result.call_sites:
                if cs.category:
                    cat_syms.setdefault(cs.category, set()).add(cs.ossl_symbol)
            top_cat, top_count = '', 0
            if cat_syms:
                top_cat = max(cat_syms, key=lambda c: len(cat_syms[c]))
                top_count = len(cat_syms[top_cat])

            stats.append({
                'project': name,
                'files_scanned': result.total_files_scanned,
                'call_sites': result.total_call_sites,
                'unique_symbols': len(result.unique_symbols),
                'files_with_calls': result.files_with_calls,
                'top_category': top_cat,
                'top_cat_symbols': top_count,
            })

        merged = {
            'meta': {
                'report_type': 'combo_scan',
                'total_projects': len(projects),
                'total_call_sites': sum(p['total_call_sites'] for p in projects),
                'total_unique_symbols': len(all_symbols),
            },
            'projects': projects,
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(merged, f, indent=2, ensure_ascii=False)
        logger.info("Merged JSON report saved to: %s", output_path)
        return {'sheets': stats, 'total_symbols': len(all_symbols)}
