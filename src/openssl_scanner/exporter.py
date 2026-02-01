"""
Export module for scan reports.

Supports exporting to:
- Excel (.xlsx) with multiple sheets for full data analysis
- Self-contained HTML with embedded JS/CSS
"""

import json
import os
import logging
from typing import Dict, List, Any, Optional
from importlib import resources

logger = logging.getLogger(__name__)


class ExcelExporter:
    """
    Export report to Excel with comprehensive data sheets.

    Sheets:
    1. Overview     - Metadata and summary statistics
    2. Files        - All scanned files with full attributes
    3. File-Symbol  - Flat table for pivot analysis (file, symbol, category)
    4. Import Chains - Symbol import paths
    5. By Category  - Category-wise symbol statistics
    6. By Depth     - Depth-wise symbol statistics
    7. Dep Tree     - Flattened dependency tree
    8. Errors       - Scan errors and warnings
    """

    def export(self, report_path: str, output_path: str) -> None:
        """
        Export JSON report to Excel file.

        Args:
            report_path: Path to JSON report file
            output_path: Output Excel file path
        """
        try:
            from openpyxl import Workbook
            from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
            from openpyxl.utils import get_column_letter
        except ImportError:
            raise ImportError(
                "openpyxl is required for Excel export. "
                "Install with: pip install openpyxl"
            )

        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        wb = Workbook()

        self._header_font = Font(bold=True)
        self._header_fill = PatternFill(start_color="E8F4FC", end_color="E8F4FC", fill_type="solid")

        self._create_overview_sheet(wb, data)
        self._create_files_sheet(wb, data)
        self._create_file_symbol_sheet(wb, data)
        self._create_import_chains_sheet(wb, data)
        self._create_category_sheet(wb, data)
        self._create_depth_sheet(wb, data)
        self._create_dep_tree_sheet(wb, data)
        self._create_errors_sheet(wb, data)

        del wb['Sheet']

        wb.save(output_path)
        logger.info(f"Excel report saved to: {output_path}")

    def _style_header(self, ws, row: int, num_cols: int) -> None:
        """Apply header styling to a row."""
        for col in range(1, num_cols + 1):
            cell = ws.cell(row=row, column=col)
            cell.font = self._header_font
            cell.fill = self._header_fill

    def _create_overview_sheet(self, wb, data: Dict) -> None:
        """Create overview sheet with metadata and summary."""
        ws = wb.create_sheet("Overview", 0)

        meta = data.get('meta', {})
        summary = data.get('summary', {})
        report_type = meta.get('report_type', 'single')

        is_aggregated = report_type == 'aggregated'

        rows = [
            ("REPORT METADATA", ""),
            ("Report Type", report_type),
            ("Tool Version", meta.get('tool_version', '')),
            ("Scan Time", meta.get('aggregation_time', meta.get('scan_time', ''))),
            ("Scan Root", meta.get('scan_root', '')),
            ("Target Architecture", meta.get('target_arch', '')),
            ("", ""),
        ]

        if is_aggregated:
            rows.extend([
                ("AGGREGATION INFO", ""),
                ("Source Reports", meta.get('source_reports_count', 0)),
                ("Mapping File", meta.get('mapping_file', 'None')),
                ("", ""),
            ])

        rows.extend([
            ("SUMMARY STATISTICS", ""),
            ("Total Files Scanned", summary.get('total_files_scanned', summary.get('total_executables', 0))),
            ("Total ELF Files", summary.get('total_elf_files', summary.get('total_executables', 0))),
            ("Files with OpenSSL Deps", summary.get('files_with_openssl_deps', summary.get('total_components', 0))),
            ("Total OpenSSL Symbols (refs)", summary.get('total_openssl_symbols', 0)),
            ("Unique OpenSSL Symbols", summary.get('unique_openssl_symbols', summary.get('global_unique_symbols', 0))),
            ("", ""),
        ])

        openssl_libs = summary.get('openssl_libs_found', [])
        if openssl_libs:
            rows.append(("DETECTED OPENSSL LIBRARIES", ""))
            for lib in openssl_libs:
                rows.append(("", lib))

        for row_idx, (label, value) in enumerate(rows, 1):
            cell_a = ws.cell(row=row_idx, column=1, value=label)
            ws.cell(row=row_idx, column=2, value=str(value) if value else '')
            if label and label.isupper():
                cell_a.font = self._header_font

        ws.column_dimensions['A'].width = 30
        ws.column_dimensions['B'].width = 60

    def _create_files_sheet(self, wb, data: Dict) -> None:
        """Create files sheet with complete file information."""
        ws = wb.create_sheet("Files")

        headers = [
            "File Path", "File Name", "Type", "Arch",
            "OpenSSL Direct", "OpenSSL Transitive", "OpenSSL Libs",
            "Symbol Count", "Direct Dependencies"
        ]
        for col, header in enumerate(headers, 1):
            ws.cell(row=1, column=col, value=header)
        self._style_header(ws, 1, len(headers))

        files_detail = data.get('files_detail', [])

        if not files_detail:
            by_file = data.get('openssl_symbols', {}).get('by_file', {})
            if by_file:
                for path, info in by_file.items():
                    symbols = info.get('symbols', []) if isinstance(info, dict) else []
                    files_detail.append({
                        'path': path,
                        'type': 'shared_library' if '.so' in path else 'executable',
                        'arch': data.get('meta', {}).get('target_arch', ''),
                        'direct_deps': [],
                        'openssl_deps': {'direct': False, 'transitive': True, 'libs': []},
                        'openssl_symbols_used': symbols,
                        'error': None
                    })

            components = data.get('components', {})
            if components and not files_detail:
                for comp_name, comp_data in components.items():
                    executables = comp_data.get('executables', [comp_name])
                    symbols = comp_data.get('unique_symbols', comp_data.get('symbols', []))
                    for exe in executables:
                        files_detail.append({
                            'path': exe,
                            'type': 'component',
                            'arch': '',
                            'direct_deps': [],
                            'openssl_deps': {'direct': False, 'transitive': True, 'libs': []},
                            'openssl_symbols_used': symbols,
                            'error': None
                        })

        row_idx = 2
        for f in files_detail:
            path = f.get('path', '')
            openssl_deps = f.get('openssl_deps', {})
            symbols = f.get('openssl_symbols_used', [])
            direct_deps = f.get('direct_deps', [])

            ws.cell(row=row_idx, column=1, value=path)
            ws.cell(row=row_idx, column=2, value=os.path.basename(path))
            ws.cell(row=row_idx, column=3, value=f.get('type', ''))
            ws.cell(row=row_idx, column=4, value=f.get('arch', ''))
            ws.cell(row=row_idx, column=5, value='Yes' if openssl_deps.get('direct') else 'No')
            ws.cell(row=row_idx, column=6, value='Yes' if openssl_deps.get('transitive') else 'No')
            ws.cell(row=row_idx, column=7, value=', '.join(openssl_deps.get('libs', [])))
            ws.cell(row=row_idx, column=8, value=len(symbols))
            ws.cell(row=row_idx, column=9, value=', '.join(direct_deps) if direct_deps else '')
            row_idx += 1

        if row_idx == 2:
            ws.cell(row=2, column=1, value="No file data available")

        col_widths = [60, 25, 15, 10, 15, 18, 40, 12, 60]
        for col, width in enumerate(col_widths, 1):
            ws.column_dimensions[get_column_letter(col)].width = width

    def _create_file_symbol_sheet(self, wb, data: Dict) -> None:
        """
        Create flat file-symbol table for pivot analysis.

        Each row is one (component/file, binary, symbol) tuple - ideal for pivot tables.
        For single scans: Component = File Path, Binary = File Name
        For aggregated scans: Component = component name, Binary = executable name
        """
        ws = wb.create_sheet("File-Symbol")

        report_type = data.get('meta', {}).get('report_type', 'single')
        is_aggregated = report_type == 'aggregated'

        headers = ["Component", "Binary", "Symbol", "Category"]
        for col, header in enumerate(headers, 1):
            ws.cell(row=1, column=col, value=header)
        self._style_header(ws, 1, len(headers))

        by_category = data.get('openssl_symbols', {}).get('by_category', {})
        symbol_to_category = {}
        for cat, cat_data in by_category.items():
            if isinstance(cat_data, dict):
                for sym in cat_data.get('symbols', []):
                    symbol_to_category[sym] = cat

        components = data.get('components', {})
        if components:
            for comp_name, comp_data in components.items():
                for cat, cat_data in comp_data.get('by_category', {}).items():
                    if isinstance(cat_data, dict):
                        for sym in cat_data.get('symbols', []):
                            symbol_to_category[sym] = cat

        row_idx = 2

        by_file = data.get('openssl_symbols', {}).get('by_file', {})
        if by_file:
            for path, info in by_file.items():
                symbols = info.get('symbols', []) if isinstance(info, dict) else []
                filename = os.path.basename(path)
                for sym in sorted(symbols):
                    category = symbol_to_category.get(sym, 'other')
                    ws.cell(row=row_idx, column=1, value=path)
                    ws.cell(row=row_idx, column=2, value=filename)
                    ws.cell(row=row_idx, column=3, value=sym)
                    ws.cell(row=row_idx, column=4, value=category)
                    row_idx += 1

        files_detail = data.get('files_detail', [])
        if files_detail and row_idx == 2:
            for f in files_detail:
                path = f.get('path', '')
                filename = os.path.basename(path)
                symbols = f.get('openssl_symbols_used', [])
                for sym in sorted(symbols):
                    category = symbol_to_category.get(sym, 'other')
                    ws.cell(row=row_idx, column=1, value=path)
                    ws.cell(row=row_idx, column=2, value=filename)
                    ws.cell(row=row_idx, column=3, value=sym)
                    ws.cell(row=row_idx, column=4, value=category)
                    row_idx += 1

        if components and row_idx == 2:
            for comp_name, comp_data in components.items():
                exec_detail = comp_data.get('executables_detail', {})
                if exec_detail:
                    for bin_name, bin_data in exec_detail.items():
                        for cat, cat_data in bin_data.get('by_category', {}).items():
                            symbols = cat_data.get('symbols', []) if isinstance(cat_data, dict) else []
                            for sym in sorted(symbols):
                                ws.cell(row=row_idx, column=1, value=comp_name)
                                ws.cell(row=row_idx, column=2, value=bin_name)
                                ws.cell(row=row_idx, column=3, value=sym)
                                ws.cell(row=row_idx, column=4, value=cat)
                                row_idx += 1
                else:
                    for cat, cat_data in comp_data.get('by_category', {}).items():
                        symbols = cat_data.get('symbols', []) if isinstance(cat_data, dict) else []
                        for sym in sorted(symbols):
                            ws.cell(row=row_idx, column=1, value=comp_name)
                            ws.cell(row=row_idx, column=2, value=comp_name)
                            ws.cell(row=row_idx, column=3, value=sym)
                            ws.cell(row=row_idx, column=4, value=cat)
                            row_idx += 1

        if row_idx == 2:
            ws.cell(row=2, column=1, value="No file-symbol data available")

        ws.column_dimensions['A'].width = 60
        ws.column_dimensions['B'].width = 25
        ws.column_dimensions['C'].width = 35
        ws.column_dimensions['D'].width = 18

    def _create_import_chains_sheet(self, wb, data: Dict) -> None:
        """
        Create import chains sheet showing dependency paths.

        Supports both formats:
        - Detailed: {symbol: [{source_file, chain, depth}, ...]}
        - Legacy: {symbol: [chain_string, ...]}
        """
        ws = wb.create_sheet("Import Chains")

        headers = ["Source File", "File Name", "Symbol", "Category", "Import Chain", "Depth"]
        for col, header in enumerate(headers, 1):
            ws.cell(row=1, column=col, value=header)
        self._style_header(ws, 1, len(headers))

        import_chains = data.get('openssl_symbols', {}).get('import_chains', {})
        by_category = data.get('openssl_symbols', {}).get('by_category', {})

        symbol_to_category = {}
        for cat, cat_data in by_category.items():
            if isinstance(cat_data, dict):
                for sym in cat_data.get('symbols', []):
                    symbol_to_category[sym] = cat

        row_idx = 2
        for symbol, chains in sorted(import_chains.items()):
            category = symbol_to_category.get(symbol, 'other')

            for chain_item in chains:
                if isinstance(chain_item, dict):
                    source_file = chain_item.get('source_file', '')
                    if not source_file:
                        component = chain_item.get('component', '')
                        binary = chain_item.get('binary', '')
                        source_file = f"{component}/{binary}" if component else binary
                    chain_str = chain_item.get('chain', '')
                    depth = chain_item.get('depth', 0)
                else:
                    source_file = ''
                    chain_str = chain_item
                    depth = chain_str.count(' -> ')

                file_name = os.path.basename(source_file) if source_file else ''

                ws.cell(row=row_idx, column=1, value=source_file)
                ws.cell(row=row_idx, column=2, value=file_name)
                ws.cell(row=row_idx, column=3, value=symbol)
                ws.cell(row=row_idx, column=4, value=category)
                ws.cell(row=row_idx, column=5, value=chain_str)
                ws.cell(row=row_idx, column=6, value=depth)
                row_idx += 1

        if row_idx == 2:
            ws.cell(row=2, column=1, value="No import chain data available")

        ws.column_dimensions['A'].width = 50
        ws.column_dimensions['B'].width = 20
        ws.column_dimensions['C'].width = 35
        ws.column_dimensions['D'].width = 15
        ws.column_dimensions['E'].width = 80
        ws.column_dimensions['F'].width = 10

    def _create_category_sheet(self, wb, data: Dict) -> None:
        """Create category statistics sheet."""
        ws = wb.create_sheet("By Category")

        headers = ["Category", "Symbol Count", "Percentage", "Symbols"]
        for col, header in enumerate(headers, 1):
            ws.cell(row=1, column=col, value=header)
        self._style_header(ws, 1, len(headers))

        by_category = data.get('openssl_symbols', {}).get('by_category', {})

        if not by_category:
            components = data.get('components', {})
            category_symbols: Dict[str, set] = {}
            for comp_data in components.values():
                for cat, cat_data in comp_data.get('by_category', {}).items():
                    if cat not in category_symbols:
                        category_symbols[cat] = set()
                    symbols = cat_data.get('symbols', []) if isinstance(cat_data, dict) else []
                    category_symbols[cat].update(symbols)
            by_category = {
                cat: {'count': len(syms), 'symbols': list(syms)}
                for cat, syms in category_symbols.items()
            }

        total = sum(
            cat_data.get('count', len(cat_data.get('symbols', [])))
            if isinstance(cat_data, dict) else 0
            for cat_data in by_category.values()
        ) or 1

        sorted_cats = sorted(
            by_category.items(),
            key=lambda x: x[1].get('count', 0) if isinstance(x[1], dict) else 0,
            reverse=True
        )

        row_idx = 2
        for cat, cat_data in sorted_cats:
            if not isinstance(cat_data, dict):
                continue
            count = cat_data.get('count', len(cat_data.get('symbols', [])))
            symbols = cat_data.get('symbols', [])
            pct = (count / total) * 100

            ws.cell(row=row_idx, column=1, value=cat)
            ws.cell(row=row_idx, column=2, value=count)
            ws.cell(row=row_idx, column=3, value=f"{pct:.1f}%")
            ws.cell(row=row_idx, column=4, value=', '.join(sorted(symbols)))
            row_idx += 1

        ws.cell(row=row_idx, column=1, value="TOTAL")
        ws.cell(row=row_idx, column=2, value=total)
        ws.cell(row=row_idx, column=3, value="100%")
        ws.cell(row=row_idx, column=1).font = self._header_font

        ws.column_dimensions['A'].width = 20
        ws.column_dimensions['B'].width = 15
        ws.column_dimensions['C'].width = 12
        ws.column_dimensions['D'].width = 100

    def _create_depth_sheet(self, wb, data: Dict) -> None:
        """Create depth statistics sheet."""
        ws = wb.create_sheet("By Depth")

        headers = ["Depth", "Description", "Symbol Count", "File Count", "Symbols"]
        for col, header in enumerate(headers, 1):
            ws.cell(row=1, column=col, value=header)
        self._style_header(ws, 1, len(headers))

        by_depth = data.get('openssl_symbols', {}).get('by_depth', {})

        if not by_depth:
            ws.cell(row=2, column=1, value="No depth data available")
            ws.column_dimensions['A'].width = 50
            return

        depth_descriptions = {
            1: "Direct OpenSSL dependency (depth 1)",
            2: "One hop to OpenSSL (depth 2)",
            3: "Two hops to OpenSSL (depth 3)",
        }

        row_idx = 2
        for depth_key in sorted(by_depth.keys()):
            depth_data = by_depth[depth_key]
            if not isinstance(depth_data, dict):
                continue

            depth_num = depth_key.replace('depth_', '') if isinstance(depth_key, str) else depth_key
            try:
                depth_int = int(depth_num)
            except (ValueError, TypeError):
                depth_int = -1

            count = depth_data.get('count', len(depth_data.get('symbols', [])))
            symbols = depth_data.get('symbols', [])
            files = depth_data.get('files', [])

            desc = depth_descriptions.get(depth_int, f"{depth_int - 1} hops to OpenSSL (depth {depth_int})")

            ws.cell(row=row_idx, column=1, value=depth_int)
            ws.cell(row=row_idx, column=2, value=desc)
            ws.cell(row=row_idx, column=3, value=count)
            ws.cell(row=row_idx, column=4, value=len(files))
            ws.cell(row=row_idx, column=5, value=', '.join(sorted(symbols)))
            row_idx += 1

        ws.column_dimensions['A'].width = 10
        ws.column_dimensions['B'].width = 35
        ws.column_dimensions['C'].width = 15
        ws.column_dimensions['D'].width = 12
        ws.column_dimensions['E'].width = 100

    def _create_dep_tree_sheet(self, wb, data: Dict) -> None:
        """Create flattened dependency tree sheet."""
        ws = wb.create_sheet("Dep Tree")

        headers = ["Parent", "Child", "Depth", "Is OpenSSL Lib", "Symbol Count", "Full Path"]
        for col, header in enumerate(headers, 1):
            ws.cell(row=1, column=col, value=header)
        self._style_header(ws, 1, len(headers))

        dep_tree = data.get('dependency_tree', {})

        if not dep_tree:
            ws.cell(row=2, column=1, value="No dependency tree data available")
            ws.cell(row=3, column=1, value="(Dependency tree requires single-binary scan mode)")
            ws.column_dimensions['A'].width = 50
            return

        rows = []
        self._flatten_tree(dep_tree, None, 0, rows)

        row_idx = 2
        for item in rows:
            ws.cell(row=row_idx, column=1, value=item['parent'] or '(root)')
            ws.cell(row=row_idx, column=2, value=item['name'])
            ws.cell(row=row_idx, column=3, value=item['depth'])
            ws.cell(row=row_idx, column=4, value='Yes' if item['is_openssl'] else 'No')
            ws.cell(row=row_idx, column=5, value=item['symbol_count'])
            ws.cell(row=row_idx, column=6, value=item['path'])
            row_idx += 1

        ws.column_dimensions['A'].width = 25
        ws.column_dimensions['B'].width = 25
        ws.column_dimensions['C'].width = 10
        ws.column_dimensions['D'].width = 15
        ws.column_dimensions['E'].width = 12
        ws.column_dimensions['F'].width = 60

    def _flatten_tree(self, node: Dict, parent: Optional[str], depth: int, rows: List[Dict]) -> None:
        """Recursively flatten dependency tree into list of rows."""
        rows.append({
            'parent': parent,
            'name': node.get('name', ''),
            'path': node.get('path', ''),
            'depth': depth,
            'is_openssl': node.get('is_openssl_lib', False),
            'symbol_count': node.get('openssl_symbols_count', 0),
        })

        for child in node.get('children', []):
            self._flatten_tree(child, node.get('name'), depth + 1, rows)

    def _create_errors_sheet(self, wb, data: Dict) -> None:
        """Create errors sheet."""
        ws = wb.create_sheet("Errors")

        headers = ["Severity", "File", "Error Message"]
        for col, header in enumerate(headers, 1):
            ws.cell(row=1, column=col, value=header)
        self._style_header(ws, 1, len(headers))

        errors = data.get('errors', [])

        row_idx = 2
        for err in errors:
            if isinstance(err, dict):
                ws.cell(row=row_idx, column=1, value=err.get('severity', 'warning').upper())
                ws.cell(row=row_idx, column=2, value=err.get('file', ''))
                ws.cell(row=row_idx, column=3, value=err.get('error', ''))
            else:
                ws.cell(row=row_idx, column=1, value='WARNING')
                ws.cell(row=row_idx, column=2, value='')
                ws.cell(row=row_idx, column=3, value=str(err))
            row_idx += 1

        if row_idx == 2:
            ws.cell(row=2, column=1, value="No errors")

        ws.column_dimensions['A'].width = 12
        ws.column_dimensions['B'].width = 50
        ws.column_dimensions['C'].width = 60


def get_column_letter(col_idx):
    """Convert column index to letter (1=A, 2=B, etc.)."""
    result = ""
    while col_idx > 0:
        col_idx, remainder = divmod(col_idx - 1, 26)
        result = chr(65 + remainder) + result
    return result


class HTMLExporter:
    """Export report to self-contained HTML."""

    def export(self, report_path: str, output_path: str) -> None:
        """
        Export JSON report to self-contained HTML file.

        Args:
            report_path: Path to JSON report file
            output_path: Output HTML file path
        """
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        html_content = self._generate_html(report_data)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"HTML report saved to: {output_path}")

    def _generate_html(self, data: Dict) -> str:
        """Generate self-contained HTML with embedded data and scripts."""
        css = self._get_css()
        js = self._get_js()
        chartjs = self._get_chartjs_minimal()
        sheetjs = self._get_sheetjs_minimal()

        json_data = json.dumps(data, ensure_ascii=False)

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenSSL Dependency Analysis Report</title>
    <style>
{css}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>OpenSSL Dependency Analysis Report</h1>
            <div class="actions">
                <button onclick="exportExcel()">Export Excel</button>
                <button onclick="loadFile()">Load JSON</button>
                <input type="file" id="fileInput" accept=".json" style="display:none" onchange="handleFileSelect(event)">
            </div>
        </header>

        <div class="summary-cards" id="summaryCards"></div>

        <div class="tabs">
            <button class="tab-btn active" onclick="showTab('ranking')">Ranking</button>
            <button class="tab-btn" onclick="showTab('categories')">Categories</button>
            <button class="tab-btn" onclick="showTab('symbols')">Symbols</button>
        </div>

        <div id="ranking" class="tab-content active">
            <div class="chart-container">
                <canvas id="rankingChart"></canvas>
            </div>
            <table id="rankingTable"></table>
        </div>

        <div id="categories" class="tab-content">
            <div class="chart-container">
                <canvas id="categoryChart"></canvas>
            </div>
            <table id="categoryTable"></table>
        </div>

        <div id="symbols" class="tab-content">
            <div class="search-box">
                <input type="text" id="symbolSearch" placeholder="Search symbols..." oninput="filterSymbols()">
                <select id="categoryFilter" onchange="filterSymbols()">
                    <option value="">All Categories</option>
                </select>
                <select id="componentFilter" onchange="filterSymbols()">
                    <option value="">All Components</option>
                </select>
            </div>
            <table id="symbolsTable"></table>
        </div>
    </div>

    <!-- Component Detail Modal -->
    <div id="componentModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">Component Details</h2>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-summary" id="modalSummary"></div>
            <div class="modal-body" id="modalBody"></div>
        </div>
    </div>

    <script>
{chartjs}
    </script>
    <script>
{sheetjs}
    </script>
    <script>
const REPORT_DATA = {json_data};
{js}
document.addEventListener('DOMContentLoaded', function() {{
    try {{
        renderReport(REPORT_DATA);
    }} catch(e) {{
        console.error('Render error:', e);
        document.body.innerHTML += '<div style="color:red;padding:20px;">Error: ' + e.message + '</div>';
    }}
}});
    </script>
</body>
</html>'''

    def _get_css(self) -> str:
        """Get embedded CSS."""
        return '''
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f5f5f5;
    color: #333;
    line-height: 1.6;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 20px;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding: 20px;
    background: #fff;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

header h1 {
    font-size: 1.5rem;
    color: #2c3e50;
}

.actions button {
    padding: 8px 16px;
    margin-left: 10px;
    border: none;
    border-radius: 4px;
    background: #3498db;
    color: #fff;
    cursor: pointer;
    font-size: 14px;
}

.actions button:hover {
    background: #2980b9;
}

.summary-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin-bottom: 20px;
}

.card {
    background: #fff;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    text-align: center;
}

.card .value {
    font-size: 2rem;
    font-weight: bold;
    color: #3498db;
}

.card .label {
    color: #7f8c8d;
    font-size: 0.9rem;
}

.tabs {
    display: flex;
    gap: 5px;
    margin-bottom: 20px;
}

.tab-btn {
    padding: 10px 20px;
    border: none;
    background: #fff;
    cursor: pointer;
    border-radius: 4px 4px 0 0;
    font-size: 14px;
}

.tab-btn.active {
    background: #3498db;
    color: #fff;
}

.tab-content {
    display: none;
    background: #fff;
    padding: 20px;
    border-radius: 0 8px 8px 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.tab-content.active {
    display: block;
}

.chart-container {
    height: 300px;
    margin-bottom: 20px;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #eee;
}

th {
    background: #f8f9fa;
    font-weight: 600;
    color: #2c3e50;
}

tr:hover {
    background: #f8f9fa;
}

.search-box {
    display: flex;
    gap: 10px;
    margin-bottom: 15px;
}

.search-box input,
.search-box select {
    padding: 8px 12px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 14px;
}

.search-box input {
    flex: 1;
}

.bar {
    height: 20px;
    background: #3498db;
    border-radius: 3px;
    transition: width 0.3s;
}

.bar-container {
    background: #ecf0f1;
    border-radius: 3px;
    overflow: hidden;
}

/* Clickable component links */
.component-link {
    color: #3498db;
    cursor: pointer;
    text-decoration: none;
}
.component-link:hover {
    text-decoration: underline;
}

/* Modal styles */
.modal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.5);
    z-index: 10000;
    overflow: auto;
}
.modal.active {
    display: flex;
    justify-content: center;
    align-items: flex-start;
    padding: 40px 20px;
}
.modal-content {
    background: #fff;
    border-radius: 8px;
    width: 100%;
    max-width: 900px;
    max-height: 85vh;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    box-shadow: 0 4px 20px rgba(0,0,0,0.2);
}
.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 15px 20px;
    border-bottom: 1px solid #eee;
    background: #f8f9fa;
}
.modal-header h2 {
    font-size: 1.3rem;
    color: #2c3e50;
}
.modal-close {
    background: none;
    border: none;
    font-size: 28px;
    cursor: pointer;
    color: #7f8c8d;
    line-height: 1;
}
.modal-close:hover {
    color: #e74c3c;
}
.modal-summary {
    padding: 15px 20px;
    background: #fff;
    border-bottom: 1px solid #eee;
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}
.modal-summary .stat {
    text-align: center;
    padding: 10px 15px;
    background: #f8f9fa;
    border-radius: 6px;
}
.modal-summary .stat .value {
    font-size: 1.5rem;
    font-weight: bold;
    color: #3498db;
}
.modal-summary .stat .label {
    font-size: 0.8rem;
    color: #7f8c8d;
}
.modal-body {
    padding: 20px;
    overflow-y: auto;
    flex: 1;
}
.category-section {
    margin-bottom: 20px;
}
.category-section h3 {
    font-size: 1rem;
    color: #2c3e50;
    padding: 8px 12px;
    background: #e8f4fc;
    border-radius: 4px;
    margin-bottom: 10px;
    display: flex;
    justify-content: space-between;
}
.category-section h3 .count {
    color: #3498db;
    font-weight: normal;
}
.symbol-list {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    padding-left: 12px;
}
.symbol-tag {
    display: inline-block;
    padding: 4px 10px;
    background: #f5f5f5;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-family: monospace;
    font-size: 12px;
    color: #333;
}
.symbol-tag:hover {
    background: #e8f4fc;
    border-color: #3498db;
}

/* Binary-level hierarchy styles */
.binary-section {
    margin-bottom: 15px;
    border: 1px solid #e0e0e0;
    border-radius: 6px;
    overflow: hidden;
}
.binary-header {
    display: flex;
    align-items: center;
    padding: 12px 15px;
    background: #f8f9fa;
    cursor: pointer;
    user-select: none;
    border-bottom: 1px solid #e0e0e0;
}
.binary-header:hover {
    background: #e8f4fc;
}
.binary-header.expanded {
    background: #e8f4fc;
    border-bottom-color: #3498db;
}
.binary-toggle {
    margin-right: 10px;
    color: #7f8c8d;
    font-size: 10px;
    transition: transform 0.2s;
}
.binary-name {
    font-weight: 600;
    color: #2c3e50;
    flex: 1;
}
.binary-stats {
    color: #7f8c8d;
    font-size: 0.85rem;
}
.binary-content {
    padding: 15px;
    background: #fff;
}
.binary-content .category-section {
    margin-bottom: 15px;
}
.binary-content .category-section:last-child {
    margin-bottom: 0;
}

/* Sortable table headers */
th.sortable {
    cursor: pointer;
    user-select: none;
    position: relative;
}
th.sortable:hover {
    background: #e8f4fc;
}
.sort-icon {
    margin-left: 5px;
    color: #bdc3c7;
    font-size: 12px;
}
.sort-icon.active {
    color: #3498db;
}
'''

    def _get_js(self) -> str:
        """Get embedded JavaScript."""
        return '''
let currentData = null;
let rankingChart = null;
let categoryChart = null;

function normalizeData(data) {
    /* Normalize single and aggregated report formats to common structure */
    const reportType = data.meta?.report_type || 'single';

    if (reportType === 'single') {
        /* Convert single report format to aggregated-like format */
        const byFile = data.openssl_symbols?.by_file || {};
        const byCategory = data.openssl_symbols?.by_category || {};

        /* Build ranking from by_file */
        const ranking = Object.entries(byFile)
            .map(([path, info]) => ({
                component: path.split('/').pop(),
                unique_symbols_count: info.count || 0,
                symbols: info.symbols || []
            }))
            .sort((a, b) => b.unique_symbols_count - a.unique_symbols_count)
            .map((item, i) => ({ ...item, rank: i + 1 }));

        /* Build components from by_file with category info */
        const components = {};
        Object.entries(byFile).forEach(([path, info]) => {
            const name = path.split('/').pop();
            components[name] = {
                executables: [name],
                unique_symbols_count: info.count || 0,
                unique_symbols: info.symbols || [],
                by_category: {}
            };
            /* Assign symbols to categories */
            (info.symbols || []).forEach(sym => {
                for (const [cat, catInfo] of Object.entries(byCategory)) {
                    if (catInfo.symbols && catInfo.symbols.includes(sym)) {
                        if (!components[name].by_category[cat]) {
                            components[name].by_category[cat] = { count: 0, symbols: [] };
                        }
                        components[name].by_category[cat].symbols.push(sym);
                        components[name].by_category[cat].count++;
                        break;
                    }
                }
            });
        });

        data.ranking = ranking;
        data.components = components;
        data._normalized = true;
    }

    return data;
}

function renderReport(data) {
    console.log('renderReport called, report_type:', data.meta?.report_type);
    console.log('ranking:', data.ranking?.length, 'components:', Object.keys(data.components || {}).length);

    try {
        currentData = normalizeData(data);
        console.log('After normalize - ranking:', currentData.ranking?.length);

        renderSummary(currentData);
        console.log('Summary rendered');

        renderRanking(currentData);
        console.log('Ranking rendered');

        renderCategories(currentData);
        console.log('Categories rendered');

        renderSymbols(currentData);
        console.log('Symbols rendered');

        populateFilters(currentData);
        console.log('Filters populated');
    } catch (e) {
        console.error('Error in renderReport:', e);
        document.body.innerHTML += '<div style="color:red;padding:20px;">Error: ' + e.message + '</div>';
    }
}

function renderSummary(data) {
    const container = document.getElementById('summaryCards');
    const summary = data.summary || {};

    const cards = [
        { label: 'Components', value: summary.total_components || summary.files_with_openssl_deps || 0 },
        { label: 'Total ELF Files', value: summary.total_executables || summary.total_elf_files || 0 },
        { label: 'Unique Symbols', value: summary.global_unique_symbols || summary.unique_openssl_symbols || 0 }
    ];

    container.innerHTML = cards.map(c => `
        <div class="card">
            <div class="value">${c.value}</div>
            <div class="label">${c.label}</div>
        </div>
    `).join('');
}

/* Ranking sort state */
let rankingSortCol = 'symbols';
let rankingSortAsc = false;

function renderRanking(data) {
    window.rankingData = data.ranking || [];
    renderRankingTable();

    if (window.rankingData.length === 0) {
        return;
    }

    const ctx = document.getElementById('rankingChart').getContext('2d');
    if (rankingChart) rankingChart.destroy();
    const ranking = window.rankingData;
    rankingChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ranking.slice(0, 15).map(r => r.component),
            datasets: [{
                label: 'Symbols Used',
                data: ranking.slice(0, 15).map(r => r.unique_symbols_count),
                backgroundColor: '#3498db'
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

function renderRankingTable() {
    const ranking = [...window.rankingData];
    const total = currentData?.summary?.global_unique_symbols || currentData?.summary?.unique_openssl_symbols || 1;

    /* Sort ranking */
    ranking.sort((a, b) => {
        let cmp = 0;
        if (rankingSortCol === 'component') {
            cmp = a.component.localeCompare(b.component);
        } else if (rankingSortCol === 'symbols') {
            cmp = a.unique_symbols_count - b.unique_symbols_count;
        }
        return rankingSortAsc ? cmp : -cmp;
    });

    const table = document.getElementById('rankingTable');
    const sortIcon = (col) => {
        if (rankingSortCol !== col) return '<span class="sort-icon">&#x2195;</span>';
        return rankingSortAsc ? '<span class="sort-icon active">&#x2191;</span>' : '<span class="sort-icon active">&#x2193;</span>';
    };

    table.innerHTML = `
        <thead>
            <tr>
                <th>#</th>
                <th class="sortable" onclick="sortRanking('component')">Component ${sortIcon('component')}</th>
                <th class="sortable" onclick="sortRanking('symbols')">Symbols ${sortIcon('symbols')}</th>
                <th>Distribution</th>
            </tr>
        </thead>
        <tbody>
            ${ranking.map((r, i) => {
                const pct = (r.unique_symbols_count / total * 100).toFixed(1);
                return `
                <tr>
                    <td>${i + 1}</td>
                    <td><span class="component-link" onclick="showComponentDetail('${r.component.replace(/'/g, "\\'")}')">${r.component}</span></td>
                    <td>${r.unique_symbols_count}</td>
                    <td>
                        <div class="bar-container" style="width:200px">
                            <div class="bar" style="width:${pct}%"></div>
                        </div>
                        ${pct}%
                    </td>
                </tr>`;
            }).join('')}
        </tbody>
    `;

    if (ranking.length === 0) {
        table.innerHTML += '<tbody><tr><td colspan="4">No data available</td></tr></tbody>';
    }
}

function sortRanking(col) {
    if (rankingSortCol === col) {
        rankingSortAsc = !rankingSortAsc;
    } else {
        rankingSortCol = col;
        rankingSortAsc = col === 'component';
    }
    renderRankingTable();
}

function renderCategories(data) {
    const components = data.components || {};
    const categoryTotals = {};

    /* Also check openssl_symbols.by_category for single reports */
    const directCategories = data.openssl_symbols?.by_category || {};

    if (Object.keys(directCategories).length > 0) {
        Object.entries(directCategories).forEach(([cat, catData]) => {
            categoryTotals[cat] = catData.count || 0;
        });
    } else {
        Object.values(components).forEach(comp => {
            Object.entries(comp.by_category || {}).forEach(([cat, catData]) => {
                const count = typeof catData === 'object' ? catData.count : 0;
                categoryTotals[cat] = (categoryTotals[cat] || 0) + count;
            });
        });
    }

    const sorted = Object.entries(categoryTotals).sort((a, b) => b[1] - a[1]);

    const table = document.getElementById('categoryTable');
    table.innerHTML = `
        <thead>
            <tr>
                <th>Category</th>
                <th>Total Symbols</th>
            </tr>
        </thead>
        <tbody>
            ${sorted.map(([cat, count]) => `
                <tr>
                    <td>${cat}</td>
                    <td>${count}</td>
                </tr>
            `).join('')}
        </tbody>
    `;

    const ctx = document.getElementById('categoryChart').getContext('2d');
    if (categoryChart) categoryChart.destroy();
    categoryChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: sorted.slice(0, 10).map(s => s[0]),
            datasets: [{
                data: sorted.slice(0, 10).map(s => s[1]),
                backgroundColor: [
                    '#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6',
                    '#1abc9c', '#34495e', '#e67e22', '#95a5a6', '#d35400'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

function renderSymbols(data) {
    const components = data.components || {};
    const symbolMap = {};
    const isSingle = data.meta?.report_type === 'single';

    /* For single reports, use openssl_symbols.by_category directly */
    if (isSingle && data.openssl_symbols?.by_category) {
        const byCategory = data.openssl_symbols.by_category;
        const byFile = data.openssl_symbols.by_file || {};

        /* Build symbol -> files mapping */
        const symbolToFiles = {};
        Object.entries(byFile).forEach(([path, info]) => {
            const fileName = path.split('/').pop();
            (info.symbols || []).forEach(sym => {
                if (!symbolToFiles[sym]) symbolToFiles[sym] = [];
                if (!symbolToFiles[sym].includes(fileName)) {
                    symbolToFiles[sym].push(fileName);
                }
            });
        });

        /* Build symbolMap from categories */
        Object.entries(byCategory).forEach(([cat, catData]) => {
            (catData.symbols || []).forEach(sym => {
                if (!symbolMap[sym]) {
                    symbolMap[sym] = {
                        components: symbolToFiles[sym] || [],
                        category: cat
                    };
                }
            });
        });
    } else {
        /* Aggregated report format */
        Object.entries(components).forEach(([compName, comp]) => {
            Object.entries(comp.by_category || {}).forEach(([cat, catData]) => {
                const symbols = typeof catData === 'object' ? catData.symbols || [] : [];
                symbols.forEach(sym => {
                    if (!symbolMap[sym]) {
                        symbolMap[sym] = { components: [], category: cat };
                    }
                    if (!symbolMap[sym].components.includes(compName)) {
                        symbolMap[sym].components.push(compName);
                    }
                });
            });
        });
    }

    window.symbolData = Object.entries(symbolMap).map(([name, info]) => ({
        name,
        components: info.components,
        category: info.category
    })).sort((a, b) => a.name.localeCompare(b.name));

    renderSymbolTable(window.symbolData);
}

function renderSymbolTable(symbols) {
    const table = document.getElementById('symbolsTable');
    table.innerHTML = `
        <thead>
            <tr>
                <th>Symbol</th>
                <th>Components</th>
                <th>Category</th>
            </tr>
        </thead>
        <tbody>
            ${symbols.slice(0, 500).map(s => `
                <tr>
                    <td>${s.name}</td>
                    <td>${s.components.join(', ')}</td>
                    <td>${s.category}</td>
                </tr>
            `).join('')}
        </tbody>
    `;
    if (symbols.length > 500) {
        table.innerHTML += `<tfoot><tr><td colspan="3">Showing 500 of ${symbols.length} symbols. Use filters to narrow down.</td></tr></tfoot>`;
    }
}

function populateFilters(data) {
    const components = data.components || {};
    const categories = new Set();
    const isSingle = data.meta?.report_type === 'single';

    /* Get categories from openssl_symbols for single reports */
    if (isSingle && data.openssl_symbols?.by_category) {
        Object.keys(data.openssl_symbols.by_category).forEach(cat => categories.add(cat));
    } else {
        Object.values(components).forEach(comp => {
            Object.keys(comp.by_category || {}).forEach(cat => categories.add(cat));
        });
    }

    /* Get file/component names */
    let compNames = Object.keys(components);
    if (isSingle && data.openssl_symbols?.by_file) {
        compNames = Object.keys(data.openssl_symbols.by_file).map(p => p.split('/').pop());
    }

    const catFilter = document.getElementById('categoryFilter');
    catFilter.innerHTML = '<option value="">All Categories</option>' +
        [...categories].sort().map(c => `<option value="${c}">${c}</option>`).join('');

    const compFilter = document.getElementById('componentFilter');
    const filterLabel = isSingle ? 'All Files' : 'All Components';
    compFilter.innerHTML = `<option value="">${filterLabel}</option>` +
        compNames.sort().map(c => `<option value="${c}">${c}</option>`).join('');
}

function filterSymbols() {
    const search = document.getElementById('symbolSearch').value.toLowerCase();
    const category = document.getElementById('categoryFilter').value;
    const component = document.getElementById('componentFilter').value;

    const filtered = window.symbolData.filter(s => {
        if (search && !s.name.toLowerCase().includes(search)) return false;
        if (category && s.category !== category) return false;
        if (component && !s.components.includes(component)) return false;
        return true;
    });

    renderSymbolTable(filtered);
}

function showTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    event.target.classList.add('active');
}

function loadFile() {
    document.getElementById('fileInput').click();
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            try {
                const data = JSON.parse(e.target.result);
                renderReport(data);
            } catch (err) {
                alert('Invalid JSON file');
            }
        };
        reader.readAsText(file);
    }
}

function exportExcel() {
    if (!currentData) {
        alert('No data to export');
        return;
    }

    /* Check if SheetJS loaded from CDN */
    if (window.XLSX_LOADED && typeof XLSX !== 'undefined' && XLSX.utils) {
        exportWithSheetJS();
    } else {
        /* Fallback to CSV */
        console.log('Using CSV fallback for export');
        exportAsCSV(currentData, 'openssl_report.xlsx');
    }
}

function exportWithSheetJS() {
    /*
     * Excel export with 8 sheets - matches CLI ExcelExporter exactly:
     * 1. Overview     - Metadata and summary statistics
     * 2. Files        - All scanned files with full attributes
     * 3. File-Symbol  - Flat table for pivot analysis
     * 4. Import Chains - Symbol import paths
     * 5. By Category  - Category-wise symbol statistics
     * 6. By Depth     - Depth-wise symbol statistics
     * 7. Dep Tree     - Flattened dependency tree
     * 8. Errors       - Scan errors and warnings
     */
    const wb = XLSX.utils.book_new();
    const meta = currentData.meta || {};
    const summary = currentData.summary || {};
    const reportType = meta.report_type || 'single';
    const isAggregated = reportType === 'aggregated';

    /* Build symbol-to-category mapping */
    const byCategory = currentData.openssl_symbols?.by_category || {};
    const symToCategory = {};
    Object.entries(byCategory).forEach(([cat, catData]) => {
        (catData.symbols || []).forEach(sym => { symToCategory[sym] = cat; });
    });

    /* ===== Sheet 1: Overview ===== */
    const overviewData = [
        ['REPORT METADATA', ''],
        ['Report Type', reportType],
        ['Tool Version', meta.tool_version || ''],
        ['Scan Time', meta.aggregation_time || meta.scan_time || ''],
        ['Scan Root', meta.scan_root || ''],
        ['Target Architecture', meta.target_arch || ''],
        ['', '']
    ];
    if (isAggregated) {
        overviewData.push(
            ['AGGREGATION INFO', ''],
            ['Source Reports', meta.source_reports_count || 0],
            ['Mapping File', meta.mapping_file || 'None'],
            ['', '']
        );
    }
    overviewData.push(
        ['SUMMARY STATISTICS', ''],
        ['Total Files Scanned', summary.total_files_scanned || summary.total_executables || 0],
        ['Total ELF Files', summary.total_elf_files || summary.total_executables || 0],
        ['Files with OpenSSL Deps', summary.files_with_openssl_deps || summary.total_components || 0],
        ['Total OpenSSL Symbols (refs)', summary.total_openssl_symbols || 0],
        ['Unique OpenSSL Symbols', summary.unique_openssl_symbols || summary.global_unique_symbols || 0],
        ['', '']
    );
    const openssl_libs = summary.openssl_libs_found || [];
    if (openssl_libs.length > 0) {
        overviewData.push(['DETECTED OPENSSL LIBRARIES', '']);
        openssl_libs.forEach(lib => overviewData.push(['', lib]));
    }
    const overviewWs = XLSX.utils.aoa_to_sheet(overviewData);
    overviewWs['!cols'] = [{ wch: 30 }, { wch: 60 }];
    XLSX.utils.book_append_sheet(wb, overviewWs, 'Overview');

    /* ===== Sheet 2: Files ===== */
    const filesData = [['File Path', 'File Name', 'Type', 'Arch', 'OpenSSL Direct', 'OpenSSL Transitive', 'OpenSSL Libs', 'Symbol Count', 'Direct Dependencies']];
    let filesDetail = currentData.files_detail || [];
    if (filesDetail.length === 0) {
        /* Fallback: build from by_file */
        const byFile = currentData.openssl_symbols?.by_file || {};
        Object.entries(byFile).forEach(([path, info]) => {
            filesDetail.push({
                path: path,
                type: path.includes('.so') ? 'shared_library' : 'executable',
                arch: meta.target_arch || '',
                openssl_deps: { direct: false, transitive: true, libs: [] },
                openssl_symbols_used: info.symbols || [],
                direct_deps: []
            });
        });
    }
    filesDetail.forEach(f => {
        const deps = f.openssl_deps || {};
        filesData.push([
            f.path || '',
            (f.path || '').split('/').pop(),
            f.type || '',
            f.arch || '',
            deps.direct ? 'Yes' : 'No',
            deps.transitive ? 'Yes' : 'No',
            (deps.libs || []).join(', '),
            (f.openssl_symbols_used || []).length,
            (f.direct_deps || []).join(', ')
        ]);
    });
    if (filesData.length > 1) {
        const filesWs = XLSX.utils.aoa_to_sheet(filesData);
        filesWs['!cols'] = [{ wch: 60 }, { wch: 25 }, { wch: 15 }, { wch: 10 }, { wch: 15 }, { wch: 18 }, { wch: 40 }, { wch: 12 }, { wch: 60 }];
        XLSX.utils.book_append_sheet(wb, filesWs, 'Files');
    }

    /* ===== Sheet 3: File-Symbol (core pivot table) ===== */
    const fileSymbolData = [['Component', 'Binary', 'Symbol', 'Category']];
    const byFile = currentData.openssl_symbols?.by_file || {};
    Object.entries(byFile).forEach(([path, info]) => {
        const fileName = path.split('/').pop();
        (info.symbols || []).sort().forEach(sym => {
            fileSymbolData.push([fileName, fileName, sym, symToCategory[sym] || 'other']);
        });
    });
    /* For aggregated reports: use executables_detail if available */
    if (fileSymbolData.length === 1 && currentData.components) {
        Object.entries(currentData.components).forEach(([compName, compData]) => {
            const execDetail = compData.executables_detail || {};
            if (Object.keys(execDetail).length > 0) {
                /* Use binary-level detail */
                Object.entries(execDetail).forEach(([binName, binData]) => {
                    Object.entries(binData.by_category || {}).forEach(([cat, catData]) => {
                        (catData.symbols || []).sort().forEach(sym => {
                            fileSymbolData.push([compName, binName, sym, cat]);
                        });
                    });
                });
            } else {
                /* Fallback to component-level aggregation */
                Object.entries(compData.by_category || {}).forEach(([cat, catData]) => {
                    (catData.symbols || []).sort().forEach(sym => {
                        fileSymbolData.push([compName, compName, sym, cat]);
                    });
                });
            }
        });
    }
    if (fileSymbolData.length > 1) {
        const fileSymbolWs = XLSX.utils.aoa_to_sheet(fileSymbolData);
        fileSymbolWs['!cols'] = [{ wch: 60 }, { wch: 25 }, { wch: 35 }, { wch: 18 }];
        XLSX.utils.book_append_sheet(wb, fileSymbolWs, 'File-Symbol');
    }

    /* ===== Sheet 4: Import Chains ===== */
    const importChainsData = [['Source File', 'File Name', 'Symbol', 'Category', 'Import Chain', 'Depth']];
    const importChains = currentData.openssl_symbols?.import_chains || {};
    Object.entries(importChains).sort().forEach(([sym, chains]) => {
        const cat = symToCategory[sym] || 'other';
        (chains || []).forEach(chainItem => {
            let sourceFile, chainStr, depth;
            if (typeof chainItem === 'object') {
                sourceFile = chainItem.source_file || '';
                if (!sourceFile && chainItem.component) {
                    sourceFile = chainItem.component + '/' + (chainItem.binary || '');
                }
                chainStr = chainItem.chain || '';
                depth = chainItem.depth || 0;
            } else {
                sourceFile = '';
                chainStr = chainItem;
                depth = (chainStr.match(/ -> /g) || []).length;
            }
            const fileName = sourceFile ? sourceFile.split('/').pop() : '';
            importChainsData.push([sourceFile, fileName, sym, cat, chainStr, depth]);
        });
    });
    if (importChainsData.length === 1) {
        importChainsData.push(['No import chain data available', '', '', '', '', '']);
    }
    const importChainsWs = XLSX.utils.aoa_to_sheet(importChainsData);
    importChainsWs['!cols'] = [{ wch: 50 }, { wch: 20 }, { wch: 35 }, { wch: 15 }, { wch: 80 }, { wch: 10 }];
    XLSX.utils.book_append_sheet(wb, importChainsWs, 'Import Chains');

    /* ===== Sheet 5: By Category ===== */
    const categoryData = [['Category', 'Symbol Count', 'Percentage', 'Symbols']];
    let catStats = {};
    Object.entries(byCategory).forEach(([cat, catData]) => {
        catStats[cat] = {
            count: catData.count || (catData.symbols || []).length,
            symbols: catData.symbols || []
        };
    });
    /* Fallback for aggregated reports */
    if (Object.keys(catStats).length === 0 && currentData.components) {
        Object.values(currentData.components).forEach(comp => {
            Object.entries(comp.by_category || {}).forEach(([cat, catData]) => {
                if (!catStats[cat]) catStats[cat] = { count: 0, symbols: new Set() };
                const symbols = catData.symbols || [];
                catStats[cat].count += symbols.length;
                symbols.forEach(s => catStats[cat].symbols.add(s));
            });
        });
        Object.keys(catStats).forEach(cat => {
            if (catStats[cat].symbols instanceof Set) {
                catStats[cat].symbols = Array.from(catStats[cat].symbols);
            }
        });
    }
    const totalCatSymbols = Object.values(catStats).reduce((sum, c) => sum + c.count, 0) || 1;
    Object.entries(catStats)
        .sort((a, b) => b[1].count - a[1].count)
        .forEach(([cat, data]) => {
            const pct = ((data.count / totalCatSymbols) * 100).toFixed(1) + '%';
            categoryData.push([cat, data.count, pct, data.symbols.sort().join(', ')]);
        });
    categoryData.push(['TOTAL', totalCatSymbols, '100%', '']);
    const categoryWs = XLSX.utils.aoa_to_sheet(categoryData);
    categoryWs['!cols'] = [{ wch: 20 }, { wch: 15 }, { wch: 12 }, { wch: 100 }];
    XLSX.utils.book_append_sheet(wb, categoryWs, 'By Category');

    /* ===== Sheet 6: By Depth ===== */
    const depthData = [['Depth', 'Description', 'Symbol Count', 'Symbols']];
    const byDepth = currentData.openssl_symbols?.by_depth || {};
    const depthDescs = {
        0: 'Root binary itself',
        1: 'Direct dependencies (depth 1)',
        2: 'Transitive dependencies (depth 2)'
    };
    if (Object.keys(byDepth).length === 0) {
        depthData.push(['No depth data available', '', '', '']);
        depthData.push(['(Depth analysis requires single-binary scan mode)', '', '', '']);
    } else {
        Object.keys(byDepth).sort().forEach(depthKey => {
            const depthInfo = byDepth[depthKey];
            const depthNum = parseInt(depthKey.replace('depth_', ''), 10) || 0;
            const desc = depthDescs[depthNum] || ('Transitive dependencies (depth ' + depthNum + ')');
            const count = depthInfo.count || (depthInfo.symbols || []).length;
            depthData.push([depthNum, desc, count, (depthInfo.symbols || []).sort().join(', ')]);
        });
    }
    const depthWs = XLSX.utils.aoa_to_sheet(depthData);
    depthWs['!cols'] = [{ wch: 10 }, { wch: 35 }, { wch: 15 }, { wch: 100 }];
    XLSX.utils.book_append_sheet(wb, depthWs, 'By Depth');

    /* ===== Sheet 7: Dep Tree (flattened) ===== */
    const depTreeData = [['Parent', 'Child', 'Depth', 'Is OpenSSL Lib', 'Symbol Count', 'Full Path']];
    const depTree = currentData.dependency_tree;
    if (!depTree) {
        depTreeData.push(['No dependency tree data available', '', '', '', '', '']);
        depTreeData.push(['(Dependency tree requires single-binary scan mode)', '', '', '', '', '']);
    } else {
        function flattenTree(node, parent, depth) {
            depTreeData.push([
                parent || '(root)',
                node.name || '',
                depth,
                node.is_openssl_lib ? 'Yes' : 'No',
                node.openssl_symbols_count || 0,
                node.path || ''
            ]);
            (node.children || []).forEach(child => flattenTree(child, node.name, depth + 1));
        }
        flattenTree(depTree, null, 0);
    }
    const depTreeWs = XLSX.utils.aoa_to_sheet(depTreeData);
    depTreeWs['!cols'] = [{ wch: 25 }, { wch: 25 }, { wch: 10 }, { wch: 15 }, { wch: 12 }, { wch: 60 }];
    XLSX.utils.book_append_sheet(wb, depTreeWs, 'Dep Tree');

    /* ===== Sheet 8: Errors ===== */
    const errorsData = [['Severity', 'File', 'Error Message']];
    const errors = currentData.errors || [];
    if (errors.length === 0) {
        errorsData.push(['No errors', '', '']);
    } else {
        errors.forEach(err => {
            if (typeof err === 'object') {
                errorsData.push([
                    (err.severity || 'warning').toUpperCase(),
                    err.file || '',
                    err.error || ''
                ]);
            } else {
                errorsData.push(['WARNING', '', String(err)]);
            }
        });
    }
    const errorsWs = XLSX.utils.aoa_to_sheet(errorsData);
    errorsWs['!cols'] = [{ wch: 12 }, { wch: 50 }, { wch: 60 }];
    XLSX.utils.book_append_sheet(wb, errorsWs, 'Errors');

    XLSX.writeFile(wb, 'openssl_report.xlsx');
}

/* Component Detail Modal Functions */
function showComponentDetail(componentName) {
    const modal = document.getElementById('componentModal');
    const title = document.getElementById('modalTitle');
    const summary = document.getElementById('modalSummary');
    const body = document.getElementById('modalBody');

    title.textContent = componentName;

    /* Get component data */
    const compData = currentData.components?.[componentName];
    const isSingle = currentData.meta?.report_type === 'single';

    if (!compData && isSingle) {
        /* For single reports, build from openssl_symbols */
        const byFile = currentData.openssl_symbols?.by_file || {};
        const byCategory = currentData.openssl_symbols?.by_category || {};

        /* Find matching file */
        let fileData = null;
        let filePath = '';
        for (const [path, info] of Object.entries(byFile)) {
            if (path.endsWith('/' + componentName) || path === componentName) {
                fileData = info;
                filePath = path;
                break;
            }
        }

        if (!fileData) {
            body.innerHTML = '<p>No data found for this component.</p>';
            modal.classList.add('active');
            return;
        }

        /* Build category-grouped symbols */
        const symbolsByCategory = {};
        (fileData.symbols || []).forEach(sym => {
            let found = false;
            for (const [cat, catInfo] of Object.entries(byCategory)) {
                if (catInfo.symbols && catInfo.symbols.includes(sym)) {
                    if (!symbolsByCategory[cat]) symbolsByCategory[cat] = [];
                    symbolsByCategory[cat].push(sym);
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (!symbolsByCategory['other']) symbolsByCategory['other'] = [];
                symbolsByCategory['other'].push(sym);
            }
        });

        renderComponentModal(summary, body, {
            totalSymbols: fileData.count || fileData.symbols?.length || 0,
            categoryCount: Object.keys(symbolsByCategory).length,
            binaryCount: 1,
            symbolsByCategory: symbolsByCategory,
            executables: null
        });
    } else if (compData) {
        /* Aggregated report format - check for executables_detail */
        const execDetail = compData.executables_detail || {};
        const hasDetail = Object.keys(execDetail).length > 0;

        if (hasDetail) {
            /* Three-level hierarchy: Component -> Binary -> Category */
            renderComponentModalWithBinaries(summary, body, compData);
        } else {
            /* Legacy format: Component -> Category */
            const symbolsByCategory = {};
            Object.entries(compData.by_category || {}).forEach(([cat, catData]) => {
                const symbols = typeof catData === 'object' ? catData.symbols || [] : [];
                if (symbols.length > 0) {
                    symbolsByCategory[cat] = symbols;
                }
            });

            renderComponentModal(summary, body, {
                totalSymbols: compData.unique_symbols_count || compData.unique_symbols?.length || 0,
                categoryCount: Object.keys(symbolsByCategory).length,
                binaryCount: compData.executables?.length || 0,
                symbolsByCategory: symbolsByCategory,
                executables: compData.executables
            });
        }
    } else {
        body.innerHTML = '<p>No data found for this component.</p>';
    }

    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
}

function renderComponentModalWithBinaries(summary, body, compData) {
    /* Three-level hierarchy: Component -> Binary -> Category */
    const execDetail = compData.executables_detail || {};
    const binaryCount = Object.keys(execDetail).length;
    const totalSymbols = compData.unique_symbols_count || 0;
    const categoryCount = Object.keys(compData.by_category || {}).length;

    /* Render summary stats */
    summary.innerHTML = `
        <div class="stat">
            <div class="value">${binaryCount}</div>
            <div class="label">Binaries</div>
        </div>
        <div class="stat">
            <div class="value">${totalSymbols}</div>
            <div class="label">Total APIs</div>
        </div>
        <div class="stat">
            <div class="value">${categoryCount}</div>
            <div class="label">Categories</div>
        </div>
    `;

    /* Sort binaries by symbol count (descending) */
    const sortedBinaries = Object.entries(execDetail)
        .sort((a, b) => (b[1].unique_symbols_count || 0) - (a[1].unique_symbols_count || 0));

    /* Render binary sections */
    body.innerHTML = sortedBinaries.map(([binName, binData]) => {
        const binCategories = binData.by_category || {};
        const sortedCats = Object.entries(binCategories)
            .sort((a, b) => (b[1].count || b[1].symbols?.length || 0) - (a[1].count || a[1].symbols?.length || 0));

        return `
            <div class="binary-section">
                <div class="binary-header" onclick="toggleBinarySection(this)">
                    <span class="binary-toggle">&#9654;</span>
                    <span class="binary-name">${binName}</span>
                    <span class="binary-stats">${binData.unique_symbols_count || 0} APIs in ${sortedCats.length} categories</span>
                </div>
                <div class="binary-content" style="display:none;">
                    ${sortedCats.map(([cat, catData]) => {
                        const symbols = catData.symbols || [];
                        return `
                            <div class="category-section">
                                <h3>
                                    <span>${cat}</span>
                                    <span class="count">${symbols.length} APIs</span>
                                </h3>
                                <div class="symbol-list">
                                    ${symbols.sort().map(s => `<span class="symbol-tag">${s}</span>`).join('')}
                                </div>
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>
        `;
    }).join('');
}

function toggleBinarySection(header) {
    const content = header.nextElementSibling;
    const toggle = header.querySelector('.binary-toggle');
    if (content.style.display === 'none') {
        content.style.display = 'block';
        toggle.innerHTML = '&#9660;';
        header.classList.add('expanded');
    } else {
        content.style.display = 'none';
        toggle.innerHTML = '&#9654;';
        header.classList.remove('expanded');
    }
}

function renderComponentModal(summary, body, data) {
    /* Render summary stats */
    summary.innerHTML = `
        <div class="stat">
            <div class="value">${data.totalSymbols}</div>
            <div class="label">Total APIs</div>
        </div>
        <div class="stat">
            <div class="value">${data.categoryCount}</div>
            <div class="label">Categories</div>
        </div>
    `;

    /* Sort categories by symbol count (descending) */
    const sortedCategories = Object.entries(data.symbolsByCategory)
        .sort((a, b) => b[1].length - a[1].length);

    /* Render category sections */
    body.innerHTML = sortedCategories.map(([cat, symbols]) => `
        <div class="category-section">
            <h3>
                <span>${cat}</span>
                <span class="count">${symbols.length} APIs</span>
            </h3>
            <div class="symbol-list">
                ${symbols.sort().map(s => `<span class="symbol-tag">${s}</span>`).join('')}
            </div>
        </div>
    `).join('');
}

function closeModal() {
    const modal = document.getElementById('componentModal');
    modal.classList.remove('active');
    document.body.style.overflow = '';
}

/* Close modal on outside click */
document.addEventListener('click', function(e) {
    const modal = document.getElementById('componentModal');
    if (e.target === modal) {
        closeModal();
    }
});

/* Close modal on Escape key */
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeModal();
    }
});
'''

    def _get_chartjs_minimal(self) -> str:
        """Get self-contained SVG chart implementation (no external deps)."""
        return '''
/* Self-contained SVG Chart Implementation - No External Dependencies */
const ChartRegistry = {
    instances: {},
    getChart: function(canvas) {
        return this.instances[canvas.id];
    }
};

function createChart(ctx, config) {
    const canvas = ctx.canvas;
    if (!canvas) {
        console.error('Chart: canvas not found');
        return { destroy: function() {} };
    }
    const container = canvas.parentElement;
    if (!container) {
        console.error('Chart: container not found');
        return { destroy: function() {} };
    }

    /* Get dimensions with fallbacks */
    let width = container.clientWidth || container.offsetWidth || 600;
    let height = container.clientHeight || container.offsetHeight || 300;

    /* Ensure minimum dimensions */
    if (width < 100) width = 600;
    if (height < 100) height = 300;

    /* Replace canvas with SVG */
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '100%');
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    svg.style.display = 'block';

    canvas.style.display = 'none';
    container.appendChild(svg);

    const colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6',
                    '#1abc9c', '#34495e', '#e67e22', '#95a5a6', '#d35400',
                    '#c0392b', '#27ae60', '#2980b9', '#8e44ad', '#f1c40f'];

    if (config.type === 'bar' && config.options?.indexAxis === 'y') {
        drawHorizontalBarChart(svg, config.data, width, height, colors);
    } else if (config.type === 'doughnut') {
        drawDoughnutChart(svg, config.data, width, height, colors);
    }

    const instance = {
        canvas: canvas,
        container: container,
        svg: svg,
        destroy: function() {
            if (this.svg && this.svg.parentElement) {
                this.svg.remove();
            }
            this.canvas.style.display = 'block';
            delete ChartRegistry.instances[this.canvas.id];
        }
    };

    ChartRegistry.instances[canvas.id] = instance;
    return instance;
}

function drawHorizontalBarChart(svg, data, width, height, colors) {
    const labels = data.labels || [];
    const values = data.datasets?.[0]?.data || [];
    const maxVal = Math.max(...values, 1);

    const margin = { top: 20, right: 20, bottom: 20, left: 120 };
    const chartW = width - margin.left - margin.right;
    const chartH = height - margin.top - margin.bottom;
    const barHeight = Math.min(25, (chartH / labels.length) * 0.7);
    const barGap = (chartH - barHeight * labels.length) / (labels.length + 1);

    labels.forEach((label, i) => {
        const y = margin.top + barGap * (i + 1) + barHeight * i;
        const barW = (values[i] / maxVal) * chartW;

        /* Label */
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', margin.left - 5);
        text.setAttribute('y', y + barHeight / 2 + 4);
        text.setAttribute('text-anchor', 'end');
        text.setAttribute('font-size', '11');
        text.setAttribute('fill', '#333');
        text.textContent = label.length > 15 ? label.substring(0, 15) + '...' : label;
        svg.appendChild(text);

        /* Bar */
        const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        rect.setAttribute('x', margin.left);
        rect.setAttribute('y', y);
        rect.setAttribute('width', Math.max(barW, 2));
        rect.setAttribute('height', barHeight);
        rect.setAttribute('fill', colors[i % colors.length]);
        rect.setAttribute('rx', '3');
        svg.appendChild(rect);

        /* Value */
        const valText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        valText.setAttribute('x', margin.left + barW + 5);
        valText.setAttribute('y', y + barHeight / 2 + 4);
        valText.setAttribute('font-size', '11');
        valText.setAttribute('fill', '#666');
        valText.textContent = values[i];
        svg.appendChild(valText);
    });
}

function drawDoughnutChart(svg, data, width, height, colors) {
    const labels = data.labels || [];
    const values = data.datasets?.[0]?.data || [];
    const total = values.reduce((a, b) => a + b, 0) || 1;

    const cx = width / 2;
    const cy = height / 2;
    const outerR = Math.min(width, height) / 2 - 40;
    const innerR = outerR * 0.5;

    let startAngle = -Math.PI / 2;

    values.forEach((val, i) => {
        const angle = (val / total) * Math.PI * 2;
        const endAngle = startAngle + angle;

        const x1 = cx + outerR * Math.cos(startAngle);
        const y1 = cy + outerR * Math.sin(startAngle);
        const x2 = cx + outerR * Math.cos(endAngle);
        const y2 = cy + outerR * Math.sin(endAngle);
        const x3 = cx + innerR * Math.cos(endAngle);
        const y3 = cy + innerR * Math.sin(endAngle);
        const x4 = cx + innerR * Math.cos(startAngle);
        const y4 = cy + innerR * Math.sin(startAngle);

        const largeArc = angle > Math.PI ? 1 : 0;

        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', `M ${x1} ${y1} A ${outerR} ${outerR} 0 ${largeArc} 1 ${x2} ${y2} L ${x3} ${y3} A ${innerR} ${innerR} 0 ${largeArc} 0 ${x4} ${y4} Z`);
        path.setAttribute('fill', colors[i % colors.length]);
        svg.appendChild(path);

        startAngle = endAngle;
    });

    /* Legend */
    const legendX = width - 120;
    let legendY = 20;
    labels.slice(0, 8).forEach((label, i) => {
        const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        rect.setAttribute('x', legendX);
        rect.setAttribute('y', legendY);
        rect.setAttribute('width', '12');
        rect.setAttribute('height', '12');
        rect.setAttribute('fill', colors[i % colors.length]);
        svg.appendChild(rect);

        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', legendX + 16);
        text.setAttribute('y', legendY + 10);
        text.setAttribute('font-size', '10');
        text.setAttribute('fill', '#333');
        text.textContent = label.length > 12 ? label.substring(0, 12) + '..' : label;
        svg.appendChild(text);

        legendY += 18;
    });
}

/* Chart.js compatibility wrapper - must support 'new' keyword */
function ChartConstructor(ctx, config) {
    return createChart(ctx, config);
}
ChartConstructor.prototype.destroy = function() {};
window.Chart = ChartConstructor;
'''

    def _get_sheetjs_minimal(self) -> str:
        """Get SheetJS library embedded locally and CSV fallback."""
        try:
            sheetjs_code = resources.files('openssl_scanner.resources').joinpath(
                'xlsx.full.min.js'
            ).read_text(encoding='utf-8')
        except Exception as e:
            logger.warning(f"Failed to load SheetJS from resources: {e}")
            sheetjs_code = "/* SheetJS not available */"

        return '''
/* SheetJS Library (embedded locally) */
''' + sheetjs_code + '''
window.XLSX_LOADED = (typeof XLSX !== 'undefined');
console.log('SheetJS loaded:', window.XLSX_LOADED ? 'embedded' : 'unavailable');

/* CSV fallback export */
function exportAsCSV(data, filename) {
    const rows = [];

    /* Header */
    rows.push(['OpenSSL Dependency Analysis Report']);
    rows.push([]);

    /* Summary */
    rows.push(['Summary']);
    rows.push(['Components', data.summary?.total_components || data.summary?.files_with_openssl_deps || 0]);
    rows.push(['Total ELF Files', data.summary?.total_executables || data.summary?.total_elf_files || 0]);
    rows.push(['Unique Symbols', data.summary?.global_unique_symbols || data.summary?.unique_openssl_symbols || 0]);
    rows.push([]);

    /* Ranking */
    rows.push(['Ranking']);
    rows.push(['Rank', 'Component', 'Symbols', 'Percentage']);
    const total = data.summary?.global_unique_symbols || data.summary?.unique_openssl_symbols || 1;
    (data.ranking || []).forEach((r, i) => {
        const pct = ((r.unique_symbols_count / total) * 100).toFixed(1);
        rows.push([r.rank || i + 1, r.component, r.unique_symbols_count, pct + '%']);
    });
    rows.push([]);

    /* Symbols */
    rows.push(['All Symbols']);
    rows.push(['Symbol', 'Components', 'Category']);
    (window.symbolData || []).forEach(s => {
        rows.push([s.name, s.components.join('; '), s.category]);
    });

    /* Convert to CSV */
    const csv = rows.map(row =>
        row.map(cell => {
            const str = String(cell == null ? '' : cell);
            return str.includes(',') || str.includes('"') || str.includes('\\n')
                ? '"' + str.replace(/"/g, '""') + '"'
                : str;
        }).join(',')
    ).join('\\n');

    /* Add BOM for Excel UTF-8 compatibility */
    const bom = '\\uFEFF';
    const blob = new Blob([bom + csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename.replace('.xlsx', '.csv');
    a.click();
    URL.revokeObjectURL(url);
}
'''


class Exporter:
    """Main exporter class."""

    def __init__(self) -> None:
        self._excel_exporter = ExcelExporter()
        self._html_exporter = HTMLExporter()

    def export(self, report_path: str, output_path: str,
               format: Optional[str] = None) -> None:
        """
        Export report to specified format.

        Args:
            report_path: Path to JSON report file
            output_path: Output file path
            format: Output format ('xlsx' or 'html'), auto-detected if None
        """
        if not os.path.isfile(report_path):
            raise FileNotFoundError(f"Report file not found: {report_path}")

        if format is None:
            ext = os.path.splitext(output_path)[1].lower()
            format = ext[1:] if ext else 'xlsx'

        if format == 'xlsx':
            self._excel_exporter.export(report_path, output_path)
        elif format in ('html', 'htm'):
            self._html_exporter.export(report_path, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
