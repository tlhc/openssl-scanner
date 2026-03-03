# Source Scan Result Diff Design

**Module**: `source_diff.py` (new) + `__main__.py` (extension)

**Status**: Design phase

---

## 1. Overview

Compare two source scan JSON reports and produce a structured diff at
four layers: summary, symbol, file, and call site. Supports both
single-project (`source_scan`) and multi-project (`combo_scan`) reports.

```
source-diff old.json new.json [-o diff.json|diff.xlsx]

  old.json ----+
               |    load_report()     diff_single()
               +--> normalize paths -> build identity maps
               |                       three-way partition
  new.json ----+                       aggregate layers
                                          |
               +-------- DiffResult ------+
               |              |           |
               v              v           v
          console        diff.json    diff.xlsx
       (human text)    (structured)  (5 sheets)
```

Combo-scan diff adds a fifth layer (project delta) and delegates
per-project comparison to `diff_single()`.

## 2. Use Cases

| Scenario              | Old Report       | New Report       | Focus                          |
|-----------------------|------------------|------------------|--------------------------------|
| Version upgrade audit | v3.1 scan        | v3.2 scan        | New/removed OpenSSL calls      |
| Refactor impact       | Pre-refactor     | Post-refactor    | API surface changed?           |
| Combo-scan comparison | Last full scan   | Current full scan | Which sub-projects changed     |
| CI regression gate    | Baseline JSON    | PR scan JSON     | Exit code 1 if delta non-empty |

## 3. Input Format

Only JSON input is accepted. Every `source` scan already generates a
companion JSON file when XLSX is requested (see `_export_result()`),
so JSON is always available.

Two schemas are supported, auto-detected by `meta.report_type`:

**Single-project** (`report_type: "source_scan"`):
```json
{
  "meta": { "tool_version", "report_type", "scan_time", "target" },
  "summary": {
    "total_files_scanned", "files_with_calls",
    "total_call_sites", "unique_symbols_count",
    "unique_symbols", "symbols_by_category"
  },
  "call_sites": [
    { "file_path", "file_name", "caller_function",
      "line_number", "column", "ossl_symbol",
      "category", "call_args", "language", "detection_method" }
  ],
  "errors": []
}
```

**Multi-project** (`report_type: "combo_scan"`):
```json
{
  "meta": {
    "report_type": "combo_scan", "merge_time",
    "total_projects", "total_call_sites", "total_unique_symbols"
  },
  "projects": [
    {
      "project", "target",
      "total_files_scanned", "files_with_calls",
      "total_call_sites", "unique_symbols",
      "symbols_by_category", "call_sites": [...]
    }
  ]
}
```

## 4. Call Site Identity and Matching

### 4.1 Identity Key

Line numbers drift when code is edited, so the match key is:

```
identity = (relative_file_path, caller_function, ossl_symbol)
```

- `relative_file_path`: relative to `target`, portable across machines
- `caller_function`: stable unless the function is renamed
- `ossl_symbol`: the specific OpenSSL API called

### 4.2 Count-Based Diff

The same identity key can appear multiple times (e.g., `SSL_write`
called three times in `send_data()`). The algorithm compares counts:

```
old_map[key] = [call1, call2, call3]   (3 occurrences)
new_map[key] = [call1, call2, ...]     (5 occurrences)
  -> delta = +2 for this key
```

### 4.3 Matching Algorithm

```
Input:  old_call_sites[], new_call_sites[]

Step 1: Normalize file paths
  rel_path = os.path.relpath(file_path, target)
  Apply --old-prefix / --new-prefix strip if provided

Step 2: Build identity maps
  key = (rel_path, caller_function, ossl_symbol)
  old_map: key -> [{ line, args, category }]
  new_map: key -> [{ line, args, category }]

Step 3: Three-way partition
  added_keys   = new_map.keys() - old_map.keys()
  removed_keys = old_map.keys() - new_map.keys()
  common_keys  = old_map.keys() & new_map.keys()

Step 4: Classify common keys
  for key in common_keys:
    old_count = len(old_map[key])
    new_count = len(new_map[key])
    if old_count == new_count and lines match:
      -> UNCHANGED
    elif old_count == new_count and lines differ:
      -> MOVED (same calls, different line numbers)
    else:
      -> CHANGED (count delta = new_count - old_count)

Step 5: Aggregate upward
  call_site_delta -> symbol_delta   (group by ossl_symbol)
  call_site_delta -> file_delta     (group by file_path)
  file_delta      -> project_delta  (combo only, group by project)
  all             -> summary_delta  (totals)
```

## 5. Diff Layers

### Layer 0: Project Delta (combo_scan only)

```
added_projects:     projects in new but not old
removed_projects:   projects in old but not new
changed_projects:   projects present in both with different call sites
unchanged_projects: projects present in both with identical call sites
```

### Layer 1: Summary Delta

Four metrics, each with `{ old, new, delta }`:

| Metric              | Description                  |
|---------------------|------------------------------|
| total_files_scanned | Total source files parsed    |
| files_with_calls    | Files containing OpenSSL API |
| total_call_sites    | Total call site count        |
| unique_symbols_count| Distinct OpenSSL symbols     |

### Layer 2: Symbol Delta

```
added:    symbols in new but not old
removed:  symbols in old but not new
category_delta: per-category { old_count, new_count, delta }
```

Where "count" is the number of unique symbols in that category (not
call site count).

### Layer 3: File Delta

```
added_files:   files with calls in new but not old
removed_files: files with calls in old but not new
changed_files: files in both with different call counts or symbols
  per file: old_calls, new_calls, delta,
            old_symbols, new_symbols, delta_symbols,
            added_symbols[], removed_symbols[]
unchanged_files_count: integer (not enumerated by default)
```

### Layer 4: Call Site Delta

Most granular level. Each entry has:

```
status:          ADDED | REMOVED | CHANGED | MOVED | UNCHANGED
file_path:       relative path
caller_function: enclosing function name
ossl_symbol:     OpenSSL API name
category:        symbol category
old_line:        line number in old (null if ADDED)
new_line:        line number in new (null if REMOVED)
old_args:        call arguments in old (null if ADDED)
new_args:        call arguments in new (null if REMOVED)
old_count:       occurrences in old (for CHANGED)
new_count:       occurrences in new (for CHANGED)
```

UNCHANGED entries are excluded from output by default.
Use `--include-unchanged` to include them.

## 6. JSON Output Schema

```json
{
  "meta": {
    "report_type": "source_diff",
    "diff_time": "2026-03-03T13:00:00",
    "tool_version": "1.x.x",
    "old_report": "baseline.json",
    "new_report": "current.json",
    "old_scan_time": "2026-02-15T10:00:00",
    "new_scan_time": "2026-03-01T10:00:00"
  },

  "summary_delta": {
    "total_files_scanned":  { "old": 120, "new": 125, "delta": 5  },
    "files_with_calls":     { "old": 45,  "new": 48,  "delta": 3  },
    "total_call_sites":     { "old": 612, "new": 648, "delta": 36 },
    "unique_symbols_count": { "old": 289, "new": 295, "delta": 6  }
  },

  "symbol_delta": {
    "added":   ["EVP_MAC_init", "EVP_MAC_update", "EVP_MAC_final"],
    "removed": ["DES_ecb_encrypt", "DES_set_key"],
    "unchanged_count": 284,
    "category_delta": {
      "crypto_evp":    { "old": 45, "new": 53, "delta": 8 },
      "crypto_legacy": { "old": 12, "new":  9, "delta": -3 }
    }
  },

  "file_delta": {
    "added_files":   ["src/mac_wrapper.c", "src/kdf_new.c"],
    "removed_files": ["src/des_compat.c"],
    "changed_files": [
      {
        "file": "src/tls.c",
        "old_calls": 42,  "new_calls": 47, "delta": 5,
        "old_symbols": 18, "new_symbols": 20, "delta_symbols": 2,
        "added_symbols":   ["SSL_CTX_set_min_proto_version"],
        "removed_symbols": []
      }
    ],
    "unchanged_files_count": 40
  },

  "call_site_delta": [
    {
      "status": "added",
      "file_path": "src/mac_wrapper.c",
      "caller_function": "init_mac",
      "ossl_symbol": "EVP_MAC_init",
      "category": "crypto_evp",
      "new_line": 42,
      "new_args": "(ctx, key, keylen, params)"
    },
    {
      "status": "removed",
      "file_path": "src/des_compat.c",
      "caller_function": "legacy_encrypt",
      "ossl_symbol": "DES_ecb_encrypt",
      "category": "crypto_legacy",
      "old_line": 88,
      "old_args": "(input, output, &ks, DES_ENCRYPT)"
    },
    {
      "status": "changed",
      "file_path": "src/tls.c",
      "caller_function": "init_ssl",
      "ossl_symbol": "SSL_CTX_new",
      "category": "ssl_core",
      "old_count": 1, "new_count": 2, "delta": 1
    },
    {
      "status": "moved",
      "file_path": "src/tls.c",
      "caller_function": "init_ssl",
      "ossl_symbol": "SSL_connect",
      "category": "ssl_core",
      "old_line": 55,
      "new_line": 62,
      "args": "(ssl)"
    }
  ],

  "project_delta": {
    "added_projects":   ["new_module"],
    "removed_projects": ["deprecated_lib"],
    "changed_projects": [
      {
        "project": "curl",
        "old_calls": 612, "new_calls": 624, "delta": 12,
        "old_symbols": 289, "new_symbols": 295, "delta_symbols": 6,
        "symbols_added": ["EVP_MAC_init"],
        "symbols_removed": ["DES_ecb_encrypt"]
      }
    ],
    "unchanged_projects": ["openssl", "zlib"]
  }
}
```

`project_delta` is present only when both inputs are `combo_scan`.

## 7. XLSX Output Layout

### 7.1 Color Scheme

Reuse existing project colors plus diff-specific status fills:

| Use               | Color   | Hex       | Inherited From     |
|-------------------|---------|-----------|--------------------|
| Call site header   | Blue    | `#E8F4FC` | source_exporter.py |
| Summary header     | Green   | `#F0F8E8` | source_exporter.py |
| Status: ADDED      | Lt Green| `#C6EFCE` | (new, Excel std)   |
| Status: REMOVED    | Lt Red  | `#FFC7CE` | (new, Excel std)   |
| Status: CHANGED    | Lt Yellow| `#FFEB9C`| (new, Excel std)   |
| Status: MOVED      | Lt Gray | `#D9D9D9` | (new)              |
| Delta positive     | Green fg| `#006100` | (new, Excel std)   |
| Delta negative     | Red fg  | `#9C0006` | (new, Excel std)   |
| Delta zero         | Gray fg | `#808080` | (new)              |

### 7.2 Sheet 1: Summary Delta

Header fill: `#F0F8E8` (green, consistent with existing Summary sheets).

```
| Metric              | Old    | New    | Delta  |
|---------------------|--------|--------|--------|
| Files Scanned       | 120    | 125    | +5     |
| Files with Calls    | 45     | 48     | +3     |
| Call Sites           | 612    | 648    | +36    |
| Unique Symbols      | 289    | 295    | +6     |
|                     |        |        |        |
| Category Breakdown  |        |        |        |
| crypto_evp          | 45     | 53     | +8     |
| crypto_legacy       | 12     | 9      | -3     |
| ssl_core            | 30     | 30     | 0      |
| ...                 |        |        |        |
```

Delta column: green font for positive, red font for negative, gray for zero.
Rows sorted by absolute delta descending.

Columns: `(Metric, 30), (Old, 12), (New, 12), (Delta, 12)`

### 7.3 Sheet 2: Symbol Delta

Header fill: `#E8F4FC` (blue).

```
| Symbol              | Category       | Status    | Old Calls | New Calls | Delta |
|---------------------|----------------|-----------|-----------|-----------|-------|
| EVP_MAC_init        | crypto_evp     | ADDED     | 0         | 3         | +3    |
| DES_ecb_encrypt     | crypto_legacy  | REMOVED   | 5         | 0         | -5    |
| SSL_CTX_new         | ssl_core       | CHANGED   | 8         | 10        | +2    |
```

- Status column cells: conditional fill per 7.1 color table
- UNCHANGED rows excluded by default; included with `--include-unchanged`
- Sorted by: Status (ADDED > REMOVED > CHANGED > UNCHANGED), then Category, then Symbol

Columns: `(OpenSSL Symbol, 35), (Category, 20), (Status, 12),
          (Old Calls, 12), (New Calls, 12), (Delta, 10)`

### 7.4 Sheet 3: File Delta

Header fill: `#E8F4FC` (blue).

```
| File Path           | Status   | Old Calls | New Calls | Delta | Old Syms | New Syms | Added Symbols       | Removed Symbols     |
|---------------------|----------|-----------|-----------|-------|----------|----------|---------------------|---------------------|
| src/mac_wrapper.c   | ADDED    | 0         | 5         | +5    | 0        | 3        | EVP_MAC_init, ...   |                     |
| src/des_compat.c    | REMOVED  | 8         | 0         | -8    | 4        | 0        |                     | DES_ecb_encrypt,... |
| src/tls.c           | CHANGED  | 42        | 47        | +5    | 18       | 20       | SSL_CTX_set_min_... |                     |
```

Sorted by: Status (ADDED > REMOVED > CHANGED), then absolute delta descending.

Columns: `(File Path, 60), (Status, 12), (Old Calls, 12), (New Calls, 12),
          (Delta, 10), (Old Symbols, 12), (New Symbols, 12),
          (Added Symbols, 40), (Removed Symbols, 40)`

### 7.5 Sheet 4: Call Site Delta

Header fill: `#E8F4FC` (blue).

```
| Status  | File Path       | Caller Function | OpenSSL Symbol | Category     | Old Line | New Line | Old Args              | New Args              |
|---------|-----------------|-----------------|----------------|--------------|----------|----------|-----------------------|-----------------------|
| ADDED   | src/tls.c       | init_ssl        | SSL_CTX_set_.. | ssl_core     |          | 62       |                       | (TLS_1_2_VERSION)     |
| REMOVED | src/des_compat.c| legacy_encrypt  | DES_ecb_encry..| crypto_legacy| 88       |          | (input, output, ...)  |                       |
| MOVED   | src/tls.c       | init_ssl        | SSL_connect    | ssl_core     | 55       | 62       | (ssl)                 | (ssl)                 |
```

Sorted by: Status, then File Path, then New Line (or Old Line for REMOVED).

Columns: `(Status, 12), (File Path, 50), (Caller Function, 30),
          (OpenSSL Symbol, 35), (Category, 20),
          (Old Line, 10), (New Line, 10),
          (Old Args, 50), (New Args, 50)`

### 7.6 Sheet 5: Project Delta (combo_scan only)

Header fill: `#F0F8E8` (green).

```
| Project    | Status    | Old Calls | New Calls | Delta | Old Symbols | New Symbols | Added Symbols       | Removed Symbols     |
|------------|-----------|-----------|-----------|-------|-------------|-------------|---------------------|---------------------|
| curl       | CHANGED   | 612       | 624       | +12   | 289         | 295         | EVP_MAC_init        | DES_ecb_encrypt     |
| new_mod    | ADDED     | 0         | 85        | +85   | 0           | 42          | SSL_CTX_new, ...    |                     |
| depr_lib   | REMOVED   | 42        | 0         | -42   | 18          | 0           |                     | DES_set_key, ...    |
```

Columns: `(Project, 30), (Status, 12), (Old Calls, 12), (New Calls, 12),
          (Delta, 10), (Old Symbols, 12), (New Symbols, 12),
          (Added Symbols, 40), (Removed Symbols, 40)`

## 8. Console Output Format

When no `-o` is specified, print a human-readable summary:

```
  Source Diff: baseline.json -> current.json
  ============================================

  Summary:
    Files Scanned:    120 -> 125  (+5)
    Files with Calls:  45 ->  48  (+3)
    Call Sites:       612 -> 648  (+36)
    Unique Symbols:   289 -> 295  (+6)

  Symbols Added (3):
    + EVP_MAC_init        [crypto_evp]
    + EVP_MAC_update      [crypto_evp]
    + EVP_MAC_final       [crypto_evp]

  Symbols Removed (2):
    - DES_ecb_encrypt     [crypto_legacy]
    - DES_set_key         [crypto_legacy]

  Category Changes:
    crypto_evp:     45 -> 53  (+8)
    crypto_legacy:  12 ->  9  (-3)

  Files Added (2):
    + src/mac_wrapper.c      (5 calls, 3 symbols)
    + src/kdf_new.c          (8 calls, 4 symbols)

  Files Removed (1):
    - src/des_compat.c       (8 calls, 4 symbols)

  Files Changed (3):
    ~ src/tls.c              42 -> 47 calls (+5)
    ~ src/crypto.c           18 -> 22 calls (+4)
    ~ src/ssl_util.c         10 ->  8 calls (-2)
```

For combo-scan diff, prepend a Project Delta section.

## 9. Path Normalization

File paths in two reports may differ due to different checkout locations.

### 9.1 Automatic Normalization

By default, paths are made relative to the `target` field in `meta`:

```python
def _normalize_path(file_path, target):
    if os.path.isabs(file_path) and target:
        return os.path.relpath(file_path, target)
    return file_path
```

### 9.2 Manual Prefix Stripping

When automatic normalization is insufficient (e.g., `target` values
differ across machines), use explicit prefix stripping:

```bash
./scan source-diff old.json new.json \
    --old-prefix /ci/workspace/v3.1/src \
    --new-prefix /ci/workspace/v3.2/src
```

```python
def _strip_prefix(file_path, prefix):
    if prefix and file_path.startswith(prefix):
        return file_path[len(prefix):].lstrip('/')
    return file_path
```

## 10. Module Structure

```
src/openssl_scanner/
  source_diff.py                  (~400-500 lines, new)
    |
    +-- DiffStatus(Enum)
    |     ADDED, REMOVED, CHANGED, MOVED, UNCHANGED
    |
    +-- @dataclass MetricDelta
    |     old: int, new: int, delta: int
    |
    +-- @dataclass CallSiteDelta
    |     status, file_path, caller_function, ossl_symbol, category,
    |     old_line, new_line, old_args, new_args, old_count, new_count
    |
    +-- @dataclass SymbolDelta
    |     symbol, category, status, old_calls, new_calls, delta
    |
    +-- @dataclass FileDelta
    |     file_path, status, old_calls, new_calls, delta,
    |     old_symbols, new_symbols, added_symbols, removed_symbols
    |
    +-- @dataclass ProjectDelta
    |     project, status, old_calls, new_calls, delta,
    |     old_symbols, new_symbols, symbols_added, symbols_removed
    |
    +-- @dataclass DiffResult
    |     meta: dict
    |     summary_delta: dict[str, MetricDelta]
    |     symbol_delta: { added, removed, unchanged_count, category_delta }
    |     file_delta: { added_files, removed_files, changed_files, ... }
    |     call_site_delta: list[CallSiteDelta]
    |     project_delta: optional (combo only)
    |
    |     def is_empty() -> bool
    |       True if no added/removed/changed at any layer
    |
    +-- load_report(path, prefix=None) -> dict
    |     Read JSON, detect report_type, normalize paths
    |
    +-- diff_single(old_data, new_data, ...) -> DiffResult
    |     Core: identity map -> partition -> aggregate
    |
    +-- diff_combo(old_data, new_data, ...) -> DiffResult
    |     Match projects by name, call diff_single per project
    |
    +-- SourceDiffJsonExporter
    |     .export(result: DiffResult, path: str) -> None
    |
    +-- SourceDiffExcelExporter
    |     .export(result: DiffResult, path: str) -> None
    |     5 sheets: Summary Delta, Symbol Delta, File Delta,
    |               Call Site Delta, Project Delta (combo only)
    |
    +-- format_console(result: DiffResult) -> str
          Human-readable text for terminal output
```

CLI addition in `__main__.py` (~80 lines):

```
+-- create_source_diff_parser(subparsers)
+-- cmd_source_diff(args) -> int
```

## 11. CLI Interface

```
openssl-scanner source-diff OLD NEW [-o OUTPUT] [OPTIONS]

Positional:
  OLD                  Baseline report (JSON)
  NEW                  Current report (JSON)

Options:
  -o, --output PATH    Output path (.json or .xlsx); omit for console
  --summary-only       Skip call site delta (layers 1-3 only)
  --include-unchanged  Include unchanged entries in output
  --old-prefix PATH    Strip this prefix from old report paths
  --new-prefix PATH    Strip this prefix from new report paths
  --ignore-categories  Categories to exclude (space-separated)
  -v, --verbose        Increase verbosity
  --log-file PATH      Write logs to file
```

### Exit Codes

| Code | Meaning                              |
|------|--------------------------------------|
| 0    | No changes detected                  |
| 1    | Changes detected (diff is non-empty) |
| 2    | Error (file not found, parse error)  |

Exit code 1 on changes follows `diff(1)` convention, useful for CI gates:

```bash
./scan source-diff baseline.json current.json || echo "API surface changed!"
```

## 12. Usage Examples

```bash
# Quick console diff
./scan source-diff baseline.json current.json

# JSON diff for CI pipeline
./scan source-diff baseline.json current.json -o diff.json

# XLSX diff for human review
./scan source-diff baseline.json current.json -o diff.xlsx

# Summary only (skip thousands of call site entries)
./scan source-diff baseline.json current.json -o diff.xlsx --summary-only

# Cross-machine comparison with different checkout paths
./scan source-diff old.json new.json \
    --old-prefix /ci/workspace/v3.1 \
    --new-prefix /ci/workspace/v3.2

# Combo-scan full comparison
./scan source-diff last_month_combo.json this_month_combo.json -o delta.xlsx

# Filter noisy categories
./scan source-diff old.json new.json --ignore-categories crypto_err openssl_util

# CI gate: fail if OpenSSL API surface changed
./scan source-diff baseline.json pr_scan.json -o /dev/null
if [ $? -eq 1 ]; then
  echo "WARNING: OpenSSL API usage changed in this PR"
fi
```

## 13. Design Decisions

| # | Decision                                    | Rationale                                                    |
|---|---------------------------------------------|--------------------------------------------------------------|
| 1 | JSON-only input (no XLSX)                   | JSON is the data layer; XLSX is presentation. JSON always exists as companion file. |
| 2 | Identity key = (path, function, symbol)     | Resilient to line number drift from unrelated edits.         |
| 3 | Count-based diff for duplicate calls        | Same API called N times in one function is a real pattern. Simple counting handles it. |
| 4 | UNCHANGED excluded by default               | In large codebases, thousands of unchanged entries add noise. Opt-in with flag. |
| 5 | MOVED as separate status                    | Auditors care: "same dependency, code was refactored" is distinct from "no change". |
| 6 | Combo support in v1                         | Marginal cost: combo diff = loop of single diffs + project-level aggregation.        |
| 7 | Exit code 1 for changes                     | Matches `diff(1)` convention; enables CI integration without extra parsing.          |
| 8 | No XLSX-to-XLSX diff                        | Avoids openpyxl read dependency complexity; JSON is canonical data format.            |
| 9 | Status colors match Excel standard palette  | `#C6EFCE`/`#FFC7CE`/`#FFEB9C` are Excel's built-in Good/Bad/Neutral conditional formats. |

## 14. Testing Strategy

```
tests/test_source_diff.py (~400 lines)

Test categories:
  1. load_report()
     - source_scan JSON
     - combo_scan JSON
     - invalid JSON / missing fields
     - path normalization with prefix stripping

  2. diff_single()
     - identical reports -> empty diff, exit code 0
     - added symbols only
     - removed symbols only
     - mixed add/remove/change/move
     - count-based diff (duplicate calls)
     - category delta aggregation
     - file delta aggregation

  3. diff_combo()
     - added/removed projects
     - changed projects delegate to diff_single
     - project name matching

  4. Exporters
     - JSON round-trip (export -> load -> verify structure)
     - XLSX sheet count and header verification
     - Console output format smoke test

  5. CLI integration
     - Exit code 0 (no changes)
     - Exit code 1 (has changes)
     - Exit code 2 (bad input)
     - --summary-only flag
     - --include-unchanged flag
     - --ignore-categories filter
```

## 15. Future Extensions

- **XLSX diff output with hyperlinks**: link changed symbols to documentation
- **HTML diff report**: side-by-side visual comparison
- **Trend tracking**: diff chain across multiple versions (v1 -> v2 -> v3)
- **Threshold alerts**: "warn if more than N new crypto_legacy calls"
- **HAP scan diff**: extend to HAP binary scan results (different JSON schema)
