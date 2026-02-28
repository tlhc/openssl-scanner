# Custom Pattern Scan Design

**Module**: `custom_matcher.py` (new) + `elf_analyzer.py` (extension) + `hap_report.py` (extension)

**Status**: Implemented, pending commit

---

## 1. Overview

Custom string matching runs in parallel with OpenSSL detection within
the existing HAP scan pipeline. The two are fully independent.

```
cmd_hap():
  extract HAP -> .so files
    |
    +-- OpenSSL pipeline (existing)
    |     remove OpenSSL .so -> scan_directory() -> classify
    |
    +-- Custom pattern pipeline (new, runs on remaining .so)
    |     load patterns -> scan .dynsym UND/DEF + .rodata -> aggregate
    |
    +-- build_hap_summary_row(openssl_result, custom_result)
          |
          v
        summary.xlsx (OpenSSL columns + Custom Match column)
```

## 2. Data Storage

File: `data/custom_patterns.json`

```json
{
  "version": "1.0",
  "description": "Custom pattern groups for non-OpenSSL library detection",
  "groups": {
    "openHiTLS": [
      "HITLS_Init",
      "HITLS_CFG_NewConfig",
      "HITLS_Connect",
      "..."
    ],
    "wolfSSL": [
      "wolfSSL_Init",
      "wolfSSL_CTX_new",
      "..."
    ],
    "mbedTLS": [
      "mbedtls_ssl_init",
      "mbedtls_aes_init",
      "..."
    ],
    "libsodium": [
      "sodium_init",
      "crypto_secretbox_easy",
      "..."
    ]
  }
}
```

Current pattern counts: openHiTLS (200), wolfSSL (195), mbedTLS (195),
libsodium (149). Total: 739 unique patterns.

Groups are keyed by library name. New libraries can be added by editing
this file -- no code changes required.

## 3. Detection Mechanism

Each `.so` file is searched across three sources, with deduplication
priority: UND > DEF > rodata.

### 3.1 .dynsym UND (Dynamic Linking)

```
undefined_symbols = elf_analyzer.get_undefined_symbols(path)
matches = set(undefined_symbols) & all_patterns
```

Highest confidence: compile-time dynamic link references.

### 3.2 .dynsym DEF (Static Linking)

```
defined_symbols = elf_analyzer.get_defined_symbols(path)
matches = set(defined_symbols) & all_patterns
```

Detects statically linked libraries that export their symbols
(e.g., Flutter bundling mbedTLS with visible symbols).

### 3.3 .rodata (String Matching)

```
strings = elf_analyzer.extract_rodata_strings(path)
matches = strings & all_patterns
```

No clustering (unlike dlopen_analyzer):
- OpenSSL has 6248 symbols with high accidental match probability,
  requiring cluster-of-3 filtering
- Custom patterns are curated function names with library-specific
  prefixes (BSL_, HITLS_, wolfSSL_, mbedtls_, crypto_), making
  accidental matches extremely unlikely
- Every match is meaningful

### 3.4 Public Function

New in `elf_analyzer.py`:

```python
def extract_rodata_strings(elf_path, section_names=None, min_len=4):
    """Extract printable ASCII strings from .rodata/.data sections.

    Returns Set[str] of unique printable strings.
    """
```

`custom_matcher` calls this public function.

Note: `dlopen_analyzer` retains its own `extract_c_strings_with_offsets()`
implementation because the clustering algorithm requires `(byte_offset,
string)` tuples for byte-proximity calculation, while
`extract_rodata_strings` returns a flat `Set[str]`.

## 4. Data Structures

```python
@dataclass
class CustomMatch:
    file: str          # libfoo.so
    group: str         # wolfSSL
    pattern: str       # wolfSSL_Init
    location: str      # dynsym_und / dynsym_def / rodata

@dataclass
class CustomResult:
    matches: Dict[str, Set[str]]   # group -> matched patterns
    details: List[CustomMatch]      # per-file details

    def summary_text(self) -> str:
        # "wolfSSL (3), openHiTLS (2)"

    @property
    def has_matches(self) -> bool:
        # True if any group has matches
```

### Deduplication Priority

Within `scan_file()`, the same symbol may appear in multiple sources.
Priority determines the `location` tag:

```
1. UND match  -> location = "dynsym_und"   (suppresses DEF + rodata)
2. DEF match  -> location = "dynsym_def"   (suppresses rodata)
3. rodata hit  -> location = "rodata"       (only if not in .dynsym)
```

## 5. Summary XLSX

### New Column

```
_HAP_SUMMARY_COLUMNS appended (last column):
  ('custom_match', 22, 'Custom Match')
```

### Value Format

```
wolfSSL (3)                   -- single library
wolfSSL (3), openHiTLS (2)    -- multiple libraries
(empty)                       -- no matches
```

Number in parentheses = count of unique matched patterns.

### Example

```
+---------------------------+------+---------------+-----------------+
| Package Name              | Type | OpenSSL Usage | Custom Match    |
+---------------------------+------+---------------+-----------------+
| com.foo.app/entry (foo)   | hap  | System-Link   | openHiTLS (5)   |
| com.bar.app/entry (bar)   | hap  | None          | wolfSSL (3)     |
| com.baz.lib (baz)         | har  | Bundled       |                 |
+---------------------------+------+---------------+-----------------+
```

## 6. Per-package JSON

```json
{
  "meta": {
    "package": {
      "...existing fields...",
      "custom_match": "openHiTLS (3)",
      "custom_match_groups": {
        "openHiTLS": ["HITLS_Connect", "HITLS_Init", "HITLS_Read"],
        "wolfSSL": []
      }
    }
  }
}
```

- `custom_match`: summary text, used directly in XLSX Custom Match column
- `custom_match_groups`: per-group matched symbol lists (sorted),
  for JSON detail inspection

Per-package sub-XLSX does not include custom match data (phase 1).

## 7. Default Behavior

- `data/custom_patterns.json` present and non-empty: auto-enabled
- File missing or groups empty: silently skipped, no error
- No CLI flag required to enable

## 8. Implementation Scope

| File | Change | Description |
|------|--------|-------------|
| `data/custom_patterns.json` | New | openHiTLS + wolfSSL + mbedTLS + libsodium (739 patterns) |
| `elf_analyzer.py` | Extension | New `extract_rodata_strings()` public function (returns Set[str]) |
| `dlopen_analyzer.py` | Minor | MAX_SECTION_SIZE adjusted; retains own offset-aware extraction (clustering needs) |
| `custom_matcher.py` | New | CustomMatcher, CustomResult, scan_file/scan_directory |
| `hap_report.py` | Extension | Custom Match column, build_hap_summary_row accepts custom_result |
| `__main__.py` | Modified | cmd_hap() loads custom patterns, invokes custom scan |

## 9. Test Plan

| Test | Coverage |
|------|----------|
| load_patterns: normal / empty / missing / malformed | Loading logic |
| scan_file: .dynsym UND match | Symbol table matching |
| scan_file: .dynsym DEF match | Static link detection |
| scan_file: .rodata match | String matching |
| scan_file: dedup UND > DEF > rodata | Priority logic |
| scan_file: no match / non-ELF / no patterns | Edge cases |
| scan_directory: multi-file aggregation | Per-group merge |
| scan_directory: skips non-.so / corrupt ELF | Robustness |
| summary_text format | "wolfSSL (3)" correctness |
| HAP summary column + build_row | Integration |
| Backward compat: no custom_patterns.json | Graceful degradation |
