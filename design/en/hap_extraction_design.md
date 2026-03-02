# HAP Extraction and Scanning Design

**Module**: `hap_extractor.py` + `hap_report.py` + `__main__.cmd_hap()`

---

## 1. Overview

Extract native `.so` libraries from OpenHarmony packages (HAP/HAR/HSP/APP/ZIP),
scan for OpenSSL dependencies, and output reports.

```
                               +------------------+
*.hap / *.har / *.hsp -+------>| _extract_single  |--+
                       |       +------------------+  |
*.app -----------------+------>| _extract_app     |--+---> Scanner.scan_directory()
                       |       +------------------+  |        |
*.zip -----------------+------>| _extract_zip     |--+        v
                       |       +------------------+       ScanResult
directory of packages -+                                      |
                                                              v
                                                    JSON / XLSX / summary.xlsx
```

## 2. Package Format

```
APP bundle
  +-- entry.hap
  +-- feature.hap
  +-- shared.hsp
  |
  Each HAP/HSP:
    +-- module.json           (metadata)
    +-- libs/
    |   +-- arm64-v8a/        (ABI directory)
    |   |   +-- libentry.so
    |   |   +-- libcrypto.so.3  (bundled OpenSSL, optional)
    |   +-- armeabi-v7a/
    +-- resources/
    +-- ets/
```

| Extension | Description |
|-----------|-------------|
| `.hap` | Harmony Ability Package |
| `.har` | Harmony Archive (shared library) |
| `.hsp` | Harmony Shared Package |
| `.app` | Application bundle, contains HAP/HSP |
| `.zip` | Generic container, may nest packages |

Supported ABIs (priority order):

| ABI | e_machine | Note |
|-----|-----------|------|
| `arm64-v8a` | 0xB7 EM_AARCH64 | primary |
| `armeabi-v7a` | 0x28 EM_ARM | |
| `armeabi` | 0x28 EM_ARM | legacy |
| `x86_64` | 0x3E EM_X86_64 | emulator |
| `x86` | 0x03 EM_386 | emulator |

When no ABI is specified, all ABIs are extracted. `ABI_PRIORITY` only
affects the ordering in metadata.

## 3. Data Structures

### HapMetadata

```python
@dataclass
class HapMetadata:
    package_path: str
    package_type: str          # "hap" / "har" / "hsp" / "app" / "zip"
    bundle_name: str           # app.bundleName
    module_name: str           # module.name
    module_type: str           # "entry" / "feature" / "shared"
    version_name: str
    version_code: int
    min_api_version: int
    device_types: List[str]
    abis_found: List[str]
    native_libs: Dict[str, List[str]]   # ABI -> [filenames]
```

When `module.json` is missing or malformed, all fields fall back to empty
values and extraction proceeds normally.

### HapExtractResult

```python
@dataclass
class HapExtractResult:
    metadata: HapMetadata
    extract_dir: str
    so_files: List[str]
    openssl_lib: Optional[str]      # bundled libcrypto path
    openssl_ssl: Optional[str]      # bundled libssl path
    sub_packages: List[HapExtractResult]
```

APP bundles form a tree structure:

```
HapExtractResult (APP)
  +-- so_files: [all .so merged]
  +-- sub_packages:
       +-- HapExtractResult (entry.hap)
       +-- HapExtractResult (feature.hap)
```

## 4. Extraction Pipeline

### 4.1 Dispatch

```
extract(package_path, abi, extract_dir)
  +-- .app  --> _extract_app()
  +-- .zip  --> _extract_zip()
  +-- other --> _extract_single()
```

### 4.2 _extract_single (HAP/HAR/HSP)

```
Open ZipFile
  -> read module.json
  -> discover libs/<abi>/ (ELF magic check)
  -> build HapMetadata
  -> extract ELF files to <extract_dir>/<abi>/
  -> _detect_openssl() for bundled libcrypto/libssl
```

When no ABI is specified, all ABIs are extracted. Specifying a non-existent
ABI raises ValueError.

### 4.3 _extract_app (APP bundle)

```
Open ZipFile
  -> build APP-level metadata
  -> for each .hap/.hsp entry:
       path traversal check
       _safe_extract_member() to temp
       _extract_single() on sub-package
  -> merge all so_files
```

### 4.4 _extract_zip (recursive)

A ZIP file may be:
- A flat package (containing a libs/ directory)
- A container (nesting .hap/.har/.hsp/.zip inside)
- Both (outer libs + nested packages)

```
Scan for nested packages
  -> none found:         fallback to _extract_single()
  -> depth >= 20:        warn, fallback to _extract_single()
  -> has nested:
       extract outer libs/ (if any)
       for each nested entry:
         deduplicate names (entry_2.hap)
         path traversal check
         create sub_extract_dir/<stem>/
         .zip -> recursive _extract_zip(_depth+1)
         else -> _extract_single()
       merge all so_files
```

Design notes:
- `MAX_ZIP_DEPTH = 20` prevents zip bombs
- Each nested package extracts to its own subdirectory, avoiding `.so` filename collisions
- Outer libs/ and nested packages are both processed

## 5. Security

**Path traversal**: Every extraction path is checked via `os.path.realpath()` confinement.

**Size limit**: `MAX_EXTRACT_SIZE = 20 GB`, written in chunks; partial files
are deleted immediately upon exceeding the limit.

**ELF identification**: Identified by `\x7fELF` magic bytes, not by file extension.
Additionally validates that `e_machine` matches the declared ABI.

## 6. CLI Integration

### 6.1 Planning

```
cmd_hap(args)
  -> collect targets (files + directories)
  -> plan_packages() -> List[PkgEntry]
```

`plan_packages()` expands containers (.zip/.app) into internal entries
without performing extraction:

```python
class PkgEntry:
    path: str           # standalone path, or None
    container: str      # container path, or None
    zip_entry: str      # entry name inside container
    display_name: str   # e.g. "bundle_entry.hap"
```

### 6.2 JIT Extraction

`extract_pkg_entry()` extracts on demand, one package at a time:
- Standalone: returns the path directly
- Container entry: extracts to a temp file, cleaned up in finally block

### 6.3 Scan Flow

```
For each PkgEntry:
  1. incremental check: skip if JSON+XLSX cached and newer than source
  2. extract package -> HapExtractResult
  3. remove bundled OpenSSL libs (prevents scanning OpenSSL itself)
  4. Scanner.scan_directory() with ProcessPoolExecutor
  5. attach package_info to ScanResult
  6. per-package mode: write report immediately
  7. print progress line
```

### 6.4 Output Modes

| Flag | Behavior |
|------|----------|
| `-o report.xlsx` | merged single report |
| `-o /tmp/reports/` | per-package JSON + XLSX + summary.xlsx |
| `--json-only` | suppress XLSX |
| `--force` | ignore cache, rescan all |

### 6.5 Incremental Scanning

In per-package mode, previously scanned packages are skipped via mtime
comparison:

```
cached = (json exists AND json_mtime >= source_mtime)
         AND (json_only OR xlsx exists)
```

Supports resumable batch scanning.

## 7. Summary Report

### 7.1 Classification (`classify_hap_detection`)

Per-file analysis aggregated to package-level classification:

```
detection method: Dynamic / Static / dlopen / Mixed / None

ossl_type (internal):
  Self-Contained  -- all deps resolved within package (mapped to None in output)
  System-Link     -- has unresolved external OpenSSL dependency
  In-APP-Link     -- System-Link resolved by sibling HAP from same app release
  No-OpenSSL      -- no OpenSSL symbols (mapped to None in output)
```

Per-library resolution: each `.so` file's dependencies are evaluated
independently. If any file has an unresolved external dependency, the
package is marked as System-Link. Static providers with high/medium
confidence are added to the bundled set for dependency resolution.

The internal `ossl_type` is then combined with `bundled_openssl` in
`build_hap_summary_row()` to produce the final `openssl_usage` column:

```
bundled_openssl (str "Yes ...")  ->  Bundled (static) / Bundled (static, shared)
bundled_openssl (True)           ->  Bundled
ossl_type == No-OpenSSL          ->  None
ossl_type == System-Link         ->  System-Link
ossl_type == In-APP-Link         ->  In-APP-Link
otherwise                        ->  None
```

Priority: standalone .so > static providers > dependency resolution.

Helper functions:
- `detect_static_providers(scan_result)`:
  Identifies .so files with statically linked OpenSSL (high/medium confidence).
  Deduplicates by basename across ABIs, keeping the highest symbol count.
  Returns `(bundled_str, providers_list)`.
- `_dt_needed_resolved(openssl_libs, bundled_basenames, patterns)`:
  Checks whether all DT_NEEDED OpenSSL libraries are satisfied by bundled
  libraries within the package. Pattern matching uses the original basename
  (not stem), then stem comparison against the bundled set.
- `_dlopen_targets_resolved(dlopen_libs, bundled_basenames, patterns)`:
  Checks whether all dlopen-loaded OpenSSL targets are satisfied by bundled
  libraries within the package. Same logic as above.
- `_deps_include_provider(direct_deps, providers)`:
  Checks whether any DT_NEEDED entry matches a known static OpenSSL provider.
  Used when a file has OpenSSL UND symbols but no OpenSSL-named DT_NEEDED --
  the symbols are routed through a non-OpenSSL lib (e.g. libfoo.so with
  statically linked OpenSSL).

### OpenSSL Usage Classification Reference

| OpenSSL Usage | Meaning | Criteria | Example |
|---|---|---|---|
| None | No OpenSSL usage | All `.so` files have no OpenSSL symbols (UND / .rodata / dlsym), OR all dependencies resolved within the package but no standalone bundled OpenSSL `.so` detected | `libentry.so` calls only system APIs, no crypto involvement |
| Bundled | Ships standalone OpenSSL `.so` | Package `libs/` contains `libcrypto.so*` or `libssl.so*` (matched by `OPENSSL_LIBRARY_PATTERNS`) | `libs/arm64-v8a/` has both `libentry.so` and `libcrypto.so.3` |
| Bundled (static) | OpenSSL statically linked into a `.so`, self-use only | A `.so` in the package has OpenSSL version banner + corroborating symbols, compiled with `-fvisibility=hidden`; no other `.so` in the package has this file in its DT_NEEDED | `libfoo.so` contains `OpenSSL 3.0.9` string internally, no other `.so` depends on it |
| Bundled (static, shared) | OpenSSL statically linked into a `.so` that is shared by other libs | Same as above, but other `.so` files in the package have the static provider in their DT_NEEDED -- the provider acts as an internal OpenSSL facade | `libfoo.so` has static OpenSSL; `libapp.so` DT_NEEDs `libfoo.so` to use OpenSSL through it |
| System-Link | Depends on system-provided OpenSSL | `.so` has OpenSSL UND symbols but DT_NEEDED targets are not found in the package | `libentry.so` DT_NEEDs `libcrypto.so.3` but the package does not contain it |
| In-APP-Link | Resolved by sibling HAP from same app release | Per-HAP classification is System-Link, but a sibling HAP with matching `(bundle_name, version_code, version_name)` bundles the needed OpenSSL library or provides it via static linking | `entry.hap` DT_NEEDs `libcrypto.so.3`; `feature.hap` (same app release) carries `libcrypto.so.3` |

Priority in `build_hap_summary_row()`:

```
bundled_openssl (str "Yes ...")  ->  Bundled (static) / Bundled (static, shared)
bundled_openssl (True)           ->  Bundled
ossl_type == No-OpenSSL          ->  None
ossl_type == System-Link         ->  System-Link
ossl_type == In-APP-Link         ->  In-APP-Link
otherwise (Self-Contained)       ->  None
```

### 7.1.1 Cross-HAP Aggregation (`aggregate_app_classification`)

After per-HAP classification, a second pass reclassifies System-Link HAPs
that are resolved by sibling HAPs from the same app release:

```
Phase 1: Per-HAP Classification
  classify_hap_detection(result) for each HAP
    -> (method, static_syms, dynamic_syms, dlopen_syms, ossl_type)

Phase 2: Cross-HAP Aggregation
  aggregate_app_classification(all_results, per_hap_classifications)
    -> updated classifications with In-APP-Link where applicable
```

**Grouping key:** HAPs are grouped by `(bundle_name, version_code, version_name)` --
the canonical app-release identity from `module.json`'s `app` section. All HAPs from
the same app release share these three values regardless of packaging format (.app
container, .zip bundle, or standalone files).

When metadata is missing, `bundle_name` and `version_code` fall back to `package_path`
(unique per package), ensuring no false grouping.

Flow:

```
                    all_results[]
                         |
              group by (bundle_name, version_code, version_name)
              with package_path fallback for missing fields
                         |
              +----------+-----------+
              |                      |
         group size >= 2        group size == 1
              |                      |
              v                      v
     +------------------+     no aggregation
     | APP release      |     (keep per-HAP)
     | member_idxs[]    |
     +------------------+
              |
    collect from all members:
      app_bundles = bundled_openssl_files
                  + static providers (high/medium)
      app_providers = {member_idx: {provider .so names}}
              |
    for each System-Link member:
      sibling_provs = providers from other members (exclude self)
      re-classify with extra_bundled + sibling_providers
              |
         +----+----+
         |         |
     resolves   still
     to Self-   System-
     Contained  Link
         |         |
         v         v
    In-APP-Link  unchanged
```

Two resolution paths can upgrade System-Link to In-APP-Link:

| Path | Mechanism | Example |
|------|-----------|---------|
| Stem match | Sibling bundles standalone `libcrypto.so.3`, resolves consumer's `DT_NEEDED: libcrypto.so.3` via `_lib_stem()` comparison | feature.hap ships `libcrypto.so.3`, entry.hap links against it |
| Provider match | Sibling has `libfoo.so` with static OpenSSL (high/medium confidence), consumer's `DT_NEEDED: libfoo.so` resolved by `_deps_include_provider()` | feature.hap ships `libfoo.so` (static OpenSSL inside), entry.hap's `libapp.so` DT_NEEDs `libfoo.so` |

Guard rules:
- HAPs grouped by semantic identity `(bundle_name, version_code, version_name)`
- Missing `bundle_name` or `version_code` falls back to `package_path` (no false grouping)
- At least 2 members required for aggregation (single-member groups unchanged)
- Low-confidence static providers are excluded
- Self-providers are excluded (a HAP cannot resolve its own System-Link)
- Input classification list is not mutated (returns new list)

### 7.2 Summary XLSX

`generate_hap_summary()` output:

| Column | Content |
|--------|---------|
| Package Name | bundle_name or filename |
| Type | hap/har/hsp/app/zip |
| Version | version_name |
| ABI | comma-separated |
| .so Files | native lib count |
| OpenSSL Usage | None / System-Link / In-APP-Link / Bundled / Bundled (static) / Bundled (static, shared) |
| Detection | Dynamic / Static / dlopen / Mixed |
| Static Symbols | per-package static symbol count |
| Dynamic Symbols | per-package dynamic symbol count |
| dlopen Symbols | per-package dlopen symbol count |
| Total Symbols | per-package total symbol count |
| Top Category | most-used category |
| ssl_core | symbol count in ssl_core |
| crypto_evp | symbol count in crypto_evp |
| crypto_x509 | symbol count in crypto_x509 |
| crypto_ec | symbol count in crypto_ec |
| crypto_hash | symbol count in crypto_hash |
| crypto_sm | symbol count in crypto_sm |
| crypto_bio | symbol count in crypto_bio |
| Other Cats | remaining categories combined |
| dlopen Libs | detected library names |
| Custom Match | non-OpenSSL library matches (e.g., "mbedTLS (167)") |

The TOTAL row uses arithmetic summation (each column = sum of per-package
values), so that Excel users see TOTAL = SUM(visible rows), matching
spreadsheet conventions.

### 7.3 `hap-summary` Subcommand

Regenerates summary.xlsx from existing JSON reports without re-scanning:

```
collect *.json -> load_scan_result_from_json() -> generate_hap_summary()
```

## 8. Filename Collision

Three layers of deduplication:

1. **Nested package names**: Duplicate names within the same ZIP get
   auto-suffixed (`entry_2.hap`)
2. **Output files**: `resolve_hap_output_names()` ensures unique output paths
3. **Container expansion**: `plan_packages()` adds container prefix to
   internal packages (`bundle_entry.hap`)

## 9. OpenSSL Detection

### Bundled Library Detection

Matches `OPENSSL_LIBRARY_PATTERNS` (basename prefix):
`libcrypto.`, `libcrypto-`, `libcrypto_`, `libssl.`, `libssl-`, `libssl_`,
`libcrypto_openssl`, `libssl_openssl`, `libopenssl`,
`libboringssl`, `libboringcrypto`

Matching libraries are **removed** from the extraction directory before
scanning, to avoid scanning OpenSSL itself and generating spurious
self-referencing symbols.

### Three Detection Methods

| Method | Mechanism |
|--------|-----------|
| Dynamic | `.dynsym` UND symbols vs OpenSSL exports |
| Static | version banner + corroborating symbols + `-fvisibility=hidden` |
| dlopen | string clustering + disassembly cross-reference |

## 10. Error Handling

| Scenario | Behavior |
|----------|----------|
| module.json missing/malformed | empty metadata, continue |
| Invalid ZIP entry / BadZipFile | warn, skip |
| Architecture mismatch | warn, extract anyway |
| Size limit exceeded | delete partial, raise |
| No native libs | return empty result |
| Path traversal | warn, skip |
| Max depth exceeded | warn, treat as flat |

Cleanup: `HapExtractor.cleanup()` recursively removes temporary directories;
`cmd_hap()` cleans up container temp files in its finally block.

## 11. Performance

- **JIT extraction**: Only one package extracted at a time, preventing memory bloat
- **Sequential per-package, parallel per-file**: Sequential package processing
  controls memory; per-file `.so` analysis uses `ProcessPoolExecutor`
- **Bundled lib removal**: Skips libcrypto/libssl to avoid unnecessary scanning
- **Early exit in analysis**: Skips dlopen analysis when no dlopen/dlsym present;
  skips clustering + disassembly when no raw matches found

## 12. File Map

```
src/openssl_scanner/
  hap_extractor.py          extract / _extract_single / _extract_app / _extract_zip
                            _safe_extract_member / _detect_openssl / find_packages
                            cleanup / parse_metadata
  hap_report.py             plan_packages / extract_pkg_entry / merge_hap_results
                            resolve_hap_output_names / hap_write_single_report
                            collect_bundled_names / detect_static_providers
                            classify_hap_detection / aggregate_app_classification
                            build_hap_summary_row / generate_hap_summary
                            load_scan_result_from_json
                            _lib_stem / _dt_needed_resolved / _dlopen_targets_resolved
                            _deps_include_provider
  __main__.py               cmd_hap / cmd_hap_summary
  constants.py              OPENSSL_LIBRARY_PATTERNS
  scanner.py                Scanner.scan_directory / _build_file_result
  custom_matcher.py         CustomMatcher / scan_file / scan_directory
  elf_analyzer.py           extract_rodata_strings (shared by custom_matcher)

tests/
  test_hap_extractor.py
  test_hap_integration.py
  test_custom_matcher.py
  test_reporter.py
```
