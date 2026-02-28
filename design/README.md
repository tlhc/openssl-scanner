# Design Documents

## HAP Extraction and Scanning

| Language | Document |
|----------|----------|
| English  | [en/hap_extraction_design.md](en/hap_extraction_design.md) |
| Chinese  | [zh/hap_extraction_design.md](zh/hap_extraction_design.md) |

**Module**: `hap_extractor.py` + `hap_report.py` + `__main__.cmd_hap()`

Covers the full pipeline for extracting native `.so` libraries from
OpenHarmony packages (HAP/HAR/HSP/APP/ZIP), scanning for OpenSSL
dependencies, and generating JSON/XLSX reports.

## Custom Pattern Scan

| Language | Document |
|----------|----------|
| English  | [en/custom_pattern_scan_design.md](en/custom_pattern_scan_design.md) |
| Chinese  | [zh/custom_pattern_scan_design.md](zh/custom_pattern_scan_design.md) |

**Module**: `custom_matcher.py` (new) + `elf_analyzer.py` (extension)

Custom string matching integrated into HAP scan pipeline. Scans
`.dynsym` UND symbols and `.rodata` strings against user-defined
pattern groups (e.g., openHiTLS, wolfSSL). Independent from OpenSSL
detection.
