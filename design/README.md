# Design Documents

## HAP Extraction and Scanning

| Language | Document |
|----------|----------|
| English  | [en/hap_extraction_design.md](en/hap_extraction_design.md) |
| Chinese  | [zh/hap_extraction_design.md](zh/hap_extraction_design.md) |

**Module**: `hap_extractor.py` + `__main__.cmd_hap()`

Covers the full pipeline for extracting native `.so` libraries from
OpenHarmony packages (HAP/HAR/HSP/APP/ZIP), scanning for OpenSSL
dependencies, and generating JSON/XLSX reports.
