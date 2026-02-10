"""
Vendored dependencies for zero-install, offline operation.

Pure Python (cross-platform):
  - elftools (pyelftools): ELF binary parsing
  - openpyxl + et_xmlfile: Excel export

Compiled extensions (multi-platform, bundled in _plat/ subdirs):
  - tree_sitter: AST parsing core (source code scanning)
  - tree_sitter_c: C grammar
  - tree_sitter_cpp: C++ grammar
  - tree_sitter_rust: Rust grammar

Pre-bundled platforms (Python 3.10 - 3.14):
  - macOS arm64, macOS x86_64
  - Linux aarch64, Linux x86_64

Each compiled package uses _plat/{platform}_{arch}/ subdirectories
with __path__ dispatch to load the correct binary at import time.
"""

import os
import sys

_vendor_dir = os.path.dirname(os.path.abspath(__file__))
if _vendor_dir not in sys.path:
    sys.path.insert(0, _vendor_dir)
