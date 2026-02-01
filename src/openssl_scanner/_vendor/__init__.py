"""
Vendored dependencies for offline usage.

This package contains bundled third-party libraries to enable
zero-install operation without pip.

Included:
  - elftools (pyelftools): ELF binary parsing library
"""

import os
import sys

_vendor_dir = os.path.dirname(os.path.abspath(__file__))
if _vendor_dir not in sys.path:
    sys.path.insert(0, _vendor_dir)
