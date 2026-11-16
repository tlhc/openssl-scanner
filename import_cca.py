#!/usr/bin/env python3
"""Import cca_compat.xlsx into cca_compat.json beside scan."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))

from openssl_scanner.cca_import import main

if __name__ == '__main__':
    raise SystemExit(main())
