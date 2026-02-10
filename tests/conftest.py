"""Pytest configuration: set up vendored dependency paths."""

import os
import sys

vendor_dir = os.path.join(
    os.path.dirname(__file__), '..', 'src', 'openssl_scanner', '_vendor'
)
vendor_dir = os.path.abspath(vendor_dir)
if vendor_dir not in sys.path:
    sys.path.insert(0, vendor_dir)
