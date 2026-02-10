"""Vendored ripgrep (rg) binary for fast source file content search.

Platform binaries stored in _plat/{os}_{arch}/rg, following the same
layout as vendored tree-sitter.  Use get_rg_path() to locate the
appropriate binary for the current platform.

To populate binaries:
    openssl-scanner vendor-rg

Supported platforms:
    darwin_arm64, darwin_x86_64, linux_x86_64, linux_aarch64
"""

import os
import platform
import shutil
import sys


def _plat_key():
    """Return platform key matching _plat/ subdirectory name."""
    machine = platform.machine().lower()
    if machine == 'amd64':
        machine = 'x86_64'
    return f"{sys.platform}_{machine}"


def get_rg_path():
    """Find the best available rg binary.

    Search order:
        1. Vendored binary  (_plat/{platform}/rg)
        2. System rg        (in $PATH)

    Returns:
        Absolute path to rg binary, or None.
    """
    plat_dir = os.path.join(os.path.dirname(__file__), '_plat', _plat_key())
    vendored = os.path.join(plat_dir, 'rg')
    if os.path.isfile(vendored) and os.access(vendored, os.X_OK):
        return vendored

    return shutil.which('rg')
