#!/usr/bin/env python3
"""
Build synthetic ELF test binaries using elf_builder.py (pure Python, cross-platform).

Replaces gcc-compiled Mach-O binaries with valid ELF files that pyelftools
can parse on any platform (macOS, Linux, Windows).

Scenarios match test_dlopen_real_elf.py expectations:
  1. direct_link.so    - UND OpenSSL symbols, no dlopen
  2. dlopen_cluster.so - UND dlopen/dlsym + clustered OpenSSL strings in .rodata
  3. dlopen_sparse.so  - UND dlopen/dlsym + sparse OpenSSL strings in .rodata
  4. static_ossl.so    - DEF OpenSSL symbols (simulated static link)
  5. mixed.so          - UND OpenSSL + UND dlopen/dlsym + .rodata strings
  6. no_openssl.so     - No OpenSSL at all
  7. hm_plugin.so      - UND dlopen/dlsym + HarmonyOS lib pattern + OpenSSL strings
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf_builder import ELFBuilder


OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          'dlopen_binaries')


def _pack_rodata_strings(strings):
    """Pack strings as contiguous NULL-terminated C strings (clustered)."""
    parts = []
    for s in strings:
        parts.append(s.encode('ascii') + b'\x00')
    return b''.join(parts)


def _pack_rodata_sparse(entries, pad_size=512):
    """Pack strings with large padding between them (sparse layout)."""
    parts = []
    for s in entries:
        parts.append(s.encode('ascii') + b'\x00')
        parts.append(b'\x00' * pad_size)
    return b''.join(parts)


def build_dlopen_cluster():
    """Scenario 2: dlopen+dlsym with clustered OpenSSL symbols."""
    elf = ELFBuilder(arch='aarch64')
    elf.add_dynsym('dlopen')
    elf.add_dynsym('dlsym')
    elf.add_dynsym('dlerror')
    elf.add_dynsym('fprintf')

    rodata = _pack_rodata_strings([
        'libcrypto.so.3',
        'SSL_CTX_new',
        'SSL_connect',
        'SSL_read',
        'EVP_sha256',
        'EVP_DigestInit_ex',
        'dlopen failed: %s\n',
        'dlsym(%s) failed\n',
    ])
    elf.set_rodata(rodata)
    return elf.build()


def build_dlopen_sparse():
    """Scenario 3: dlopen+dlsym with sparse/isolated symbols."""
    elf = ELFBuilder(arch='aarch64')
    elf.add_dynsym('dlopen')
    elf.add_dynsym('dlsym')
    elf.add_dynsym('printf')

    rodata = _pack_rodata_sparse([
        'libcrypto.so.3',
        'SSL_CTX_new',
        'EVP_sha256',
        'loaded: %p %p from %s %s\n',
    ], pad_size=512)
    elf.set_rodata(rodata)
    return elf.build()


def build_static_ossl():
    """Scenario 4: Defines OpenSSL-named symbols (simulated static build)."""
    elf = ELFBuilder(arch='aarch64')
    elf.add_dynsym('SSL_CTX_new', defined=True)
    elf.add_dynsym('EVP_sha256', defined=True)
    elf.add_dynsym('BIO_new', defined=True)
    elf.add_dynsym('OPENSSL_init_ssl', defined=True)
    elf.add_dynsym('printf')
    return elf.build()


def build_no_openssl():
    """Scenario 6: No OpenSSL at all (negative control)."""
    elf = ELFBuilder(arch='aarch64')
    elf.add_dynsym('printf')
    elf.add_dynsym('snprintf')
    elf.add_dynsym('strlen')

    rodata = b'result=%d\x00no_openssl_here\x00'
    elf.set_rodata(rodata)
    return elf.build()


def build_direct_link():
    """Scenario 1: UND OpenSSL symbols via .dynsym (no dlopen)."""
    elf = ELFBuilder(arch='aarch64')
    elf.add_dynsym('SSL_CTX_new')
    elf.add_dynsym('SSL_connect')
    elf.add_dynsym('SSL_read')
    elf.add_dynsym('EVP_sha256')
    elf.add_dynsym('EVP_DigestInit_ex')
    return elf.build()


def build_mixed():
    """Scenario 5: Direct UND OpenSSL + dlopen for additional symbols."""
    elf = ELFBuilder(arch='aarch64')
    elf.add_dynsym('SSL_CTX_new')
    elf.add_dynsym('SSL_connect')
    elf.add_dynsym('dlopen')
    elf.add_dynsym('dlsym')

    rodata = _pack_rodata_strings([
        'libcrypto.so.3',
        'EVP_DigestInit_ex',
        'EVP_DigestUpdate',
        'EVP_DigestFinal_ex',
    ])
    elf.set_rodata(rodata)
    return elf.build()


def build_hm_plugin():
    """Scenario 7: HarmonyOS-style plugin with dlopen libcrypto_openssl.z.so."""
    elf = ELFBuilder(arch='aarch64')
    elf.add_dynsym('dlopen')
    elf.add_dynsym('dlsym')
    elf.add_dynsym('fprintf')

    rodata = _pack_rodata_strings([
        'libcrypto_openssl.z.so',
        'libssl_openssl.z.so',
        'SSL_CTX_new',
        'SSL_connect',
        'SSL_read',
        'SSL_write',
        'EVP_sha256',
        'EVP_DigestInit_ex',
        'EVP_DigestUpdate',
        'EVP_DigestFinal_ex',
        'missing: %s\n',
    ])
    elf.set_rodata(rodata)
    return elf.build()


SCENARIOS = [
    ('dlopen_cluster.so', build_dlopen_cluster),
    ('dlopen_sparse.so', build_dlopen_sparse),
    ('static_ossl.so', build_static_ossl),
    ('no_openssl.so', build_no_openssl),
    ('direct_link.so', build_direct_link),
    ('mixed.so', build_mixed),
    ('hm_plugin.so', build_hm_plugin),
]


def build_all():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    built = 0
    failed = 0

    for name, builder in SCENARIOS:
        out_path = os.path.join(OUTPUT_DIR, name)
        try:
            data = builder()
            with open(out_path, 'wb') as f:
                f.write(data)
            os.chmod(out_path, 0o755)
            print(f'  OK: {name} ({len(data)} bytes)')
            built += 1
        except Exception as e:
            print(f'  FAIL: {name}: {e}', file=sys.stderr)
            failed += 1

    meta_path = os.path.join(OUTPUT_DIR, 'build_info.txt')
    with open(meta_path, 'w') as f:
        f.write('os=linux\n')
        f.write('arch=aarch64\n')
        f.write('cc=elf_builder.py\n')
        f.write(f'built={built}\n')
        f.write(f'failed={failed}\n')

    print(f'\nBuilt {built}, failed {failed} -> {OUTPUT_DIR}')
    return failed == 0


if __name__ == '__main__':
    ok = build_all()
    sys.exit(0 if ok else 1)
