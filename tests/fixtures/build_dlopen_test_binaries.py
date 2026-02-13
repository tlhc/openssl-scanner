#!/usr/bin/env python3
"""
Build real ELF test binaries for dlopen/dlsym detection integration tests.

Scenarios:
  1. direct_link.so    - Links libcrypto directly (DT_NEEDED + UND symbols)
  2. dlopen_cluster.so - Uses dlopen/dlsym with clustered OpenSSL symbols in .rodata
  3. dlopen_sparse.so  - Uses dlopen/dlsym with isolated OpenSSL symbols (false-positive bait)
  4. static_ossl.so    - Defines (exports) OpenSSL-named symbols (simulated static link)
  5. mixed.so          - Direct link + dlopen for additional symbols
  6. no_openssl.so     - No OpenSSL at all (negative control)
  7. hm_plugin.so      - Simulates HarmonyOS plugin: dlopen libcrypto_openssl.z.so

Cross-platform: builds for the host architecture (macOS arm64/x86_64 or Linux aarch64/x86_64).
"""
import os
import platform
import shutil
import subprocess
import sys
import tempfile


FIXTURE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(FIXTURE_DIR, 'dlopen_binaries')

CC = os.environ.get('CC', 'gcc')
CFLAGS_COMMON = ['-shared', '-fPIC', '-O0', '-Wall']


def _find_cc():
    """Find a working C compiler."""
    for cc in [CC, 'cc', 'gcc', 'clang']:
        if shutil.which(cc):
            return cc
    return None


def _get_host_info():
    """Return (os_name, arch) for host."""
    os_name = sys.platform
    machine = platform.machine().lower()
    if machine in ('arm64', 'aarch64'):
        arch = 'aarch64'
    elif machine in ('x86_64', 'amd64'):
        arch = 'x86_64'
    else:
        arch = machine
    return os_name, arch


def _compile(cc, src_content, output_path, extra_flags=None):
    """Compile C source string to a shared library."""
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(src_content)
        src_path = f.name

    try:
        cmd = [cc] + CFLAGS_COMMON
        if extra_flags:
            cmd.extend(extra_flags)
        cmd.extend(['-o', output_path, src_path])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"WARN: compile failed for {os.path.basename(output_path)}: "
                  f"{result.stderr.strip()}", file=sys.stderr)
            return False
        return True
    finally:
        os.unlink(src_path)


SRC_DIRECT_LINK = r"""
/* Scenario 1: Direct link to libcrypto (UND symbols via -lcrypto stub) */
/* Since we may not have libcrypto, we declare prototypes and call them. */
/* The linker creates UND symbols for these. We use -Wl,-z,lazy to allow unresolved. */
#include <stdio.h>

extern void *SSL_CTX_new(void *method);
extern int SSL_connect(void *ssl);
extern int SSL_read(void *ssl, void *buf, int num);
extern void *EVP_sha256(void);
extern int EVP_DigestInit_ex(void *ctx, const void *type, void *impl);

void init_tls(void) {
    void *ctx = SSL_CTX_new(NULL);
    SSL_connect(ctx);
    SSL_read(ctx, NULL, 0);
    EVP_sha256();
    EVP_DigestInit_ex(NULL, NULL, NULL);
}
"""

SRC_DLOPEN_CLUSTER = r"""
/* Scenario 2: dlopen + dlsym with clustered OpenSSL symbol strings */
#include <dlfcn.h>
#include <stdio.h>

typedef void *(*ssl_ctx_new_fn)(void *);
typedef int (*ssl_connect_fn)(void *);
typedef int (*ssl_read_fn)(void *, void *, int);
typedef void *(*evp_sha256_fn)(void);
typedef int (*evp_digestinit_fn)(void *, const void *, void *);

static const char *ossl_symbols[] = {
    "SSL_CTX_new",
    "SSL_connect",
    "SSL_read",
    "EVP_sha256",
    "EVP_DigestInit_ex",
    NULL
};

void load_openssl(void) {
    void *handle = dlopen("libcrypto.so.3", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return;
    }
    for (int i = 0; ossl_symbols[i]; i++) {
        void *sym = dlsym(handle, ossl_symbols[i]);
        if (!sym) {
            fprintf(stderr, "dlsym(%s) failed\n", ossl_symbols[i]);
        }
    }
}
"""

SRC_DLOPEN_SPARSE = r"""
/* Scenario 3: dlopen + dlsym with sparse/isolated OpenSSL symbol strings */
/* These strings are far apart in .rodata -- should be caught by raw match fallback */
#include <dlfcn.h>
#include <stdio.h>

static const char padding1[512] = "This is a long padding string to create distance between OpenSSL symbols...";
static const char sym1[] = "SSL_CTX_new";
static const char padding2[512] = "Another long padding string to spread out the symbols in the rodata section...";
static const char sym2[] = "EVP_sha256";

void sparse_load(void) {
    void *handle = dlopen("libcrypto.so.3", RTLD_NOW);
    if (!handle) return;
    void *f1 = dlsym(handle, sym1);
    void *f2 = dlsym(handle, sym2);
    printf("loaded: %p %p from %s %s\n", f1, f2, padding1, padding2);
}
"""

SRC_STATIC_OSSL = r"""
/* Scenario 4: Defines OpenSSL-named symbols (simulates static link) */
#include <stdio.h>

void *SSL_CTX_new(void *method) {
    printf("static SSL_CTX_new called\n");
    return NULL;
}

int EVP_sha256(void) {
    return 42;
}

void *BIO_new(void *type) {
    return NULL;
}

void OPENSSL_init_ssl(unsigned long opts, void *settings) {
    printf("static OPENSSL_init_ssl\n");
}
"""

SRC_MIXED = r"""
/* Scenario 5: Direct link (UND) + dlopen for additional symbols */
#include <dlfcn.h>
#include <stdio.h>

extern void *SSL_CTX_new(void *method);
extern int SSL_connect(void *ssl);

static const char *extra_syms[] = {
    "EVP_DigestInit_ex",
    "EVP_DigestUpdate",
    "EVP_DigestFinal_ex",
    NULL
};

void mixed_usage(void) {
    void *ctx = SSL_CTX_new(NULL);
    SSL_connect(ctx);

    void *handle = dlopen("libcrypto.so.3", RTLD_NOW);
    if (!handle) return;
    for (int i = 0; extra_syms[i]; i++) {
        dlsym(handle, extra_syms[i]);
    }
}
"""

SRC_NO_OPENSSL = r"""
/* Scenario 6: No OpenSSL at all (negative control) */
#include <stdio.h>
#include <string.h>

int compute(int x) {
    char buf[64];
    snprintf(buf, sizeof(buf), "result=%d", x * 2);
    return (int)strlen(buf);
}
"""

SRC_HM_PLUGIN = r"""
/* Scenario 7: HarmonyOS-style plugin: dlopen libcrypto_openssl.z.so */
#include <dlfcn.h>
#include <stdio.h>

static const char *hm_symbols[] = {
    "SSL_CTX_new",
    "SSL_connect",
    "SSL_read",
    "SSL_write",
    "EVP_sha256",
    "EVP_DigestInit_ex",
    "EVP_DigestUpdate",
    "EVP_DigestFinal_ex",
    NULL
};

void hm_crypto_init(void) {
    void *h = dlopen("libcrypto_openssl.z.so", RTLD_NOW);
    if (!h) {
        h = dlopen("libssl_openssl.z.so", RTLD_NOW);
    }
    if (!h) return;
    for (int i = 0; hm_symbols[i]; i++) {
        void *fn = dlsym(h, hm_symbols[i]);
        if (!fn) {
            fprintf(stderr, "missing: %s\n", hm_symbols[i]);
        }
    }
}
"""


SCENARIOS = [
    ('dlopen_cluster.so', SRC_DLOPEN_CLUSTER, ['-ldl']),
    ('dlopen_sparse.so', SRC_DLOPEN_SPARSE, ['-ldl']),
    ('static_ossl.so', SRC_STATIC_OSSL, []),
    ('no_openssl.so', SRC_NO_OPENSSL, []),
    ('hm_plugin.so', SRC_HM_PLUGIN, ['-ldl']),
]

SCENARIOS_WITH_UNDEF = [
    ('direct_link.so', SRC_DIRECT_LINK, []),
    ('mixed.so', SRC_MIXED, ['-ldl']),
]


def build_all():
    os_name, arch = _get_host_info()
    cc = _find_cc()
    if not cc:
        print("ERROR: No C compiler found", file=sys.stderr)
        return False

    print(f"Platform: {os_name}/{arch}, compiler: {cc}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    is_macos = os_name == 'darwin'
    undef_flags = ['-Wl,-undefined,dynamic_lookup'] if is_macos else [
        '-Wl,--unresolved-symbols=ignore-all']

    built = 0
    failed = 0

    for name, src, extra in SCENARIOS:
        out = os.path.join(OUTPUT_DIR, name)
        flags = list(extra)
        if is_macos and '-ldl' in flags:
            flags.remove('-ldl')
        if _compile(cc, src, out, flags):
            print(f"  OK: {name}")
            built += 1
        else:
            failed += 1

    for name, src, extra in SCENARIOS_WITH_UNDEF:
        out = os.path.join(OUTPUT_DIR, name)
        flags = undef_flags + list(extra)
        if is_macos and '-ldl' in flags:
            flags.remove('-ldl')
        if _compile(cc, src, out, flags):
            print(f"  OK: {name}")
            built += 1
        else:
            failed += 1

    meta_path = os.path.join(OUTPUT_DIR, 'build_info.txt')
    with open(meta_path, 'w') as f:
        f.write(f"os={os_name}\n")
        f.write(f"arch={arch}\n")
        f.write(f"cc={cc}\n")
        f.write(f"built={built}\n")
        f.write(f"failed={failed}\n")

    print(f"\nBuilt {built}, failed {failed} -> {OUTPUT_DIR}")
    return failed == 0


if __name__ == '__main__':
    ok = build_all()
    sys.exit(0 if ok else 1)
