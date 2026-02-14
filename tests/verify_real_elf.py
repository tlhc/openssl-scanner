"""
Verify with REAL ELF files: time each phase of _build_file_result.

Uses system .so files to reproduce actual workload.
Prints per-phase timings and identifies which phase is slowest.
"""

import os
import sys
import time
import signal
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed

src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src')
sys.path.insert(0, src_dir)


def find_test_libs():
    """Find real ELF .so files of various sizes."""
    targets = []
    search_dirs = [
        '/usr/lib/aarch64-linux-gnu',
        '/usr/lib/x86_64-linux-gnu',
        '/usr/lib64',
        '/usr/lib',
    ]
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if not f.endswith('.so') and '.so.' not in f:
                continue
            path = os.path.join(d, f)
            if not os.path.isfile(path) or os.path.islink(path):
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size < 100 * 1024:
                continue
            targets.append((path, size))

    targets.sort(key=lambda x: x[1])

    selected = []
    for bucket_min, bucket_max, label in [
        (100*1024, 1*1024*1024, 'small'),
        (1*1024*1024, 5*1024*1024, 'medium'),
        (5*1024*1024, 20*1024*1024, 'large'),
        (20*1024*1024, 100*1024*1024, 'xlarge'),
        (100*1024*1024, 10*1024*1024*1024, 'huge'),
    ]:
        bucket = [t for t in targets if bucket_min <= t[1] < bucket_max]
        if bucket:
            selected.append(bucket[-1])

    return selected


def _profile_build_file_result(args):
    """Profile the actual _build_file_result with real ELF."""
    path, openssl_exports = args
    pid = os.getpid()
    timings = {'pid': pid, 'path': os.path.basename(path),
               'size_mb': os.path.getsize(path) / (1024*1024)}

    from openssl_scanner.elf_analyzer import ELFAnalyzer
    from openssl_scanner.static_detector import detect_static_ssl, scan_hidden_static_symbols
    from openssl_scanner.constants import OPENSSL_LIBRARY_PATTERNS

    analyzer = ELFAnalyzer()

    t0 = time.monotonic()
    info = analyzer.analyze(path)
    t1 = time.monotonic()
    timings['elf_analyze'] = t1 - t0

    if not info:
        timings['error'] = 'not ELF'
        return timings

    timings['arch'] = info.arch
    timings['needed'] = len(info.needed_libs)
    timings['undef'] = len(info.undefined_symbols)
    timings['defined'] = len(info.defined_symbols)
    timings['has_dlopen'] = info.has_dlopen
    timings['has_dlsym'] = info.has_dlsym

    undefined_names = [s.name for s in info.undefined_symbols]
    openssl_symbols = [s for s in undefined_names if s in openssl_exports]
    defined_names = [s.name for s in info.defined_symbols]
    openssl_defined = [s for s in defined_names if s in openssl_exports]
    openssl_libs = [lib for lib in info.needed_libs
                    if any(lib.lower().startswith(p)
                           for p in ('libcrypto', 'libssl', 'libcrypto_openssl',
                                     'libssl_openssl', 'libopenssl'))]

    t2 = time.monotonic()
    timings['symbol_filter'] = t2 - t1

    ssl_result = detect_static_ssl(path)
    t3 = time.monotonic()
    timings['detect_static_ssl'] = t3 - t2
    timings['ssl_detected'] = ssl_result.detected
    if ssl_result.detected:
        timings['ssl_library'] = ssl_result.library
        timings['ssl_version'] = ssl_result.version

    hidden_static = False
    if ssl_result.detected and not openssl_defined and not openssl_libs:
        hidden_static = True
        if openssl_exports:
            hidden_syms = scan_hidden_static_symbols(path, openssl_exports)
            t4 = time.monotonic()
            timings['scan_hidden'] = t4 - t3
            timings['hidden_count'] = len(hidden_syms)
        else:
            t4 = t3
    else:
        t4 = t3
        timings['scan_hidden'] = 0

    if (info.has_dlopen or info.has_dlsym) and not hidden_static:
        from openssl_scanner.dlopen_analyzer import detect_dlopen_openssl
        t5 = time.monotonic()
        timings['dlopen_import'] = t5 - t4

        exclude_ossl = set(openssl_symbols) | set(openssl_defined)
        try:
            dlopen_result = detect_dlopen_openssl(
                path, openssl_exports, OPENSSL_LIBRARY_PATTERNS,
                exclude_symbols=exclude_ossl, strict_mode=True)
            t6 = time.monotonic()
            timings['detect_dlopen'] = t6 - t5
            if dlopen_result:
                timings['dlopen_syms'] = len(dlopen_result.dlsym_symbols)
                timings['dlopen_conf'] = dlopen_result.confidence
        except Exception as e:
            t6 = time.monotonic()
            timings['dlopen_error'] = str(e)[:100]
            timings['detect_dlopen'] = t6 - t5
    else:
        t6 = t4
        timings['detect_dlopen'] = 0
        timings['dlopen_skip'] = True

    timings['total'] = t6 - t0

    return timings


def _profile_with_alarm(args):
    """Profile with SIGALRM to catch truly stuck workers."""
    path, exports, timeout = args

    def handler(signum, frame):
        import traceback
        tb = ''.join(traceback.format_stack(frame)[-8:])
        raise TimeoutError(f"STUCK at:\n{tb}")

    old = signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout)
    try:
        result = _profile_build_file_result((path, exports))
        signal.alarm(0)
        return result
    except TimeoutError as e:
        return {'pid': os.getpid(), 'path': os.path.basename(path),
                'size_mb': os.path.getsize(path)/(1024*1024),
                'STUCK': str(e)}
    finally:
        signal.signal(signal.SIGALRM, old)


def main():
    print("=" * 70)
    print("Real ELF Verification — Profile _build_file_result phases")
    print(f"Python {sys.version}")
    print(f"PID: {os.getpid()}, CPU: {os.cpu_count()}")
    print("=" * 70)

    from openssl_scanner.openssl_matcher import OpenSSLMatcher
    matcher = OpenSSLMatcher()
    matcher.load_builtin_symbols()
    exports = matcher.get_openssl_exports()
    print(f"Loaded {len(exports)} OpenSSL exports\n")

    libs = find_test_libs()
    if not libs:
        print("No suitable .so files found!")
        return

    print("Selected test libraries:")
    for path, size in libs:
        print(f"  {os.path.basename(path):40s} {size/1024/1024:8.1f} MB")

    print(f"\n--- Single-threaded profiling (per-file timings) ---\n")

    for path, size in libs:
        timings = _profile_with_alarm((path, exports, 120))
        name = os.path.basename(path)
        sz = size / (1024 * 1024)

        if 'STUCK' in timings:
            print(f"  {name} ({sz:.1f}MB): *** STUCK ***")
            print(f"    {timings['STUCK']}")
            continue

        if 'error' in timings:
            print(f"  {name} ({sz:.1f}MB): {timings['error']}")
            continue

        total = timings.get('total', 0)
        phases = []
        for phase in ['elf_analyze', 'symbol_filter', 'detect_static_ssl',
                       'scan_hidden', 'dlopen_import', 'detect_dlopen']:
            val = timings.get(phase, 0)
            if val > 0.001:
                phases.append(f"{phase}={val:.3f}s")

        flags = []
        if timings.get('has_dlopen'):
            flags.append('dlopen')
        if timings.get('has_dlsym'):
            flags.append('dlsym')
        if timings.get('ssl_detected'):
            flags.append(f"static:{timings.get('ssl_library','?')}")
        if timings.get('dlopen_skip'):
            flags.append('dlopen_skip')

        print(f"  {name} ({sz:.1f}MB): TOTAL={total:.3f}s "
              f"[{', '.join(flags)}]")
        for p in phases:
            print(f"    {p}")

    print(f"\n--- ProcessPoolExecutor(4 workers) all files ---\n")

    work_items = [(path, exports, 120) for path, _ in libs]

    t0 = time.monotonic()
    executor = ProcessPoolExecutor(max_workers=4)
    try:
        futures = {
            executor.submit(_profile_with_alarm, item): item[0]
            for item in work_items
        }
        for f in as_completed(futures, timeout=180):
            path = futures[f]
            try:
                t = f.result()
                name = t.get('path', os.path.basename(path))
                if 'STUCK' in t:
                    print(f"  [{t['pid']}] {name}: *** STUCK ***")
                else:
                    total = t.get('total', 0)
                    dlopen_t = t.get('detect_dlopen', 0)
                    ssl_t = t.get('detect_static_ssl', 0)
                    print(f"  [{t['pid']}] {name} ({t.get('size_mb',0):.1f}MB): "
                          f"total={total:.3f}s ssl={ssl_t:.3f}s dlopen={dlopen_t:.3f}s")
            except Exception as e:
                print(f"  Error for {os.path.basename(path)}: {e}")
        executor.shutdown(wait=True)
    except TimeoutError:
        print("  GLOBAL TIMEOUT: as_completed blocked >180s")
        executor.shutdown(wait=False, cancel_futures=True)

    wall = time.monotonic() - t0
    print(f"\n  Wall time: {wall:.1f}s")

    print(f"\n--- Sequential PPE (3 iterations, simulating cmd_hap) ---\n")

    for i in range(min(3, len(libs))):
        path, size = libs[i]
        name = os.path.basename(path)
        print(f"  Iteration {i+1}: {name} ({size/1024/1024:.1f}MB)")

        t0 = time.monotonic()
        executor = ProcessPoolExecutor(max_workers=2)
        try:
            f = executor.submit(_profile_with_alarm, (path, exports, 60))
            result = f.result(timeout=90)
            executor.shutdown(wait=True)
            wall = time.monotonic() - t0
            if 'STUCK' in result:
                print(f"    *** STUCK ***")
            else:
                print(f"    total={result.get('total',0):.3f}s wall={wall:.3f}s")
        except TimeoutError:
            print(f"    TIMEOUT at iteration {i+1}")
            executor.shutdown(wait=False, cancel_futures=True)
            break
        except Exception as e:
            print(f"    Error: {e}")
            executor.shutdown(wait=False, cancel_futures=True)

    print("\n" + "=" * 70)
    print("Verification complete.")
    print("=" * 70)


if __name__ == '__main__':
    main()
