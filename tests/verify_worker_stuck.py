"""
Verification: Is a worker getting stuck (not crashed) in _build_file_result?

Tests with real ELF files to reproduce the actual workload:
  1. detect_static_ssl() — mmap/read + regex
  2. scan_hidden_static_symbols() — full read + NUL split
  3. detect_dlopen_openssl() — pyelftools + disassembly

The hang symptom: worker takes infinitely long, as_completed blocks.
"""

import os
import sys
import time
import signal
import struct
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed


def _create_fake_elf(path, size_mb=10, has_dlopen=True):
    """Create a minimal ELF binary with .rodata for testing."""
    elf_header = bytearray(64)
    elf_header[0:4] = b'\x7fELF'
    elf_header[4] = 2
    elf_header[5] = 1
    elf_header[6] = 1
    elf_header[16:18] = struct.pack('<H', 3)
    elf_header[18:20] = struct.pack('<H', 62)

    padding = bytearray(size_mb * 1024 * 1024 - 64)

    if has_dlopen:
        marker = b'\x00dlopen\x00dlsym\x00SSL_CTX_new\x00EVP_DigestInit_ex\x00'
        offset = len(padding) // 2
        padding[offset:offset + len(marker)] = marker

    banner = b'\x00OpenSSL 1.1.1t  7 Feb 2023\x00'
    padding[1000:1000 + len(banner)] = banner

    with open(path, 'wb') as f:
        f.write(elf_header)
        f.write(padding)


def _timed_worker(args):
    """Worker that times each phase of the analysis."""
    path, exports = args
    pid = os.getpid()
    timings = {'pid': pid, 'path': os.path.basename(path)}

    t0 = time.monotonic()

    sys.path.insert(0, os.path.join(
        os.path.dirname(__file__), '..', 'src'))

    from openssl_scanner.static_detector import detect_static_ssl, scan_hidden_static_symbols

    t1 = time.monotonic()
    timings['import'] = t1 - t0

    ssl_result = detect_static_ssl(path)
    t2 = time.monotonic()
    timings['detect_static_ssl'] = t2 - t1
    timings['ssl_detected'] = ssl_result.detected

    if ssl_result.detected and exports:
        hidden_syms = scan_hidden_static_symbols(path, exports)
        t3 = time.monotonic()
        timings['scan_hidden'] = t3 - t2
        timings['hidden_count'] = len(hidden_syms)
    else:
        t3 = t2
        timings['scan_hidden'] = 0
        timings['hidden_count'] = 0

    try:
        from openssl_scanner.dlopen_analyzer import detect_dlopen_openssl
        from openssl_scanner.constants import OPENSSL_LIBRARY_PATTERNS

        t4 = time.monotonic()
        timings['dlopen_import'] = t4 - t3

        dlopen_result = detect_dlopen_openssl(
            path, exports, OPENSSL_LIBRARY_PATTERNS,
            strict_mode=True)
        t5 = time.monotonic()
        timings['detect_dlopen'] = t5 - t4
        timings['dlopen_result'] = str(dlopen_result) if dlopen_result else 'None'
    except Exception as e:
        t5 = time.monotonic()
        timings['dlopen_error'] = str(e)

    timings['total'] = t5 - t0
    return timings


def _worker_with_timeout_signal(args):
    """Worker with SIGALRM timeout to detect hangs."""
    path, exports, timeout_sec = args

    def alarm_handler(signum, frame):
        import traceback
        tb = traceback.format_stack(frame)
        raise TimeoutError(
            f"Worker {os.getpid()} stuck for {timeout_sec}s at:\n"
            + ''.join(tb[-5:]))

    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(timeout_sec)

    try:
        result = _timed_worker((path, exports))
        signal.alarm(0)
        return result
    except TimeoutError as e:
        return {'pid': os.getpid(), 'path': os.path.basename(path),
                'TIMEOUT': str(e)}


def load_exports():
    """Load OpenSSL exports from scanner's data files."""
    src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')
    sys.path.insert(0, src_dir)
    try:
        from openssl_scanner.openssl_matcher import OpenSSLMatcher
        matcher = OpenSSLMatcher()
        matcher.load_builtin_symbols()
        return matcher.get_openssl_exports()
    except Exception as e:
        print(f"  Warning: Could not load exports: {e}")
        return set()


def test_actual_scanner_flow():
    """Test with real scanner code on synthetic ELF files."""
    print("\n=== Test: Actual scanner flow timing ===")

    exports = load_exports()
    print(f"  Loaded {len(exports)} OpenSSL exports")

    tmpdir = tempfile.mkdtemp(prefix='fork_verify_')
    print(f"  Temp dir: {tmpdir}")

    sizes = [1, 5, 10, 20, 50]
    elf_files = []
    for size in sizes:
        path = os.path.join(tmpdir, f'lib_test_{size}mb.so')
        _create_fake_elf(path, size_mb=size, has_dlopen=True)
        elf_files.append(path)
        print(f"  Created {os.path.basename(path)} ({size}MB)")

    work_items = [(path, exports) for path in elf_files]

    print(f"\n  Running {len(work_items)} files with 4 workers...")
    executor = ProcessPoolExecutor(max_workers=4)
    try:
        futures = {
            executor.submit(_timed_worker, item): item[0]
            for item in work_items
        }
        for f in as_completed(futures, timeout=60):
            path = futures[f]
            try:
                timings = f.result()
                print(f"  [{timings['pid']}] {timings['path']}:")
                print(f"    import={timings.get('import', 0):.3f}s "
                      f"static_ssl={timings.get('detect_static_ssl', 0):.3f}s "
                      f"hidden={timings.get('scan_hidden', 0):.3f}s "
                      f"dlopen_import={timings.get('dlopen_import', 0):.3f}s "
                      f"dlopen={timings.get('detect_dlopen', 0):.3f}s "
                      f"TOTAL={timings.get('total', 0):.3f}s")
                if 'TIMEOUT' in timings:
                    print(f"    *** TIMEOUT: {timings['TIMEOUT']}")
            except Exception as e:
                print(f"  Error for {os.path.basename(path)}: {e}")
        executor.shutdown(wait=True)
    except TimeoutError:
        print("  GLOBAL TIMEOUT: as_completed blocked for 60s")
        executor.shutdown(wait=False, cancel_futures=True)
    except Exception as e:
        print(f"  Exception: {type(e).__name__}: {e}")

    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_sequential_ppe_with_scanner():
    """Simulate cmd_hap: sequential PPE iterations with real scanner code."""
    print("\n=== Test: Sequential PPE (simulating cmd_hap loop) ===")

    exports = load_exports()
    tmpdir = tempfile.mkdtemp(prefix='fork_seq_')

    for i in range(3):
        path = os.path.join(tmpdir, f'pkg_{i}', 'lib.so')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        _create_fake_elf(path, size_mb=10, has_dlopen=True)

    for iteration in range(3):
        pkg_dir = os.path.join(tmpdir, f'pkg_{iteration}')
        so_path = os.path.join(pkg_dir, 'lib.so')

        print(f"\n  --- Iteration {iteration + 1}/3: {os.path.basename(pkg_dir)} ---")
        t0 = time.monotonic()

        executor = ProcessPoolExecutor(max_workers=2)
        try:
            f = executor.submit(_timed_worker, (so_path, exports))
            result = f.result(timeout=30)
            executor.shutdown(wait=True)

            elapsed = time.monotonic() - t0
            print(f"    total={result.get('total', 0):.3f}s  "
                  f"wall={elapsed:.3f}s  "
                  f"ssl={result.get('detect_static_ssl', 0):.3f}s  "
                  f"dlopen={result.get('detect_dlopen', 0):.3f}s")

        except TimeoutError:
            print(f"    TIMEOUT at iteration {iteration + 1}")
            executor.shutdown(wait=False, cancel_futures=True)
            break
        except Exception as e:
            print(f"    Error: {e}")
            executor.shutdown(wait=False, cancel_futures=True)

    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_with_alarm_timeout():
    """Test with per-worker SIGALRM to catch stuck workers."""
    print("\n=== Test: Workers with SIGALRM timeout (10s per file) ===")

    exports = load_exports()
    tmpdir = tempfile.mkdtemp(prefix='fork_alarm_')

    path = os.path.join(tmpdir, 'big_lib.so')
    _create_fake_elf(path, size_mb=50, has_dlopen=True)
    print(f"  Created 50MB test ELF: {path}")

    work_items = [(path, exports, 10)]

    executor = ProcessPoolExecutor(max_workers=1)
    try:
        f = executor.submit(_worker_with_timeout_signal, work_items[0])
        result = f.result(timeout=30)
        if 'TIMEOUT' in result:
            print(f"  WORKER TIMEOUT: {result['TIMEOUT']}")
        else:
            print(f"  Completed: total={result.get('total', 0):.3f}s")
            for k, v in result.items():
                if k not in ('pid', 'path', 'total'):
                    print(f"    {k}: {v}")
        executor.shutdown(wait=True)
    except TimeoutError:
        print("  GLOBAL TIMEOUT: Worker stuck for >30s")
        executor.shutdown(wait=False, cancel_futures=True)

    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == '__main__':
    print("=" * 60)
    print("Worker Stuck Verification")
    print(f"Python {sys.version}")
    print(f"PID: {os.getpid()}, CPU: {os.cpu_count()}")
    print("=" * 60)

    test_actual_scanner_flow()
    test_sequential_ppe_with_scanner()
    test_with_alarm_timeout()

    print("\n" + "=" * 60)
    print("All tests completed.")
    print("=" * 60)
