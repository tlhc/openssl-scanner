"""
Verification script for fork-in-fork hang root cause analysis.

Tests:
  A. POSIX semaphore leak when worker dies holding _rlock
  B. Sequential ProcessPoolExecutor resource accumulation (FD leak)
  C. Reproduce actual hang with heavy _build_file_result workload
  D. Logging lock after fork (Python version dependent)

Run on Linux: python3 tests/verify_fork_hang.py
"""

import os
import sys
import time
import signal
import resource
import multiprocessing
import ctypes
from concurrent.futures import ProcessPoolExecutor, as_completed


def _count_open_fds():
    """Count open file descriptors for current process."""
    count = 0
    for fd in range(resource.getrlimit(resource.RLIMIT_NOFILE)[0]):
        try:
            os.fstat(fd)
            count += 1
        except OSError:
            pass
        if fd > 1024:
            break
    return count


def _count_fds_fast():
    """Count open FDs via /proc/self/fd (Linux only)."""
    try:
        return len(os.listdir('/proc/self/fd'))
    except OSError:
        return _count_open_fds()


def _dummy_worker(x):
    """Trivial worker for FD leak test."""
    return x * 2


def _heavy_worker(args):
    """Simulate _build_file_result heavy workload."""
    path, size_mb = args
    import logging
    logger = logging.getLogger(__name__)

    data = bytearray(size_mb * 1024 * 1024)
    logger.debug("Worker %d: allocated %dMB", os.getpid(), size_mb)

    chunks = bytes(data).split(b'\x00')
    result = len(chunks)

    time.sleep(0.1)
    return result


def _worker_that_dies(x):
    """Worker that crashes via SIGKILL (simulating OOM kill)."""
    if x == 0:
        os.kill(os.getpid(), signal.SIGKILL)
    time.sleep(0.5)
    return x


def _worker_hold_and_die(q):
    """Worker that holds queue lock and dies."""
    os.kill(os.getpid(), signal.SIGKILL)


def test_a_semaphore_on_worker_death():
    """Test A: Does worker death while in call_queue.get cause deadlock?

    Theory: Worker acquires _rlock (POSIX semaphore) in call_queue.get(),
    gets OOM-killed, semaphore not released, other workers block forever.
    """
    print("\n=== Test A: POSIX semaphore behavior on worker death ===")

    executor = ProcessPoolExecutor(max_workers=4)
    futures = []

    try:
        for i in range(8):
            futures.append(executor.submit(_worker_that_dies, i))

        completed = 0
        broken = False
        for f in as_completed(futures, timeout=10):
            try:
                f.result()
                completed += 1
            except Exception as e:
                print(f"  Future exception: {type(e).__name__}: {e}")
                broken = True
    except TimeoutError:
        print("  TIMEOUT: as_completed blocked for 10s — confirms deadlock theory")
        broken = True
    except Exception as e:
        print(f"  Pool exception: {type(e).__name__}: {e}")
        broken = True
    finally:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    if broken:
        print("  RESULT: Worker death DOES cause pool breakage/deadlock")
        print("  -> Supports OOM + semaphore deadlock theory (#4)")
    else:
        print(f"  RESULT: All {completed} tasks completed normally")
        print("  -> Pool handled worker death gracefully (BrokenProcessPool)")

    return broken


def test_b_fd_leak_sequential_ppe():
    """Test B: Do sequential ProcessPoolExecutors leak FDs?

    Theory: result_queue SimpleQueue FDs not closed by shutdown,
    accumulate across iterations.
    """
    print("\n=== Test B: FD accumulation across sequential PPE iterations ===")

    fd_counts = []
    fd_before = _count_fds_fast()
    print(f"  FDs before: {fd_before}")

    for iteration in range(10):
        executor = ProcessPoolExecutor(max_workers=4)
        futures = [executor.submit(_dummy_worker, i) for i in range(16)]
        for f in as_completed(futures):
            f.result()
        executor.shutdown(wait=True)

        fd_after = _count_fds_fast()
        fd_counts.append(fd_after)

        if iteration % 3 == 2:
            import gc
            gc.collect()
            fd_after_gc = _count_fds_fast()
            print(f"  Iteration {iteration+1}: FDs={fd_after}, after GC={fd_after_gc}")

    fd_final = _count_fds_fast()
    leaked = fd_final - fd_before
    print(f"  FDs after 10 iterations: {fd_final} (leaked: {leaked})")

    if leaked > 10:
        print("  RESULT: Significant FD leak detected")
        print("  -> Supports resource accumulation theory")
    else:
        print("  RESULT: FDs properly cleaned up (or GC handled it)")

    return leaked


def test_c_memory_pressure():
    """Test C: Heavy workers causing memory pressure.

    Simulates _build_file_result reading large files multiple times.
    """
    print("\n=== Test C: Memory pressure with heavy workers ===")

    cpu_count = os.cpu_count() or 4
    workers = min(cpu_count, 8)
    size_mb = 20

    print(f"  Workers: {workers}, Simulated file size: {size_mb}MB each")
    print(f"  Expected peak memory: ~{workers * size_mb}MB")

    work_items = [(f"/tmp/fake_{i}.so", size_mb) for i in range(workers * 2)]

    start = time.time()
    executor = ProcessPoolExecutor(max_workers=workers)
    try:
        futures = {
            executor.submit(_heavy_worker, item): item[0]
            for item in work_items
        }
        for f in as_completed(futures, timeout=30):
            path = futures[f]
            try:
                result = f.result()
            except Exception as e:
                print(f"  Worker error for {path}: {e}")
        executor.shutdown(wait=True)
        elapsed = time.time() - start
        print(f"  RESULT: Completed in {elapsed:.1f}s — no hang")
    except TimeoutError:
        print("  TIMEOUT: Heavy workers caused hang!")
        executor.shutdown(wait=False, cancel_futures=True)
    except Exception as e:
        print(f"  Exception: {type(e).__name__}: {e}")


def test_d_logging_lock_after_fork():
    """Test D: Is logging lock reinitialized after fork?

    On Python < 3.12, logging RLock is NOT reinitialized in child.
    """
    print("\n=== Test D: Logging lock after fork ===")

    import logging
    logger = logging.getLogger("fork_test")
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    v = sys.version_info
    print(f"  Python version: {v.major}.{v.minor}.{v.micro}")

    if hasattr(os, 'register_at_fork'):
        print("  os.register_at_fork: available")
    else:
        print("  os.register_at_fork: NOT available (pre-3.7)")

    has_reinit = hasattr(logging, '_register_at_fork_reinit') or v >= (3, 12)
    if has_reinit:
        print("  Logging at-fork reinit: YES (Python 3.12+)")
        print("  RESULT: Logging lock deadlock UNLIKELY")
    else:
        print("  Logging at-fork reinit: NO (Python < 3.12)")
        print("  RESULT: Logging lock deadlock POSSIBLE")

    logger.removeHandler(handler)
    return not has_reinit


def test_e_start_method():
    """Test E: Confirm multiprocessing start method."""
    print("\n=== Test E: Multiprocessing start method ===")

    method = multiprocessing.get_start_method()
    print(f"  Default start method: {method}")

    if method == 'fork':
        print("  RESULT: Using fork — all fork-related issues apply")
    elif method == 'spawn':
        print("  RESULT: Using spawn — fork issues do NOT apply")
    elif method == 'forkserver':
        print("  RESULT: Using forkserver — partial fork issues")

    return method


def test_f_sequential_ppe_with_death():
    """Test F: Sequential PPE where a worker dies in first iteration.

    Does the second iteration's PPE hang?
    """
    print("\n=== Test F: Sequential PPE after worker death ===")

    print("  Iteration 1: Creating PPE with a dying worker...")
    executor1 = ProcessPoolExecutor(max_workers=2)
    futures1 = [executor1.submit(_worker_that_dies, i) for i in range(4)]
    broken1 = False
    try:
        for f in as_completed(futures1, timeout=5):
            try:
                f.result()
            except Exception as e:
                print(f"    Worker exception: {type(e).__name__}")
                broken1 = True
    except TimeoutError:
        print("    TIMEOUT in iteration 1")
        broken1 = True
    except Exception as e:
        print(f"    Pool exception: {type(e).__name__}: {e}")
        broken1 = True
    finally:
        try:
            executor1.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    import gc
    gc.collect()
    time.sleep(0.5)

    print("  Iteration 2: Creating fresh PPE...")
    executor2 = ProcessPoolExecutor(max_workers=2)
    futures2 = [executor2.submit(_dummy_worker, i) for i in range(4)]
    broken2 = False
    try:
        results = []
        for f in as_completed(futures2, timeout=5):
            results.append(f.result())
        executor2.shutdown(wait=True)
        print(f"    Completed: {results}")
    except TimeoutError:
        print("    TIMEOUT in iteration 2 — CONFIRMS cross-iteration contamination")
        broken2 = True
    except Exception as e:
        print(f"    Pool exception: {type(e).__name__}: {e}")
        broken2 = True
    finally:
        try:
            executor2.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    if broken2:
        print("  RESULT: Second PPE IS affected by first's worker death")
    else:
        print("  RESULT: Second PPE works fine after first's worker death")

    return broken2


if __name__ == '__main__':
    print("=" * 60)
    print("Fork-in-Fork Hang Verification")
    print(f"Python {sys.version}")
    print(f"PID: {os.getpid()}")
    print(f"CPU count: {os.cpu_count()}")
    print("=" * 60)

    method = test_e_start_method()
    logging_risk = test_d_logging_lock_after_fork()
    fd_leaked = test_b_fd_leak_sequential_ppe()
    sem_broken = test_a_semaphore_on_worker_death()
    test_c_memory_pressure()
    cross_contamination = test_f_sequential_ppe_with_death()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Start method:           {method}")
    print(f"  Logging lock risk:      {'YES' if logging_risk else 'NO (Python 3.12+)'}")
    print(f"  FD leak (10 iters):     {fd_leaked} FDs")
    print(f"  Semaphore deadlock:     {'CONFIRMED' if sem_broken else 'NOT observed'}")
    print(f"  Cross-iter contamination: {'YES' if cross_contamination else 'NO'}")
    print("=" * 60)
