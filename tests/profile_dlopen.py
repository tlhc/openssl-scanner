"""
Profile detect_dlopen_openssl() internal phases.

Breaks down time spent in each layer:
  - ELF open + parse
  - .dynsym scan (dlopen/dlsym check)
  - Section data read (.rodata, .data.rel.ro, .data)
  - String extraction (extract_c_strings_with_offsets)
  - Layer B: Clustering
  - Layer C: Disassembly resolution (.text load + scan)
"""

import os
import sys
import time
import struct
import logging

src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src')
sys.path.insert(0, src_dir)

logging.basicConfig(level=logging.WARNING)


def profile_dlopen_phases(elf_path, openssl_exports):
    """Profile each phase of detect_dlopen_openssl."""
    from openssl_scanner import _vendor  # noqa: F401
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from openssl_scanner.constants import DLOPEN_FUNCTION_NAMES, DLSYM_FUNCTION_NAMES
    from openssl_scanner.dlopen_analyzer import (
        STRING_SECTIONS, MAX_SECTION_SIZE, MAX_TEXT_SIZE,
        extract_c_strings_with_offsets, _cluster_symbols,
        _resolve_dlsym_strings, _is_openssl_lib_string,
        OPENSSL_LIBRARY_PATTERNS,
    )

    timings = {'path': os.path.basename(elf_path),
               'size_mb': os.path.getsize(elf_path) / (1024 * 1024)}

    t0 = time.monotonic()
    f = open(elf_path, 'rb')
    magic = f.read(4)
    if magic != b'\x7fELF':
        f.close()
        timings['error'] = 'not ELF'
        return timings
    f.seek(0)
    elf = ELFFile(f)
    t1 = time.monotonic()
    timings['elf_open'] = t1 - t0

    has_dlopen = False
    has_dlsym = False
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        if section.name != '.dynsym':
            continue
        for sym in section.iter_symbols():
            name = sym.name
            if not name:
                continue
            if sym['st_shndx'] != 'SHN_UNDEF':
                continue
            if name in DLOPEN_FUNCTION_NAMES:
                has_dlopen = True
            if name in DLSYM_FUNCTION_NAMES:
                has_dlsym = True
            if has_dlopen and has_dlsym:
                break
        break
    t2 = time.monotonic()
    timings['dynsym_scan'] = t2 - t1
    timings['has_dlopen'] = has_dlopen
    timings['has_dlsym'] = has_dlsym

    if not has_dlopen and not has_dlsym:
        f.close()
        timings['skipped'] = 'no dlopen/dlsym'
        return timings

    candidates = openssl_exports.copy()

    section_data_times = []
    string_extract_times = []
    all_strings = set()
    all_with_offsets = []
    section_ranges = []
    base_offset = 0
    total_section_bytes = 0

    for section_name in STRING_SECTIONS:
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        size = section.data_size
        if size > MAX_SECTION_SIZE:
            section_data_times.append((section_name, size, 'SKIPPED'))
            continue

        ts0 = time.monotonic()
        data = section.data()
        ts1 = time.monotonic()
        section_data_times.append((section_name, size, ts1 - ts0))
        total_section_bytes += size

        try:
            section_vaddr = section['sh_addr']
        except (KeyError, TypeError):
            section_vaddr = 0
        section_ranges.append((section_vaddr, data))

        ts2 = time.monotonic()
        with_offsets = extract_c_strings_with_offsets(data)
        ts3 = time.monotonic()
        string_extract_times.append((section_name, len(with_offsets), ts3 - ts2))

        all_strings.update(s for _, s in with_offsets)
        for off, s in with_offsets:
            all_with_offsets.append((base_offset + off, s))
        base_offset += size

    t3 = time.monotonic()
    timings['section_read_total'] = t3 - t2
    timings['section_bytes_total'] = total_section_bytes

    raw_matches = {s for s in all_strings if s in candidates}
    t4 = time.monotonic()
    timings['raw_match'] = t4 - t3
    timings['raw_match_count'] = len(raw_matches)
    timings['all_strings_count'] = len(all_strings)

    text_section = elf.get_section_by_name('.text')
    text_size = 0
    text_data_time = 0
    resolve_time = 0
    resolved = set()

    if text_section is not None:
        text_size = text_section.data_size
        timings['text_size_mb'] = text_size / (1024 * 1024)

        if text_size <= MAX_TEXT_SIZE:
            ts0 = time.monotonic()
            text_data = text_section.data()
            ts1 = time.monotonic()
            text_data_time = ts1 - ts0

            ts2 = time.monotonic()
            try:
                resolved = _resolve_dlsym_strings(elf, candidates, section_ranges)
            except Exception as e:
                timings['resolve_error'] = str(e)[:80]
            ts3 = time.monotonic()
            resolve_time = ts3 - ts2
        else:
            timings['text_skipped'] = 'too large (>%dMB)' % (MAX_TEXT_SIZE // (1024*1024))

    t5 = time.monotonic()
    timings['layer_c_text_read'] = text_data_time
    timings['layer_c_resolve'] = resolve_time
    timings['layer_c_total'] = t5 - t4
    timings['resolved_count'] = len(resolved)

    clustered = _cluster_symbols(all_with_offsets, candidates)
    t6 = time.monotonic()
    timings['layer_b_cluster'] = t6 - t5
    timings['clustered_count'] = len(clustered)

    dlopen_libs = sorted(
        s for s in all_strings
        if _is_openssl_lib_string(s, OPENSSL_LIBRARY_PATTERNS))
    timings['dlopen_libs'] = dlopen_libs

    timings['total'] = t6 - t0
    timings['sections'] = section_data_times
    timings['string_extracts'] = string_extract_times

    f.close()
    return timings


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


def main():
    print("=" * 70)
    print("dlopen_analyzer Phase Profiler")
    print(f"Python {sys.version}")
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

    for path, size in libs:
        print(f"\n--- {os.path.basename(path)} ({size/1024/1024:.1f}MB) ---")
        t = profile_dlopen_phases(path, exports)

        if 'skipped' in t:
            print(f"  SKIPPED: {t['skipped']}")
            continue
        if 'error' in t:
            print(f"  ERROR: {t['error']}")
            continue

        print(f"  elf_open:        {t.get('elf_open', 0)*1000:8.1f}ms")
        print(f"  dynsym_scan:     {t.get('dynsym_scan', 0)*1000:8.1f}ms"
              f"  (dlopen={t.get('has_dlopen')}, dlsym={t.get('has_dlsym')})")

        for name, size_or_skip, elapsed in t.get('sections', []):
            if elapsed == 'SKIPPED':
                print(f"  section {name:20s}: {size_or_skip/1024/1024:.1f}MB SKIPPED")
            else:
                print(f"  section {name:20s}: {size_or_skip/1024/1024:.1f}MB"
                      f"  read={elapsed*1000:.1f}ms")

        for name, count, elapsed in t.get('string_extracts', []):
            print(f"  strings {name:20s}: {count:6d} strings"
                  f"  extract={elapsed*1000:.1f}ms")

        print(f"  section_read:    {t.get('section_read_total', 0)*1000:8.1f}ms"
              f"  ({t.get('section_bytes_total', 0)/1024/1024:.1f}MB total)")
        print(f"  raw_match:       {t.get('raw_match', 0)*1000:8.1f}ms"
              f"  ({t.get('raw_match_count', 0)} matches"
              f" / {t.get('all_strings_count', 0)} strings)")

        text_mb = t.get('text_size_mb', 0)
        print(f"  .text size:      {text_mb:8.1f}MB")
        if 'text_skipped' in t:
            print(f"  Layer C:         SKIPPED ({t['text_skipped']})")
        else:
            print(f"  Layer C text_read: {t.get('layer_c_text_read', 0)*1000:8.1f}ms")
            print(f"  Layer C resolve:   {t.get('layer_c_resolve', 0)*1000:8.1f}ms"
                  f"  ({t.get('resolved_count', 0)} confirmed)")
        print(f"  Layer C total:   {t.get('layer_c_total', 0)*1000:8.1f}ms")
        print(f"  Layer B cluster: {t.get('layer_b_cluster', 0)*1000:8.1f}ms"
              f"  ({t.get('clustered_count', 0)} clustered)")
        print(f"  TOTAL:           {t.get('total', 0)*1000:8.1f}ms")

        total = t.get('total', 1)
        top_phases = []
        for key in ['elf_open', 'dynsym_scan', 'section_read_total',
                     'layer_c_total', 'layer_b_cluster', 'raw_match']:
            val = t.get(key, 0)
            if val > 0.001:
                top_phases.append((key, val, val / total * 100))
        top_phases.sort(key=lambda x: -x[1])
        print(f"  --- breakdown ---")
        for name, val, pct in top_phases:
            print(f"    {name:25s}: {val*1000:8.1f}ms ({pct:5.1f}%)")


if __name__ == '__main__':
    main()
