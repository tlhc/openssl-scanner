"""Integration tests for the hap subcommand end-to-end pipeline."""

import io
import json
import os
import shutil
import struct
import sys
import tempfile
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openssl_scanner.__main__ import main


def _minimal_elf64():
    """Minimal valid ELF64 shared library header (aarch64)."""
    e_ident = b'\x7fELF'
    e_ident += b'\x02\x01\x01'
    e_ident += b'\x00' * 9
    header = e_ident
    header += struct.pack('<H', 3)    # ET_DYN
    header += struct.pack('<H', 183)  # EM_AARCH64
    header += struct.pack('<I', 1)
    header += struct.pack('<Q', 0)    # e_entry
    header += struct.pack('<Q', 0)    # e_phoff
    header += struct.pack('<Q', 0)    # e_shoff
    header += struct.pack('<I', 0)
    header += struct.pack('<H', 64)
    header += struct.pack('<H', 0) * 5
    return header


def _create_test_hap(path, bundle_name="com.test.scanner",
                     module_name="entry", include_openssl=False):
    """Create a test HAP for integration testing."""
    with zipfile.ZipFile(path, 'w') as zf:
        zf.writestr("module.json", json.dumps({
            "module": {
                "name": module_name,
                "type": "entry",
                "deviceTypes": ["default", "tablet"]
            },
            "app": {
                "bundleName": bundle_name,
                "versionCode": 1000000,
                "versionName": "1.0.0",
                "minAPIVersion": 11
            }
        }))
        zf.writestr("libs/arm64-v8a/libentry.so", _minimal_elf64())
        if include_openssl:
            zf.writestr("libs/arm64-v8a/libcrypto.so.3", _minimal_elf64())
    return path


def _create_test_app(path, hap_count=2):
    """Create a test APP containing multiple HAPs."""
    with zipfile.ZipFile(path, 'w') as app_zf:
        for i in range(hap_count):
            name = f"module{i}.hap"
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w') as hap_zf:
                hap_zf.writestr("module.json", json.dumps({
                    "module": {"name": f"module{i}", "type": "entry",
                               "deviceTypes": ["default"]},
                    "app": {"bundleName": "com.test.app",
                            "versionCode": 1, "versionName": "1.0.0",
                            "minAPIVersion": 11}
                }))
                hap_zf.writestr(f"libs/arm64-v8a/libmod{i}.so", _minimal_elf64())
            app_zf.writestr(name, buf.getvalue())
    return path


class TestHapSubcommandCLI:
    """Test hap subcommand CLI behavior."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_hap_subcommand_help(self, capsys):
        """hap --help should show usage and return 0."""
        with pytest.raises(SystemExit) as exc_info:
            main(['hap', '--help'])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert 'HAP/HAR/HSP/APP' in captured.out

    def test_hap_subcommand_missing_file(self):
        """Non-existent target should return error code 1."""
        output = os.path.join(self.tmpdir, "report.json")
        ret = main(['hap', '/nonexistent/path.hap', '-o', output, '--json-only'])
        assert ret == 1

    def test_hap_subcommand_invalid_file(self):
        """Invalid ZIP file should return error code but not crash."""
        invalid = os.path.join(self.tmpdir, "bad.hap")
        with open(invalid, 'wb') as f:
            f.write(b"not a zip at all")

        output = os.path.join(self.tmpdir, "report.json")
        ret = main(['hap', invalid, '-o', output, '--json-only'])
        assert ret == 1

    def test_hap_no_native_libs(self):
        """HAP with no native libs should warn and return 1."""
        hap_path = os.path.join(self.tmpdir, "no_native.hap")
        with zipfile.ZipFile(hap_path, 'w') as zf:
            zf.writestr("module.json", json.dumps({
                "module": {"name": "entry", "type": "entry"},
                "app": {"bundleName": "com.test.empty"}
            }))

        output = os.path.join(self.tmpdir, "report.json")
        ret = main(['hap', hap_path, '-o', output, '--json-only'])
        assert ret == 1

    def test_hap_no_openssl_scans_with_builtin(self):
        """HAP with native libs but no bundled OpenSSL should scan using built-in symbols."""
        hap_path = os.path.join(self.tmpdir, "no_ssl.hap")
        _create_test_hap(hap_path, include_openssl=False)

        output = os.path.join(self.tmpdir, "report.json")
        ret = main(['hap', hap_path, '-o', output, '--json-only'])
        assert ret == 0
        assert os.path.isfile(output)

    def test_hap_directory_no_packages(self):
        """Directory with no packages should return 1."""
        empty_dir = os.path.join(self.tmpdir, "empty")
        os.makedirs(empty_dir)

        output = os.path.join(self.tmpdir, "report.json")
        ret = main(['hap', empty_dir, '-o', output, '--json-only'])
        assert ret == 1

    def test_hap_directory_finds_packages(self):
        """Directory scan should find and scan packages using built-in symbols."""
        pkg_dir = os.path.join(self.tmpdir, "packages")
        os.makedirs(pkg_dir)
        _create_test_hap(os.path.join(pkg_dir, "a.hap"))
        _create_test_hap(os.path.join(pkg_dir, "b.hap"))

        output = os.path.join(self.tmpdir, "report.json")
        ret = main(['hap', pkg_dir, '-o', output, '--json-only'])
        assert ret == 0
        assert os.path.isfile(output)


class TestHapExtractPipeline:
    """Test the extraction + metadata pipeline without requiring real OpenSSL."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_keep_extracted_preserves_files(self):
        """--keep-extracted should leave temp files in place."""
        hap_path = os.path.join(self.tmpdir, "keep.hap")
        _create_test_hap(hap_path)

        output = os.path.join(self.tmpdir, "report.json")
        ret = main(['hap', hap_path, '-o', output, '--json-only',
                     '--keep-extracted'])
        assert ret == 0
        assert os.path.isfile(output)

    def test_hap_recognized_in_command_list(self):
        """'hap' should be recognized as a valid subcommand (not falling through to scan)."""
        output = os.path.join(self.tmpdir, "report.json")
        ret = main(['hap', '/nonexistent.hap', '-o', output, '--json-only'])
        assert ret == 1


class TestHapReportMetadata:
    """Test report metadata structure from hap_extractor + reporter integration."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_extractor_metadata_structure(self):
        """Verify HapExtractor produces correct metadata that cmd_hap would use."""
        from openssl_scanner.hap_extractor import HapExtractor

        hap_path = os.path.join(self.tmpdir, "meta_test.hap")
        _create_test_hap(hap_path, bundle_name="com.test.meta",
                         module_name="feature")

        extractor = HapExtractor()
        result = extractor.extract(hap_path)

        assert result.metadata.bundle_name == "com.test.meta"
        assert result.metadata.module_name == "feature"
        assert result.metadata.package_type == "hap"
        assert result.metadata.version_name == "1.0.0"
        assert result.metadata.version_code == 1000000
        assert result.metadata.min_api_version == 11
        assert "default" in result.metadata.device_types
        assert "arm64-v8a" in result.metadata.abis_found
        assert len(result.so_files) >= 1

        extractor.cleanup(result)

    def test_app_file_extracts_sub_packages(self):
        """APP file should produce sub_packages with their own metadata."""
        from openssl_scanner.hap_extractor import HapExtractor

        app_path = os.path.join(self.tmpdir, "test.app")
        _create_test_app(app_path, hap_count=3)

        extractor = HapExtractor()
        result = extractor.extract(app_path)

        assert len(result.sub_packages) == 3
        module_names = [sub.metadata.module_name for sub in result.sub_packages]
        assert "module0" in module_names
        assert "module1" in module_names
        assert "module2" in module_names

        total_so = sum(len(sub.so_files) for sub in result.sub_packages)
        assert total_so == 3

        extractor.cleanup(result)

    def test_reporter_package_info_in_json(self):
        """Verify Reporter correctly serializes package_info to JSON."""
        from openssl_scanner.scanner import ScanResult
        from openssl_scanner.reporter import Reporter

        result = ScanResult(
            target="/tmp/test.hap",
            scan_time="2026-02-09T00:00:00",
            tool_version="0.1.0",
            arch="aarch64",
            report_type="package",
        )
        result.package_info = {
            'package_type': 'hap',
            'bundle_name': 'com.test.reporter',
            'module_name': 'entry',
            'module_type': 'entry',
            'version_name': '1.0.0',
            'version_code': 100,
            'scanned_abi': 'arm64-v8a',
            'native_libs_count': 3,
            'bundled_openssl': False,
        }

        reporter = Reporter()
        json_str = reporter.generate_json(result)
        data = json.loads(json_str)

        assert data['meta']['report_type'] == 'package'
        assert 'package' in data['meta']
        pkg = data['meta']['package']
        assert pkg['bundle_name'] == 'com.test.reporter'
        assert pkg['scanned_abi'] == 'arm64-v8a'
        assert pkg['native_libs_count'] == 3

    def test_reporter_summary_includes_package_info(self):
        """Verify console summary includes package metadata."""
        from openssl_scanner.scanner import ScanResult
        from openssl_scanner.reporter import Reporter

        result = ScanResult(
            target="/tmp/test.hap",
            scan_time="2026-02-09T00:00:00",
            tool_version="0.1.0",
            arch="aarch64",
            report_type="package",
        )
        result.package_info = {
            'package_type': 'hap',
            'bundle_name': 'com.test.summary',
            'module_name': 'entry',
            'module_type': 'entry',
            'version_name': '2.0.0',
            'version_code': 200,
            'scanned_abi': 'arm64-v8a',
            'native_libs_count': 5,
        }

        reporter = Reporter()
        summary = reporter.generate_summary(result)

        assert 'HAP' in summary
        assert 'com.test.summary' in summary
        assert '2.0.0' in summary
        assert 'arm64-v8a' in summary


class TestHapSummaryReport:
    """Test Package Summary XLSX generated during batch HAP scan."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _batch_scan(self, hap_count=3):
        """Create HAPs in a dir, batch scan to output dir, return output dir."""
        pkg_dir = os.path.join(self.tmpdir, "packages")
        os.makedirs(pkg_dir)
        for i in range(hap_count):
            _create_test_hap(
                os.path.join(pkg_dir, f"app{i}.hap"),
                bundle_name=f"com.test.app{i}",
                module_name=f"mod{i}",
            )
        out_dir = os.path.join(self.tmpdir, "output")
        ret = main(['hap', pkg_dir, '-o', out_dir, '--json-only'])
        return ret, out_dir

    def test_summary_xlsx_generated(self):
        """Batch scan should produce summary.xlsx in output dir."""
        ret, out_dir = self._batch_scan(2)
        assert ret == 0
        summary = os.path.join(out_dir, "summary.xlsx")
        assert os.path.isfile(summary)

    def test_summary_has_correct_columns(self):
        """Header row should have all 22 columns."""
        ret, out_dir = self._batch_scan(2)
        assert ret == 0
        summary = os.path.join(out_dir, "summary.xlsx")

        from openpyxl import load_workbook
        wb = load_workbook(summary)
        ws = wb.active
        assert ws.title == "Package Summary"
        headers = [ws.cell(row=1, column=c).value for c in range(1, 23)]
        assert headers[0] == "Package Name"
        assert headers[5] == "OpenSSL Type"
        assert headers[6] == "Detection"
        assert headers[7] == "Bundled OpenSSL"
        assert headers[8] == "Static Symbols"
        assert headers[9] == "Dynamic Symbols"
        assert headers[10] == "dlopen Symbols"
        assert headers[11] == "Total Symbols"
        assert headers[12] == "Top Category"
        assert headers[21] == "dlopen Libs"
        assert len(headers) == 22

    def test_summary_row_count(self):
        """Should have header + N data rows + TOTAL row."""
        ret, out_dir = self._batch_scan(3)
        assert ret == 0
        summary = os.path.join(out_dir, "summary.xlsx")

        from openpyxl import load_workbook
        wb = load_workbook(summary)
        ws = wb.active
        assert ws.cell(row=1, column=1).value == "Package Name"
        assert ws.cell(row=5, column=1).value == "TOTAL"
        for r in range(2, 5):
            val = ws.cell(row=r, column=1).value
            assert val is not None and val != "TOTAL"

    def test_summary_total_row_so_count(self):
        """TOTAL row .so Files should be sum of all packages."""
        ret, out_dir = self._batch_scan(3)
        assert ret == 0

        from openpyxl import load_workbook
        wb = load_workbook(os.path.join(out_dir, "summary.xlsx"))
        ws = wb.active
        total_row = ws.max_row
        assert ws.cell(row=total_row, column=1).value == "TOTAL"
        pkg_so = sum(ws.cell(row=r, column=5).value or 0
                     for r in range(2, total_row))
        assert ws.cell(row=total_row, column=5).value == pkg_so

    def test_summary_ossl_type_for_minimal_elf(self):
        """Minimal ELFs have no OpenSSL -> OpenSSL Type should be No-OpenSSL."""
        ret, out_dir = self._batch_scan(2)
        assert ret == 0

        from openpyxl import load_workbook
        wb = load_workbook(os.path.join(out_dir, "summary.xlsx"))
        ws = wb.active
        for r in range(2, ws.max_row):
            assert ws.cell(row=r, column=6).value == 'No-OpenSSL'
        total_row = ws.max_row
        val = ws.cell(row=total_row, column=6).value
        assert 'No-OpenSSL' in str(val)

    def test_summary_detection_none_for_minimal_elf(self):
        """Minimal ELFs have no OpenSSL -> detection should be None."""
        ret, out_dir = self._batch_scan(2)
        assert ret == 0

        from openpyxl import load_workbook
        wb = load_workbook(os.path.join(out_dir, "summary.xlsx"))
        ws = wb.active
        for r in range(2, ws.max_row):
            assert ws.cell(row=r, column=7).value == 'None'


class TestClassifyHapDetection:
    """Unit tests for _classify_hap_detection helper."""

    def test_no_openssl(self):
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/a.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=[]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert method == 'None'
        assert len(s_set) == 0 and len(d_set) == 0 and len(dl_set) == 0
        assert ossl_type == 'No-OpenSSL'

    def test_dynamic_only(self):
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/a.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_connect"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert method == 'Dynamic'
        assert ossl_type == 'System-Link'
        assert d_set == {"SSL_connect"} and len(s_set) == 0

    def test_static_only(self):
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/a.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["EVP_sha256"],
                       static_openssl=True),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert method == 'Static'
        assert ossl_type == 'Self-Contained'
        assert s_set == {"EVP_sha256"}

    def test_dlopen_only(self):
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/a.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_read"],
                       uses_dlopen=True, dlsym_symbols=["SSL_read"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert method == 'dlopen'
        assert ossl_type == 'System-Link'
        assert dl_set == {"SSL_read"}

    def test_mixed(self):
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/a.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_connect"]),
            FileResult(path="/b.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["EVP_sha256"],
                       static_openssl=True),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert method == 'Mixed'
        assert s_set == {"EVP_sha256"} and d_set == {"SSL_connect"}
        assert ossl_type == 'System-Link'

    def test_static_majority_but_unresolved_dynamic(self):
        """Static lib self-sufficient but dynamic lib unresolved -> System-Link.

        Per-library resolution: libcrypto.so is self-sufficient (static),
        but app.so has dynamic OpenSSL symbols with no bundled .so to satisfy
        them.  The HAP is NOT Self-Contained despite static count > dynamic.
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        static_syms = [f"EVP_sym_{i}" for i in range(50)]
        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/libcrypto.so", file_type="shared_library",
                       arch="aarch64", direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=static_syms, static_openssl=True),
            FileResult(path="/app.so", file_type="shared_library",
                       arch="aarch64", direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_connect", "SSL_read"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert method == 'Mixed'
        assert len(s_set) == 50 and len(d_set) == 2
        assert ossl_type == 'System-Link'

    def test_system_link_dynamic_majority(self):
        """Package with many dynamic symbols and few static -> System-Link."""
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        dynamic_syms = [f"SSL_sym_{i}" for i in range(30)]
        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/a.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=dynamic_syms),
            FileResult(path="/b.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["EVP_sha1", "EVP_sha256"],
                       static_openssl=True),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert len(s_set) == 2 and len(d_set) == 30
        assert ossl_type == 'System-Link'

    def test_equal_static_dynamic_is_system_link(self):
        """Equal static and dynamic counts -> System-Link (not >)."""
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/a.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_connect", "SSL_read", "SSL_write"]),
            FileResult(path="/b.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["EVP_sha1", "EVP_sha256", "EVP_md5"],
                       static_openssl=True),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert len(s_set) == 3 and len(d_set) == 3
        assert ossl_type == 'System-Link'

    def test_dlopen_plus_dynamic_system_link(self):
        """Package with both dlopen and dynamic (no static) -> System-Link."""
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/a.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_connect"]),
            FileResult(path="/b.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_read"],
                       uses_dlopen=True, dlsym_symbols=["SSL_read"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert len(d_set) == 1 and len(dl_set) == 1 and len(s_set) == 0
        assert ossl_type == 'System-Link'

    def test_hybrid_dlopen_file_with_direct_und(self):
        """File with both dlopen symbols and direct UND -> split counts."""
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/a.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_connect", "SSL_read", "EVP_sha256"],
                       uses_dlopen=True, dlsym_symbols=["EVP_sha256"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert dl_set == {"EVP_sha256"}
        assert d_set == {"SSL_connect", "SSL_read"}
        assert ossl_type == 'System-Link'

    def test_static_dlopen_overlap_not_double_counted(self):
        """Static file with dlopen: dlsym symbols should NOT inflate static count.

        scanner.py appends filtered dlsym symbols to openssl_symbols, so
        fr.openssl_symbols = UND + dlsym-only.  Without the fix, all of
        openssl_symbols would go into static_syms, inflating the count.

        Setup: static file with 1 true UND symbol + 2 dlsym-appended symbols.
        Correct: static=1, dlopen=2 -> 1 < 2 -> System-Link.
        Bug:     static=3, dlopen=2 -> 3 > 2 -> Self-Contained (wrong).
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/libcrypto.so", file_type="shared_library",
                       arch="aarch64", direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["EVP_sha256", "SSL_read", "SSL_write"],
                       static_openssl=True, uses_dlopen=True,
                       dlsym_symbols=["SSL_read", "SSL_write"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert s_set == {"EVP_sha256"}
        assert dl_set == {"SSL_read", "SSL_write"}
        assert len(s_set) == 1 and len(dl_set) == 2
        assert ossl_type == 'System-Link'

    def test_static_dlopen_all_symbols_are_dlsym(self):
        """Static file where ALL symbols are dlsym -> empty static_only.

        static_only = openssl_symbols - dlsym_symbols = empty.
        method='Mixed' (has_static + has_dlopen), ossl_type='System-Link'.
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/lib.so", file_type="shared_library",
                       arch="aarch64", direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_read", "SSL_write"],
                       static_openssl=True, uses_dlopen=True,
                       dlsym_symbols=["SSL_read", "SSL_write"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert s_set == set()
        assert dl_set == {"SSL_read", "SSL_write"}
        assert method == 'Mixed'
        assert ossl_type == 'System-Link'

    def test_dedup_shared_symbols_across_static_files(self):
        """Duplicate symbols across static files count once after dedup.

        Two static .so files share the same 2 symbols -> s_set has 2, not 4.
        Three dynamic symbols -> external=3 > static=2 -> System-Link.
        Without dedup this would be 4 > 3 -> Self-Contained (wrong).
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        shared_static = ["EVP_sha256", "EVP_md5"]
        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/a.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=shared_static, static_openssl=True),
            FileResult(path="/b.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=shared_static, static_openssl=True),
            FileResult(path="/app.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_connect", "SSL_read", "SSL_write"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert len(s_set) == 2
        assert len(d_set) == 3
        assert ossl_type == 'System-Link'
        assert len(s_set | d_set | dl_set) == 5

    def test_bundled_resolves_dynamic_dt_needed(self):
        """HAP with bundled libcrypto.so.3 satisfies DT_NEEDED -> Self-Contained.

        Production flow: cmd_hap removes bundled OpenSSL .so before scanning,
        storing filenames in package_info['bundled_openssl_files'].  app.so
        DT_NEEDs libcrypto.so.3 which matches the bundled lib stem.
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.package_info = {
            'bundled_openssl': True,
            'bundled_openssl_files': ['libcrypto.so.3'],
        }
        result.files_detail = [
            FileResult(path="/libs/arm64-v8a/app.so",
                       file_type="shared_library", arch="aarch64",
                       direct_deps=["libcrypto.so.3"], openssl_direct=True,
                       openssl_transitive=False,
                       openssl_libs=["libcrypto.so.3"],
                       openssl_symbols=["SSL_connect", "SSL_read"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert ossl_type == 'Self-Contained'

    def test_bundled_resolves_dlopen(self):
        """HAP with bundled libcrypto.so.3 satisfies dlopen -> Self-Contained.

        lib.so does dlopen("libcrypto.so"), stem matches bundled libcrypto.so.3.
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.package_info = {
            'bundled_openssl': True,
            'bundled_openssl_files': ['libcrypto.so.3'],
        }
        result.files_detail = [
            FileResult(path="/libs/arm64-v8a/lib.so",
                       file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_read"],
                       uses_dlopen=True, dlsym_symbols=["SSL_read"],
                       dlopen_libs=["libcrypto.so"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert ossl_type == 'Self-Contained'

    def test_static_plus_dlopen_no_bundle(self):
        """Static lib with dlopen symbols, no bundled .so -> System-Link.

        One lib has static OpenSSL for its own needs but also dlopen-loads
        additional symbols.  Without bundled .so, the dlopen part is unresolved.
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/lib.so", file_type="shared_library",
                       arch="aarch64", direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["EVP_sha256", "SSL_read"],
                       static_openssl=True, uses_dlopen=True,
                       dlsym_symbols=["SSL_read"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert s_set == {"EVP_sha256"}
        assert dl_set == {"SSL_read"}
        assert ossl_type == 'System-Link'

    def test_static_plus_dlopen_with_bundle(self):
        """Static lib with dlopen symbols, bundled .so present -> Self-Contained.

        The static portion self-resolves; the dlopen("libcrypto.so") resolves
        via bundled libcrypto.so.3 (stem match).
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.package_info = {
            'bundled_openssl': True,
            'bundled_openssl_files': ['libcrypto.so.3'],
        }
        result.files_detail = [
            FileResult(path="/libs/arm64-v8a/lib.so",
                       file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["EVP_sha256", "SSL_read"],
                       static_openssl=True, uses_dlopen=True,
                       dlsym_symbols=["SSL_read"],
                       dlopen_libs=["libcrypto.so"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert ossl_type == 'Self-Contained'

    def test_dlopen_partial_bundle_system_link(self):
        """dlopen needs both libcrypto + libssl but only libcrypto bundled.

        Per-target resolution: ALL OpenSSL dlopen targets must resolve.
        libssl.so is missing -> System-Link.
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.package_info = {
            'bundled_openssl': True,
            'bundled_openssl_files': ['libcrypto.so.3'],
        }
        result.files_detail = [
            FileResult(path="/lib.so", file_type="shared_library",
                       arch="aarch64", direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_read", "EVP_sha256"],
                       uses_dlopen=True,
                       dlsym_symbols=["SSL_read", "EVP_sha256"],
                       dlopen_libs=["libcrypto.so", "libssl.so"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert ossl_type == 'System-Link'

    def test_dlopen_absolute_path_resolved(self):
        """dlopen with absolute path '/system/lib64/libcrypto.so' is normalized.

        Basename extraction ensures path prefix does not break matching.
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.package_info = {
            'bundled_openssl': True,
            'bundled_openssl_files': ['libcrypto.so.3'],
        }
        result.files_detail = [
            FileResult(path="/lib.so", file_type="shared_library",
                       arch="aarch64", direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_read"],
                       uses_dlopen=True, dlsym_symbols=["SSL_read"],
                       dlopen_libs=["/system/lib64/libcrypto.so"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert ossl_type == 'Self-Contained'

    def test_hybrid_static_plus_dt_needed_unresolved(self):
        """Static OpenSSL lib that also DT_NEEDs external libssl -> System-Link.

        File implements some OpenSSL symbols (static) but also imports from
        libssl.so.3 via DT_NEEDED.  Without bundled libssl, the dynamic part
        is unresolved.
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/lib.so", file_type="shared_library",
                       arch="aarch64", direct_deps=["libssl.so.3"],
                       openssl_direct=True,
                       openssl_transitive=False,
                       openssl_libs=["libssl.so.3"],
                       openssl_symbols=["EVP_sha256", "SSL_connect"],
                       static_openssl=True),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert ossl_type == 'System-Link'

    def test_hybrid_static_plus_dt_needed_resolved(self):
        """Static OpenSSL lib that DT_NEEDs libssl, bundled -> Self-Contained."""
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.package_info = {
            'bundled_openssl': True,
            'bundled_openssl_files': ['libssl.so.3'],
        }
        result.files_detail = [
            FileResult(path="/lib.so", file_type="shared_library",
                       arch="aarch64", direct_deps=["libssl.so.3"],
                       openssl_direct=True,
                       openssl_transitive=False,
                       openssl_libs=["libssl.so.3"],
                       openssl_symbols=["EVP_sha256", "SSL_connect"],
                       static_openssl=True),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert ossl_type == 'Self-Contained'

    def test_bundled_openssl_files_absent_fallback(self):
        """bundled_openssl=True but bundled_openssl_files missing -> System-Link.

        Tests backward compat: old scan results without bundled_openssl_files
        key produce conservative System-Link (not crash).
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.package_info = {'bundled_openssl': True}
        result.files_detail = [
            FileResult(path="/app.so", file_type="shared_library",
                       arch="aarch64", direct_deps=["libcrypto.so.3"],
                       openssl_direct=True, openssl_transitive=False,
                       openssl_libs=["libcrypto.so.3"],
                       openssl_symbols=["SSL_connect"]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert ossl_type == 'System-Link'

    def test_harflix_scenario_system_link(self):
        """Harflix-like: static ijkplayer + dlopen reddownload -> System-Link.

        libijkplayer.so: 5215 static OpenSSL symbols, self-sufficient.
        libreddownload.so: 756 dlopen-detected symbols, no bundled .so.
        The HAP is NOT Self-Contained because libreddownload.so needs system
        OpenSSL to resolve its dlopen("libcrypto.so") call.
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        static_syms = [f"OSSL_{i}" for i in range(100)]
        dlopen_syms = [f"EVP_{i}" for i in range(50)]
        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/libijkplayer.so", file_type="shared_library",
                       arch="aarch64", direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=static_syms, static_openssl=True),
            FileResult(path="/libreddownload.so", file_type="shared_library",
                       arch="aarch64", direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=dlopen_syms,
                       uses_dlopen=True, dlsym_symbols=dlopen_syms),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert len(s_set) == 100
        assert len(dl_set) == 50
        assert ossl_type == 'System-Link'

    def test_multiple_static_all_self_sufficient(self):
        """Multiple static-only libs with no external deps -> Self-Contained."""
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/a.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["EVP_sha256"], static_openssl=True),
            FileResult(path="/b.so", file_type="shared_library", arch="aarch64",
                       direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_connect"], static_openssl=True),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert s_set == {"EVP_sha256", "SSL_connect"}
        assert ossl_type == 'Self-Contained'

    def test_dlopen_no_lib_name_no_bundle(self):
        """dlopen with empty dlopen_libs (unknown target) -> System-Link.

        When dlopen_libs is empty, the scanner couldn't determine which .so
        the library is trying to load.  Without a bundled OpenSSL, this is
        conservatively treated as unresolved.
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import _classify_hap_detection

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/lib.so", file_type="shared_library",
                       arch="aarch64", direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["SSL_read"],
                       uses_dlopen=True, dlsym_symbols=["SSL_read"],
                       dlopen_libs=[]),
        ]
        method, s_set, d_set, dl_set, ossl_type = _classify_hap_detection(result)
        assert ossl_type == 'System-Link'


class TestBundledOpenSSLDetection:
    """Tests for bundled_openssl field correctness."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_bundled_openssl_yes_for_separate_so(self):
        """HAP with libcrypto.so.3 should have bundled_openssl=True in JSON."""
        hap_path = os.path.join(self.tmpdir, "bundled.hap")
        _create_test_hap(hap_path, include_openssl=True)

        output = os.path.join(self.tmpdir, "report.json")
        ret = main(['hap', hap_path, '-o', output, '--json-only'])
        assert ret == 0

        with open(output) as f:
            data = json.load(f)
        assert data['meta']['package']['bundled_openssl'] is True

    def test_bundled_openssl_no_without_openssl(self):
        """HAP without OpenSSL libs should have bundled_openssl=False."""
        hap_path = os.path.join(self.tmpdir, "plain.hap")
        _create_test_hap(hap_path, include_openssl=False)

        output = os.path.join(self.tmpdir, "report.json")
        ret = main(['hap', hap_path, '-o', output, '--json-only'])
        assert ret == 0

        with open(output) as f:
            data = json.load(f)
        assert data['meta']['package']['bundled_openssl'] is False

    def test_bundled_summary_row_static_no_so_file(self):
        """Static OpenSSL without bundled .so -> bundled_openssl='No'.

        bundled_openssl answers 'does the package ship OpenSSL .so files?'
        Static linkage is captured by ossl_type=Self-Contained instead.
        """
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import (
            _classify_hap_detection, _build_hap_summary_row
        )

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/libapp.so", file_type="shared_library",
                       arch="aarch64", direct_deps=[], openssl_direct=True,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=["EVP_sha256", "SSL_connect"],
                       static_openssl=True),
        ]
        result.files_with_static_openssl = 1
        result.package_info = {
            'bundle_name': 'com.test.static',
            'package_type': 'hap',
            'version_name': '1.0.0',
            'scanned_abi': ['arm64-v8a'],
            'native_libs_count': 1,
            'bundled_openssl': False,
        }
        method, s, d, dl, ossl_type = _classify_hap_detection(result)
        row = _build_hap_summary_row(result, "/t.hap", method, s, d, dl,
                                     ossl_type)
        assert row['bundled_openssl'] == 'No'
        assert row['ossl_type'] == 'Self-Contained'

    def test_bundled_summary_row_no_static_no_file(self):
        """No OpenSSL .so and no static -> bundled_openssl='No'."""
        from openssl_scanner.scanner import ScanResult, FileResult
        from openssl_scanner.__main__ import (
            _classify_hap_detection, _build_hap_summary_row
        )

        result = ScanResult(
            target="/tmp/t", scan_time="", tool_version="0.1", arch="aarch64"
        )
        result.files_detail = [
            FileResult(path="/libapp.so", file_type="shared_library",
                       arch="aarch64", direct_deps=[], openssl_direct=False,
                       openssl_transitive=False, openssl_libs=[],
                       openssl_symbols=[]),
        ]
        result.package_info = {
            'bundle_name': 'com.test.plain',
            'package_type': 'hap',
            'version_name': '1.0.0',
            'scanned_abi': ['arm64-v8a'],
            'native_libs_count': 1,
            'bundled_openssl': False,
        }
        method, s, d, dl, ossl_type = _classify_hap_detection(result)
        row = _build_hap_summary_row(result, "/t.hap", method, s, d, dl,
                                     ossl_type)
        assert row['bundled_openssl'] == 'No'

    def test_libopenssl_pattern_detected(self):
        """libopenssl.so should be recognized as an OpenSSL library."""
        from openssl_scanner.openssl_matcher import OpenSSLMatcher

        matcher = OpenSSLMatcher()
        assert matcher.is_openssl_library("libopenssl.so") is True
        assert matcher.is_openssl_library("libopenssl.so.1.1") is True

    def test_bundled_summary_column_with_openssl_hap(self):
        """Batch scan with one bundled HAP -> column H shows 'Yes'."""
        pkg_dir = os.path.join(self.tmpdir, "packages")
        os.makedirs(pkg_dir)
        _create_test_hap(
            os.path.join(pkg_dir, "bundled.hap"),
            bundle_name="com.test.bundled",
            include_openssl=True,
        )
        _create_test_hap(
            os.path.join(pkg_dir, "plain.hap"),
            bundle_name="com.test.plain",
            include_openssl=False,
        )
        out_dir = os.path.join(self.tmpdir, "output")
        ret = main(['hap', pkg_dir, '-o', out_dir, '--json-only'])
        assert ret == 0

        summary = os.path.join(out_dir, "summary.xlsx")
        assert os.path.isfile(summary)

        from openpyxl import load_workbook
        wb = load_workbook(summary)
        ws = wb.active
        bundled_vals = {}
        for r in range(2, ws.max_row):
            name = ws.cell(row=r, column=1).value
            bundled = ws.cell(row=r, column=8).value
            if name and name != "TOTAL":
                bundled_vals[name] = bundled
        assert bundled_vals.get("com.test.bundled") == "Yes"
        assert bundled_vals.get("com.test.plain") == "No"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
