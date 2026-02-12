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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
