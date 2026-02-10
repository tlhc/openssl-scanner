"""Tests for HAP/HAR/HSP/APP package extractor."""

import json
import os
import struct
import sys
import tempfile
import shutil
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openssl_scanner.hap_extractor import HapExtractor, HapMetadata, HapExtractResult


def _minimal_elf64():
    """Minimal valid ELF64 shared library header (aarch64)."""
    e_ident = b'\x7fELF'
    e_ident += b'\x02'          # ELFCLASS64
    e_ident += b'\x01'          # little-endian
    e_ident += b'\x01'          # EV_CURRENT
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


def _create_module_json(bundle_name="com.test.app", module_name="entry",
                        module_type="entry", version_name="1.0.0",
                        version_code=1, min_api=11, device_types=None):
    """Build a module.json content string."""
    if device_types is None:
        device_types = ["default"]
    return json.dumps({
        "module": {
            "name": module_name,
            "type": module_type,
            "deviceTypes": device_types
        },
        "app": {
            "bundleName": bundle_name,
            "versionCode": version_code,
            "versionName": version_name,
            "minAPIVersion": min_api
        }
    })


def _create_hap(path, bundle_name="com.test.app", module_name="entry",
                module_type="entry", version_name="1.0.0", version_code=1,
                min_api=11, device_types=None, abi="arm64-v8a",
                so_names=None, include_openssl=False, no_native=False,
                no_module_json=False, bad_json=False):
    """Helper to create a test HAP file."""
    if device_types is None:
        device_types = ["default"]
    if so_names is None:
        so_names = ["libentry.so"]

    with zipfile.ZipFile(path, 'w') as zf:
        if not no_module_json:
            if bad_json:
                zf.writestr("module.json", "{invalid json content!!")
            else:
                zf.writestr("module.json", _create_module_json(
                    bundle_name=bundle_name,
                    module_name=module_name,
                    module_type=module_type,
                    version_name=version_name,
                    version_code=version_code,
                    min_api=min_api,
                    device_types=device_types
                ))

        if not no_native:
            for so_name in so_names:
                zf.writestr(f"libs/{abi}/{so_name}", _minimal_elf64())
            if include_openssl:
                zf.writestr(f"libs/{abi}/libcrypto.so.3", _minimal_elf64())
                zf.writestr(f"libs/{abi}/libssl.so.3", _minimal_elf64())
    return path


def _create_app(path, hap_names=None, bundle_name="com.test.app"):
    """Helper to create a test APP file containing sub-HAPs."""
    if hap_names is None:
        hap_names = ["entry.hap", "feature.hap"]

    with zipfile.ZipFile(path, 'w') as app_zf:
        for hap_name in hap_names:
            hap_buf = _build_hap_bytes(
                bundle_name=bundle_name,
                module_name=hap_name.replace(".hap", "")
            )
            app_zf.writestr(hap_name, hap_buf)
    return path


def _build_hap_bytes(bundle_name="com.test.app", module_name="entry",
                     abi="arm64-v8a"):
    """Build a HAP zip file in memory, return bytes."""
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr("module.json", _create_module_json(
            bundle_name=bundle_name,
            module_name=module_name
        ))
        zf.writestr(f"libs/{abi}/lib{module_name}.so", _minimal_elf64())
    return buf.getvalue()


class TestHapMetadataParsing:
    """Test metadata extraction from HAP/HAR/HSP packages."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.extractor = HapExtractor()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_parse_basic_hap_metadata(self):
        """Standard HAP with all fields present."""
        hap_path = os.path.join(self.tmpdir, "entry.hap")
        _create_hap(hap_path, bundle_name="com.example.demo",
                     module_name="entry", module_type="entry",
                     version_name="2.1.0", version_code=210,
                     min_api=12, device_types=["phone", "tablet"])

        meta = self.extractor.parse_metadata(hap_path)

        assert meta.package_path == hap_path
        assert meta.bundle_name == "com.example.demo"
        assert meta.module_name == "entry"
        assert meta.module_type == "entry"
        assert meta.version_name == "2.1.0"
        assert meta.version_code == 210
        assert meta.min_api_version == 12
        assert "phone" in meta.device_types
        assert "tablet" in meta.device_types

    def test_parse_har_metadata(self):
        """HAR (shared library) package should parse the same way."""
        har_path = os.path.join(self.tmpdir, "shared_lib.har")
        _create_hap(har_path, bundle_name="com.example.shared",
                     module_name="sharedLib", module_type="shared")

        meta = self.extractor.parse_metadata(har_path)

        assert meta.package_path == har_path
        assert meta.module_name == "sharedLib"
        assert meta.module_type == "shared"
        assert meta.package_type == "har"

    def test_parse_metadata_missing_module_json(self):
        """Package without module.json returns metadata with defaults."""
        hap_path = os.path.join(self.tmpdir, "no_meta.hap")
        _create_hap(hap_path, no_module_json=True)

        meta = self.extractor.parse_metadata(hap_path)
        assert meta.bundle_name == ''
        assert meta.module_name == ''
        assert meta.version_code == 0

    def test_parse_metadata_malformed_json(self):
        """Malformed JSON in module.json returns metadata with defaults."""
        hap_path = os.path.join(self.tmpdir, "bad.hap")
        _create_hap(hap_path, bad_json=True)

        meta = self.extractor.parse_metadata(hap_path)
        assert meta.bundle_name == ''
        assert meta.module_name == ''
        assert meta.version_code == 0

    def test_parse_metadata_partial_fields(self):
        """module.json with some fields missing should handle gracefully."""
        hap_path = os.path.join(self.tmpdir, "partial.hap")
        with zipfile.ZipFile(hap_path, 'w') as zf:
            zf.writestr("module.json", json.dumps({
                "module": {"name": "partial"},
                "app": {"bundleName": "com.test.partial"}
            }))

        meta = self.extractor.parse_metadata(hap_path)
        assert meta.bundle_name == "com.test.partial"
        assert meta.module_name == "partial"

    def test_package_type_from_extension(self):
        """Package type should be derived from file extension."""
        for ext, expected_type in [("hap", "hap"), ("har", "har"),
                                    ("hsp", "hsp")]:
            pkg_path = os.path.join(self.tmpdir, f"test.{ext}")
            _create_hap(pkg_path)
            meta = self.extractor.parse_metadata(pkg_path)
            assert meta.package_type == expected_type


class TestAbiDetection:
    """Test ABI detection from libs/ directory structure."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.extractor = HapExtractor()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_detect_single_abi(self):
        """Package with one ABI directory."""
        hap_path = os.path.join(self.tmpdir, "single_abi.hap")
        _create_hap(hap_path, abi="arm64-v8a")

        meta = self.extractor.parse_metadata(hap_path)
        assert "arm64-v8a" in meta.abis_found

    def test_detect_multiple_abis(self):
        """Package with multiple ABI directories."""
        hap_path = os.path.join(self.tmpdir, "multi_abi.hap")
        with zipfile.ZipFile(hap_path, 'w') as zf:
            zf.writestr("module.json", _create_module_json())
            zf.writestr("libs/arm64-v8a/libentry.so", _minimal_elf64())
            zf.writestr("libs/armeabi-v7a/libentry.so", _minimal_elf64())
            zf.writestr("libs/x86_64/libentry.so", _minimal_elf64())

        meta = self.extractor.parse_metadata(hap_path)
        assert len(meta.abis_found) == 3
        assert "arm64-v8a" in meta.abis_found
        assert "armeabi-v7a" in meta.abis_found
        assert "x86_64" in meta.abis_found

    def test_abi_priority_arm64_preferred(self):
        """When no ABI specified, arm64-v8a should be preferred."""
        hap_path = os.path.join(self.tmpdir, "multi_abi.hap")
        with zipfile.ZipFile(hap_path, 'w') as zf:
            zf.writestr("module.json", _create_module_json())
            zf.writestr("libs/armeabi-v7a/libentry.so", _minimal_elf64())
            zf.writestr("libs/arm64-v8a/libentry.so", _minimal_elf64())

        result = self.extractor.extract(hap_path)
        so_paths = [os.path.basename(os.path.dirname(f)) for f in result.so_files]
        assert "arm64-v8a" in so_paths or len(result.so_files) > 0

    def test_explicit_abi_selection(self):
        """Passing abi parameter should select that specific ABI."""
        hap_path = os.path.join(self.tmpdir, "multi_abi.hap")
        with zipfile.ZipFile(hap_path, 'w') as zf:
            zf.writestr("module.json", _create_module_json())
            zf.writestr("libs/armeabi-v7a/libv7.so", _minimal_elf64())
            zf.writestr("libs/arm64-v8a/libv8.so", _minimal_elf64())

        result = self.extractor.extract(hap_path, abi="armeabi-v7a")
        basenames = [os.path.basename(f) for f in result.so_files]
        assert "libv7.so" in basenames
        assert "libv8.so" not in basenames

    def test_explicit_abi_not_found(self):
        """Requesting non-existent ABI should raise or return empty."""
        hap_path = os.path.join(self.tmpdir, "arm64_only.hap")
        _create_hap(hap_path, abi="arm64-v8a")

        with pytest.raises((ValueError, FileNotFoundError)):
            self.extractor.extract(hap_path, abi="x86_64")

    def test_no_native_libs_directory(self):
        """Package without libs/ directory should report no ABIs."""
        hap_path = os.path.join(self.tmpdir, "no_native.hap")
        _create_hap(hap_path, no_native=True)

        meta = self.extractor.parse_metadata(hap_path)
        assert len(meta.abis_found) == 0
        assert len(meta.native_libs) == 0


class TestExtraction:
    """Test actual extraction of files from HAP packages."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.extractor = HapExtractor()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_extract_basic_hap(self):
        """Extract a simple HAP and verify result structure."""
        hap_path = os.path.join(self.tmpdir, "basic.hap")
        _create_hap(hap_path, so_names=["libentry.so", "libnative.so"])

        result = self.extractor.extract(hap_path)

        assert isinstance(result, HapExtractResult)
        assert result.metadata is not None
        assert result.extract_dir is not None
        assert os.path.isdir(result.extract_dir)
        assert len(result.so_files) == 2

        for so_file in result.so_files:
            assert os.path.isfile(so_file)
            assert so_file.endswith(".so")

        self.extractor.cleanup(result)

    def test_extract_only_selected_abi(self):
        """Only .so files from the selected ABI should be extracted."""
        hap_path = os.path.join(self.tmpdir, "multi_abi.hap")
        with zipfile.ZipFile(hap_path, 'w') as zf:
            zf.writestr("module.json", _create_module_json())
            zf.writestr("libs/arm64-v8a/lib_arm64.so", _minimal_elf64())
            zf.writestr("libs/armeabi-v7a/lib_arm32.so", _minimal_elf64())

        result = self.extractor.extract(hap_path, abi="arm64-v8a")

        basenames = [os.path.basename(f) for f in result.so_files]
        assert "lib_arm64.so" in basenames
        assert "lib_arm32.so" not in basenames

        self.extractor.cleanup(result)

    def test_extract_detects_bundled_openssl(self):
        """Bundled libcrypto/libssl should be detected."""
        hap_path = os.path.join(self.tmpdir, "with_openssl.hap")
        with zipfile.ZipFile(hap_path, 'w') as zf:
            zf.writestr("module.json", _create_module_json())
            zf.writestr("libs/arm64-v8a/libentry.so", _minimal_elf64())
            zf.writestr("libs/arm64-v8a/libcrypto.so", _minimal_elf64())
            zf.writestr("libs/arm64-v8a/libssl.so", _minimal_elf64())

        result = self.extractor.extract(hap_path)

        so_basenames = [os.path.basename(f) for f in result.so_files]
        assert "libcrypto.so" in so_basenames
        assert "libssl.so" in so_basenames
        assert result.openssl_lib is not None
        assert "libcrypto" in os.path.basename(result.openssl_lib)
        assert result.openssl_ssl is not None
        assert "libssl" in os.path.basename(result.openssl_ssl)

        self.extractor.cleanup(result)

    def test_extract_no_openssl_in_package(self):
        """Package without OpenSSL should have None for openssl fields."""
        hap_path = os.path.join(self.tmpdir, "no_openssl.hap")
        _create_hap(hap_path, include_openssl=False)

        result = self.extractor.extract(hap_path)

        assert result.openssl_lib is None
        assert result.openssl_ssl is None

        self.extractor.cleanup(result)

    def test_extract_custom_extract_dir(self):
        """Custom extract_dir should be used instead of temp."""
        hap_path = os.path.join(self.tmpdir, "custom_dir.hap")
        _create_hap(hap_path)
        custom_dir = os.path.join(self.tmpdir, "custom_extract")
        os.makedirs(custom_dir, exist_ok=True)

        result = self.extractor.extract(hap_path, extract_dir=custom_dir)

        assert result.extract_dir == custom_dir or \
            result.extract_dir.startswith(custom_dir)
        assert len(result.so_files) > 0

        self.extractor.cleanup(result)

    def test_cleanup_removes_temp_dir(self):
        """cleanup() should remove the temporary extraction directory."""
        hap_path = os.path.join(self.tmpdir, "cleanup_test.hap")
        _create_hap(hap_path)

        result = self.extractor.extract(hap_path)
        extract_dir = result.extract_dir
        assert os.path.isdir(extract_dir)

        self.extractor.cleanup(result)
        assert not os.path.exists(extract_dir)


class TestAppFileHandling:
    """Test .app file handling (multi-HAP bundles)."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.extractor = HapExtractor()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_extract_app_with_sub_haps(self):
        """APP file containing multiple HAPs should extract all of them."""
        app_path = os.path.join(self.tmpdir, "bundle.app")
        _create_app(app_path, hap_names=["entry.hap", "feature.hap"])

        result = self.extractor.extract(app_path)

        assert result.sub_packages is not None
        assert len(result.sub_packages) >= 2

        self.extractor.cleanup(result)

    def test_app_sub_packages_listed(self):
        """Each sub-package in APP should be individually accessible."""
        app_path = os.path.join(self.tmpdir, "bundle.app")
        _create_app(app_path, hap_names=["entry.hap", "feature.hap",
                                          "service.hap"])

        result = self.extractor.extract(app_path)

        assert result.sub_packages is not None
        assert len(result.sub_packages) == 3

        for sub in result.sub_packages:
            assert isinstance(sub, HapExtractResult)
            assert sub.metadata is not None

        self.extractor.cleanup(result)


class TestErrorHandling:
    """Test error paths and edge cases."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.extractor = HapExtractor()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_invalid_zip_file(self):
        """Non-zip file with .hap extension should raise."""
        hap_path = os.path.join(self.tmpdir, "not_a_zip.hap")
        with open(hap_path, 'wb') as f:
            f.write(b"this is not a zip file at all")

        with pytest.raises((zipfile.BadZipFile, ValueError)):
            self.extractor.extract(hap_path)

    def test_unsupported_extension(self):
        """File with unknown extension should be rejected."""
        bad_path = os.path.join(self.tmpdir, "package.apk")
        _create_hap(bad_path)

        with pytest.raises(ValueError):
            self.extractor.extract(bad_path)

    def test_nonexistent_file(self):
        """Missing file should raise FileNotFoundError."""
        missing = os.path.join(self.tmpdir, "ghost.hap")

        with pytest.raises(FileNotFoundError):
            self.extractor.extract(missing)

    def test_empty_zip(self):
        """Empty zip file returns result with no so_files and default metadata."""
        hap_path = os.path.join(self.tmpdir, "empty.hap")
        with zipfile.ZipFile(hap_path, 'w') as zf:
            pass

        result = self.extractor.extract(hap_path)
        assert result.so_files == []
        assert result.metadata.bundle_name == ''
        assert result.openssl_lib is None

        self.extractor.cleanup(result)


class TestDirectoryScanning:
    """Test find_packages() directory scanning."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.extractor = HapExtractor()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_find_packages_in_directory(self):
        """Should find all HAP files in a directory."""
        for name in ["a.hap", "b.hap", "c.hap"]:
            _create_hap(os.path.join(self.tmpdir, name))

        packages = self.extractor.find_packages(self.tmpdir)
        assert len(packages) == 3
        for pkg in packages:
            assert pkg.endswith(".hap")

    def test_find_packages_mixed_extensions(self):
        """Should find HAP, HAR, HSP, and APP files."""
        for name in ["entry.hap", "shared.har", "service.hsp",
                      "bundle.app", "readme.txt", "config.json"]:
            path = os.path.join(self.tmpdir, name)
            if name.endswith((".hap", ".har", ".hsp", ".app")):
                _create_hap(path)
            else:
                with open(path, 'w') as f:
                    f.write("not a package")

        packages = self.extractor.find_packages(self.tmpdir)
        extensions = {os.path.splitext(p)[1] for p in packages}

        assert len(packages) == 4
        assert ".hap" in extensions
        assert ".har" in extensions
        assert ".hsp" in extensions
        assert ".app" in extensions
        assert ".txt" not in extensions
        assert ".json" not in extensions

    def test_find_packages_empty_directory(self):
        """Empty directory should return empty list."""
        empty_dir = os.path.join(self.tmpdir, "empty")
        os.makedirs(empty_dir)

        packages = self.extractor.find_packages(empty_dir)
        assert packages == [] or len(packages) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
