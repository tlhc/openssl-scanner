"""
HAP/HAR/HSP/APP package extractor for OpenHarmony.

Extracts native .so libraries from OpenHarmony application packages
and parses module.json metadata for dependency analysis.
"""

import json
import logging
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .constants import OPENSSL_LIBRARY_PATTERNS

logger = logging.getLogger(__name__)


@dataclass
class HapMetadata:
    """Metadata extracted from an OpenHarmony package's module.json."""
    package_path: str
    package_type: str
    bundle_name: str
    module_name: str
    module_type: str
    version_name: str
    version_code: int
    min_api_version: int
    device_types: List[str]
    abis_found: List[str]
    native_libs: Dict[str, List[str]]


@dataclass
class HapExtractResult:
    """Result of extracting an OpenHarmony package."""
    metadata: HapMetadata
    extract_dir: str
    so_files: List[str]
    openssl_lib: Optional[str] = None
    openssl_ssl: Optional[str] = None
    sub_packages: List['HapExtractResult'] = field(default_factory=list)


class HapExtractor:
    """
    Extracts and analyzes OpenHarmony application packages.

    Handles HAP (Harmony Ability Package), HAR (Harmony Archive),
    HSP (Harmony Shared Package), and APP (application bundle)
    formats. All are ZIP archives containing native .so libraries
    under libs/<abi>/.
    """

    SUPPORTED_EXTENSIONS = {'.hap', '.har', '.hsp', '.app'}
    ABI_PRIORITY = ['arm64-v8a', 'armeabi-v7a', 'armeabi', 'x86_64', 'x86']
    ELF_MAGIC = b'\x7fELF'
    MAX_EXTRACT_SIZE = 2 * 1024 * 1024 * 1024

    ABI_ELF_MACHINE = {
        'arm64-v8a':   0xB7,   # EM_AARCH64
        'armeabi-v7a': 0x28,   # EM_ARM
        'armeabi':     0x28,   # EM_ARM
        'x86_64':      0x3E,   # EM_X86_64
        'x86':         0x03,   # EM_386
    }

    def extract(self, package_path: str, abi: Optional[str] = None,
                extract_dir: Optional[str] = None) -> HapExtractResult:
        """
        Extract native libraries from a package.

        Args:
            package_path: Path to .hap/.har/.hsp/.app file
            abi: Target ABI to extract (auto-selects if None)
            extract_dir: Directory for extraction (creates temp if None)

        Returns:
            HapExtractResult with paths to extracted .so files

        Raises:
            ValueError: Unsupported file extension
            zipfile.BadZipFile: Invalid archive
            FileNotFoundError: Package file not found
        """
        package_path = os.path.abspath(package_path)
        ext = os.path.splitext(package_path)[1].lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Unsupported extension '{ext}'. "
                f"Expected one of: {', '.join(sorted(self.SUPPORTED_EXTENSIONS))}"
            )

        if not os.path.isfile(package_path):
            raise FileNotFoundError(f"Package not found: {package_path}")

        if ext == '.app':
            return self._extract_app(package_path, abi, extract_dir)

        return self._extract_single(package_path, abi, extract_dir)

    def parse_metadata(self, package_path: str) -> HapMetadata:
        """
        Parse package metadata without full extraction.

        Args:
            package_path: Path to .hap/.har/.hsp/.app file

        Returns:
            HapMetadata with package information
        """
        package_path = os.path.abspath(package_path)
        ext = os.path.splitext(package_path)[1].lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Unsupported extension '{ext}'. "
                f"Expected one of: {', '.join(sorted(self.SUPPORTED_EXTENSIONS))}"
            )

        with zipfile.ZipFile(package_path, 'r') as zf:
            module_config = self._read_module_json(zf)
            abis, native_libs = self._discover_native_libs(zf)

        return self._build_metadata(
            package_path, ext[1:], module_config, abis, native_libs
        )

    def find_packages(self, directory: str) -> List[str]:
        """
        Find all supported packages in a directory tree.

        Args:
            directory: Root directory to search

        Returns:
            Sorted list of absolute paths to package files
        """
        packages = []
        for root, _dirs, files in os.walk(directory):
            for name in files:
                ext = os.path.splitext(name)[1].lower()
                if ext in self.SUPPORTED_EXTENSIONS:
                    packages.append(os.path.join(root, name))
        packages.sort()
        return packages

    def cleanup(self, extract_result: HapExtractResult) -> None:
        """
        Remove temporary extraction directory.

        Args:
            extract_result: Result from extract() to clean up
        """
        for sub in extract_result.sub_packages:
            self.cleanup(sub)

        if extract_result.extract_dir and os.path.isdir(extract_result.extract_dir):
            shutil.rmtree(extract_result.extract_dir, ignore_errors=True)
            logger.debug("Cleaned up: %s", extract_result.extract_dir)

    def _extract_single(self, package_path: str, abi: Optional[str],
                        extract_dir: Optional[str]) -> HapExtractResult:
        """Extract a single HAP/HAR/HSP package.

        When abi is None, extracts ALL ABIs into per-ABI subdirectories.
        When abi is specified, extracts only that ABI.
        """
        ext = os.path.splitext(package_path)[1].lower()

        with zipfile.ZipFile(package_path, 'r') as zf:
            module_config = self._read_module_json(zf)
            abis, native_libs = self._discover_native_libs(zf)
            metadata = self._build_metadata(
                package_path, ext[1:], module_config, abis, native_libs
            )

            if not abis:
                logger.info("No native libraries found in %s", package_path)
                if extract_dir is None:
                    extract_dir = tempfile.mkdtemp(prefix='hap_scan_')
                return HapExtractResult(
                    metadata=metadata,
                    extract_dir=extract_dir,
                    so_files=[]
                )

            if extract_dir is None:
                extract_dir = tempfile.mkdtemp(prefix='hap_scan_')

            if abi:
                if abi not in abis:
                    raise ValueError(
                        f"ABI '{abi}' not found in package. "
                        f"Available: {', '.join(abis)}"
                    )
                target_abis = [abi]
            else:
                target_abis = abis

            so_files = []
            for abi_name in target_abis:
                abi_dir = os.path.join(extract_dir, abi_name)
                os.makedirs(abi_dir, exist_ok=True)
                extracted = self._extract_abi_libs(zf, abi_name, abi_dir)
                so_files.extend(extracted)
                logger.debug("ABI %s: extracted %d files", abi_name, len(extracted))

        openssl_lib, openssl_ssl = self._detect_openssl(so_files)

        return HapExtractResult(
            metadata=metadata,
            extract_dir=extract_dir,
            so_files=so_files,
            openssl_lib=openssl_lib,
            openssl_ssl=openssl_ssl
        )

    def _extract_app(self, app_path: str, abi: Optional[str],
                     extract_dir: Optional[str]) -> HapExtractResult:
        """Extract an APP bundle containing multiple HAP/HSP packages."""
        if extract_dir is None:
            extract_dir = tempfile.mkdtemp(prefix='hap_scan_')

        with zipfile.ZipFile(app_path, 'r') as zf:
            module_config = self._read_module_json(zf)
            abis, native_libs = self._discover_native_libs(zf)
            metadata = self._build_metadata(
                app_path, 'app', module_config, abis, native_libs
            )

            sub_packages = []
            for entry in zf.namelist():
                entry_ext = os.path.splitext(entry)[1].lower()
                if entry_ext in {'.hap', '.hsp'}:
                    safe_name = os.path.basename(entry)
                    if not safe_name:
                        logger.warning("Skipping entry with empty basename: %s", entry)
                        continue
                    sub_path = os.path.join(extract_dir, safe_name)
                    real_sub = os.path.realpath(sub_path)
                    real_base = os.path.realpath(extract_dir)
                    if not real_sub.startswith(real_base + os.sep):
                        logger.warning("Skipping path traversal entry: %s", entry)
                        continue

                    self._safe_extract_member(zf, entry, sub_path)

                    try:
                        sub_result = self._extract_single(
                            sub_path, abi, None
                        )
                        sub_packages.append(sub_result)
                    except (zipfile.BadZipFile, KeyError) as e:
                        logger.warning(
                            "Failed to process sub-package %s: %s", entry, e
                        )

        all_so_files = []
        openssl_lib = None
        openssl_ssl = None
        for sub in sub_packages:
            all_so_files.extend(sub.so_files)
            if sub.openssl_lib and not openssl_lib:
                openssl_lib = sub.openssl_lib
            if sub.openssl_ssl and not openssl_ssl:
                openssl_ssl = sub.openssl_ssl

        return HapExtractResult(
            metadata=metadata,
            extract_dir=extract_dir,
            so_files=all_so_files,
            openssl_lib=openssl_lib,
            openssl_ssl=openssl_ssl,
            sub_packages=sub_packages
        )

    def _read_module_json(self, zf: zipfile.ZipFile) -> dict:
        """Read and parse module.json from a ZIP archive."""
        try:
            with zf.open('module.json') as f:
                return json.loads(f.read())
        except KeyError:
            logger.warning("No module.json found in archive")
            return {}
        except json.JSONDecodeError as e:
            logger.warning("Malformed module.json: %s", e)
            return {}

    def _is_elf_entry(self, zf: zipfile.ZipFile, entry: str,
                      expected_machine: Optional[int] = None) -> bool:
        """Check if a ZIP entry contains an ELF binary.

        Args:
            zf: Open ZipFile
            entry: ZIP entry name
            expected_machine: If set, also verify e_machine matches this value
        """
        try:
            with zf.open(entry) as f:
                header = f.read(20)
                if len(header) < 4 or header[:4] != self.ELF_MAGIC:
                    return False
                if expected_machine is not None and len(header) >= 20:
                    ei_data = header[5]
                    if ei_data == 2:
                        machine = (header[18] << 8) | header[19]
                    else:
                        machine = header[18] | (header[19] << 8)
                    return machine == expected_machine
                return True
        except (KeyError, zipfile.BadZipFile):
            return False

    def _discover_native_libs(
        self, zf: zipfile.ZipFile
    ) -> tuple:
        """
        Discover ABI directories and native libraries in the archive.

        Uses ELF magic bytes to identify binaries, not file extension.

        Returns:
            (abis_found, native_libs_by_abi)
        """
        native_libs: Dict[str, List[str]] = {}
        for entry in zf.namelist():
            if not entry.startswith('libs/'):
                continue
            parts = entry.split('/')
            if len(parts) < 3:
                continue
            abi = parts[1]
            filename = parts[-1]
            if not filename:
                continue
            if not self._is_elf_entry(zf, entry):
                continue
            native_libs.setdefault(abi, []).append(filename)
            expected = self.ABI_ELF_MACHINE.get(abi)
            if expected and not self._is_elf_entry(zf, entry, expected_machine=expected):
                logger.warning(
                    "Architecture mismatch: %s is ELF but wrong arch for %s",
                    entry, abi
                )

        abis = [a for a in self.ABI_PRIORITY if a in native_libs]
        for a in sorted(native_libs.keys()):
            if a not in abis:
                abis.append(a)

        return abis, native_libs

    def _build_metadata(
        self, package_path: str, package_type: str,
        config: dict, abis: List[str],
        native_libs: Dict[str, List[str]]
    ) -> HapMetadata:
        """Build HapMetadata from parsed module.json config."""
        app = config.get('app', {})
        module = config.get('module', {})

        return HapMetadata(
            package_path=package_path,
            package_type=package_type,
            bundle_name=app.get('bundleName', ''),
            module_name=module.get('name', ''),
            module_type=module.get('type', ''),
            version_name=app.get('versionName', '0.0.0'),
            version_code=app.get('versionCode', 0),
            min_api_version=app.get('minAPIVersion', 0),
            device_types=module.get('deviceTypes', []),
            abis_found=abis,
            native_libs=native_libs,
        )

    def _extract_abi_libs(self, zf: zipfile.ZipFile, abi: str,
                          extract_dir: str) -> List[str]:
        """Extract ELF binaries for a specific ABI to extract_dir.

        Extracts all ELF files; warns on architecture mismatch.
        """
        prefix = f'libs/{abi}/'
        expected = self.ABI_ELF_MACHINE.get(abi)
        so_files = []

        for entry in zf.namelist():
            if not entry.startswith(prefix):
                continue
            filename = os.path.basename(entry)
            if not filename:
                continue
            if not self._is_elf_entry(zf, entry):
                continue
            if expected and not self._is_elf_entry(zf, entry, expected_machine=expected):
                logger.warning(
                    "Architecture mismatch: %s is ELF but wrong arch for %s",
                    entry, abi
                )

            dest_path = os.path.join(extract_dir, filename)
            self._safe_extract_member(zf, entry, dest_path)
            so_files.append(dest_path)
            logger.debug("Extracted: %s -> %s", entry, dest_path)

        return so_files

    def _safe_extract_member(self, zf: zipfile.ZipFile,
                             entry: str, dest_path: str) -> None:
        """Extract a single ZIP member with size limit."""
        with zf.open(entry) as src, open(dest_path, 'wb') as dst:
            copied = 0
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > self.MAX_EXTRACT_SIZE:
                    dst.close()
                    os.unlink(dest_path)
                    raise ValueError(
                        f"Entry too large (>{self.MAX_EXTRACT_SIZE} bytes): {entry}"
                    )
                dst.write(chunk)

    @staticmethod
    def _is_elf_file(path: str) -> bool:
        """Check if file on disk is an ELF binary."""
        try:
            with open(path, 'rb') as f:
                return f.read(4) == HapExtractor.ELF_MAGIC
        except (IOError, OSError):
            return False

    def _detect_openssl(
        self, so_files: List[str]
    ) -> tuple:
        """
        Detect OpenSSL libraries among extracted files.

        Uses ELF magic verification before pattern matching.

        Returns:
            (libcrypto_path, libssl_path)
        """
        libcrypto = None
        libssl = None

        for path in so_files:
            if not self._is_elf_file(path):
                continue
            basename = os.path.basename(path).lower()
            for pattern in OPENSSL_LIBRARY_PATTERNS:
                if not basename.startswith(pattern):
                    continue
                if 'crypto' in basename and not libcrypto:
                    libcrypto = path
                elif 'ssl' in basename and not libssl:
                    libssl = path

        return libcrypto, libssl
