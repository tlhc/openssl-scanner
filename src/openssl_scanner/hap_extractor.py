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
    MAX_EXTRACT_SIZE = 2 * 1024 * 1024 * 1024

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
        """Extract a single HAP/HAR/HSP package."""
        ext = os.path.splitext(package_path)[1].lower()

        with zipfile.ZipFile(package_path, 'r') as zf:
            module_config = self._read_module_json(zf)
            abis, native_libs = self._discover_native_libs(zf)
            metadata = self._build_metadata(
                package_path, ext[1:], module_config, abis, native_libs
            )

            selected_abi = self._select_abi(abis, abi, package_path)
            if not selected_abi:
                if extract_dir is None:
                    extract_dir = tempfile.mkdtemp(prefix='hap_scan_')
                return HapExtractResult(
                    metadata=metadata,
                    extract_dir=extract_dir,
                    so_files=[]
                )

            if extract_dir is None:
                extract_dir = tempfile.mkdtemp(prefix='hap_scan_')

            so_files = self._extract_abi_libs(zf, selected_abi, extract_dir)

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

    def _discover_native_libs(
        self, zf: zipfile.ZipFile
    ) -> tuple:
        """
        Discover ABI directories and native libraries in the archive.

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
            if '.so' in filename:
                native_libs.setdefault(abi, []).append(filename)

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

    def _select_abi(self, abis: List[str], requested_abi: Optional[str],
                    package_path: str) -> Optional[str]:
        """Select target ABI for extraction."""
        if not abis:
            logger.info("No native libraries found in %s", package_path)
            return None

        if requested_abi:
            if requested_abi not in abis:
                raise ValueError(
                    f"ABI '{requested_abi}' not found in package. "
                    f"Available: {', '.join(abis)}"
                )
            return requested_abi

        selected = abis[0]
        logger.debug("Auto-selected ABI: %s (from %s)", selected, abis)
        return selected

    def _extract_abi_libs(self, zf: zipfile.ZipFile, abi: str,
                          extract_dir: str) -> List[str]:
        """Extract .so files for a specific ABI to extract_dir."""
        prefix = f'libs/{abi}/'
        so_files = []

        for entry in zf.namelist():
            if not entry.startswith(prefix):
                continue
            if '.so' not in entry:
                continue

            filename = os.path.basename(entry)
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

    def _detect_openssl(
        self, so_files: List[str]
    ) -> tuple:
        """
        Detect OpenSSL libraries among extracted .so files.

        Returns:
            (libcrypto_path, libssl_path)
        """
        libcrypto = None
        libssl = None

        for path in so_files:
            basename = os.path.basename(path).lower()
            if '.so' not in basename:
                continue
            for pattern in OPENSSL_LIBRARY_PATTERNS:
                if not basename.startswith(pattern):
                    continue
                if 'crypto' in basename and not libcrypto:
                    libcrypto = path
                elif 'ssl' in basename and not libssl:
                    libssl = path

        return libcrypto, libssl
