"""
Process analyzer for Linux /proc filesystem.

Extracts loaded shared libraries from running processes
by parsing /proc/<pid>/maps. Linux-only module.
"""

import os
import sys
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class MappedLibrary:
    """A shared library mapped into process memory."""
    path: str
    basename: str
    deleted: bool = False
    runtime_only: bool = False


@dataclass
class ProcessInfo:
    """Metadata about a running process."""
    pid: int
    name: str
    exe_path: str
    cmdline: str
    uid: Optional[int] = None
    threads: Optional[int] = None
    vm_rss_kb: Optional[int] = None
    mapped_libraries: List[MappedLibrary] = field(default_factory=list)


class ProcAnalyzer:
    """
    Analyzes running processes via /proc filesystem.

    Reads /proc/<pid>/exe, maps, status, cmdline to build
    a complete picture of a process and its loaded libraries.
    """

    @staticmethod
    def is_available() -> bool:
        """Check if /proc filesystem is accessible."""
        return sys.platform == 'linux' and os.path.isdir('/proc')

    @staticmethod
    def _check_platform() -> None:
        """Raise RuntimeError on non-Linux platforms."""
        if sys.platform != 'linux':
            raise RuntimeError(
                f"Process scan requires Linux (/proc filesystem). "
                f"Current platform: {sys.platform}"
            )
        if not os.path.isdir('/proc'):
            raise RuntimeError("/proc filesystem not found")

    def from_pid(self, pid: int) -> ProcessInfo:
        """
        Build ProcessInfo from a PID.

        Args:
            pid: Process ID

        Returns:
            ProcessInfo with metadata and mapped libraries

        Raises:
            FileNotFoundError: Process does not exist
            PermissionError: Cannot read /proc/<pid>
        """
        self._check_platform()

        proc_dir = f'/proc/{pid}'
        if not os.path.isdir(proc_dir):
            raise FileNotFoundError(f"Process {pid} not found")

        exe_path = self._read_exe(pid)
        cmdline = self._read_cmdline(pid)
        status = self._read_status(pid)
        mapped_libs = self.parse_maps(pid)

        name = status.get('Name', os.path.basename(exe_path))
        uid = None
        uid_str = status.get('Uid', '')
        if uid_str:
            parts = uid_str.split()
            if parts:
                try:
                    uid = int(parts[0])
                except ValueError:
                    pass

        threads = None
        threads_str = status.get('Threads', '')
        if threads_str:
            try:
                threads = int(threads_str.strip())
            except ValueError:
                pass

        vm_rss_kb = None
        rss_str = status.get('VmRSS', '')
        if rss_str:
            parts = rss_str.split()
            if parts:
                try:
                    vm_rss_kb = int(parts[0])
                except ValueError:
                    pass

        return ProcessInfo(
            pid=pid,
            name=name,
            exe_path=exe_path,
            cmdline=cmdline,
            uid=uid,
            threads=threads,
            vm_rss_kb=vm_rss_kb,
            mapped_libraries=mapped_libs,
        )

    def resolve_by_name(self, name: str) -> List[Tuple[int, str, str]]:
        """
        Find processes by name.

        Iterates /proc/*/status to find matching process names.

        Args:
            name: Process name to search for (case-sensitive, matches basename)

        Returns:
            List of (pid, name, cmdline) tuples
        """
        self._check_platform()

        results = []
        try:
            entries = os.listdir('/proc')
        except PermissionError:
            raise PermissionError("Cannot read /proc directory")

        for entry in entries:
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                status = self._read_status(pid)
                proc_name = status.get('Name', '')
                if proc_name == name:
                    cmdline = self._read_cmdline(pid)
                    results.append((pid, proc_name, cmdline))
            except (FileNotFoundError, PermissionError):
                continue

        return results

    def parse_maps(self, pid: int) -> List[MappedLibrary]:
        """
        Parse /proc/<pid>/maps to extract loaded shared libraries.

        Filters for lines containing .so paths, deduplicates by path.

        Args:
            pid: Process ID

        Returns:
            List of unique MappedLibrary objects
        """
        maps_path = f'/proc/{pid}/maps'
        try:
            with open(maps_path, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            raise FileNotFoundError(f"Process {pid} not found (no /proc/{pid}/maps)")
        except PermissionError:
            raise PermissionError(
                f"Cannot read /proc/{pid}/maps. Try running with sudo."
            )

        seen: Dict[str, MappedLibrary] = {}
        for line in lines:
            lib = self._parse_maps_line(line)
            if lib and lib.path not in seen:
                seen[lib.path] = lib

        return list(seen.values())

    def _read_exe(self, pid: int) -> str:
        """Read /proc/<pid>/exe symlink target."""
        exe_link = f'/proc/{pid}/exe'
        try:
            return os.readlink(exe_link)
        except (FileNotFoundError, PermissionError) as e:
            logger.warning("Cannot read %s: %s", exe_link, e)
            return ''

    def _read_cmdline(self, pid: int) -> str:
        """Read /proc/<pid>/cmdline, replace null bytes with spaces."""
        cmdline_path = f'/proc/{pid}/cmdline'
        try:
            with open(cmdline_path, 'rb') as f:
                data = f.read()
            return data.decode('utf-8', errors='replace').replace('\x00', ' ').strip()
        except (FileNotFoundError, PermissionError):
            return ''

    def _read_status(self, pid: int) -> Dict[str, str]:
        """Parse /proc/<pid>/status into key-value pairs."""
        status_path = f'/proc/{pid}/status'
        result: Dict[str, str] = {}
        try:
            with open(status_path, 'r') as f:
                for line in f:
                    if ':' in line:
                        key, _, value = line.partition(':')
                        result[key.strip()] = value.strip()
        except (FileNotFoundError, PermissionError):
            pass
        return result

    @staticmethod
    def _parse_maps_line(line: str) -> Optional[MappedLibrary]:
        """
        Parse a single /proc/pid/maps line.

        Format: address perms offset dev inode pathname
        Example:
          7f1234000000-7f1234100000 r-xp 00000000 08:01 12345 /usr/lib/libcrypto.so.3

        Returns:
            MappedLibrary if line contains a .so path, None otherwise
        """
        line = line.strip()
        if not line:
            return None

        parts = line.split(None, 5)
        if len(parts) < 6:
            return None

        pathname = parts[5]

        if pathname.startswith('['):
            return None

        if '.so' not in pathname:
            return None

        deleted = False
        clean_path = pathname
        if pathname.endswith(' (deleted)'):
            deleted = True
            clean_path = pathname[:-len(' (deleted)')]

        if not os.path.isabs(clean_path):
            return None

        basename = os.path.basename(clean_path)

        return MappedLibrary(
            path=clean_path,
            basename=basename,
            deleted=deleted,
        )
