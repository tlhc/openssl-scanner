"""
Tests for proc_analyzer module.

Uses mock /proc data - can run on any platform.
"""

import os
import sys
import pytest
from unittest.mock import patch, mock_open, MagicMock

from openssl_scanner.proc_analyzer import ProcAnalyzer, MappedLibrary, ProcessInfo


class TestParseMapLine:
    """Test _parse_maps_line static method."""

    def test_regular_so(self):
        line = "7f1a2b3c4000-7f1a2b3c5000 r-xp 00000000 08:01 131073 /usr/lib/libfoo.so"
        result = ProcAnalyzer._parse_maps_line(line)
        assert result is not None
        assert result.path == "/usr/lib/libfoo.so"
        assert result.basename == "libfoo.so"
        assert result.deleted is False

    def test_versioned_so(self):
        line = "7f1a2b3c4000-7f1a2b5c6000 r-xp 00000000 08:01 131073 /usr/lib/x86_64-linux-gnu/libcrypto.so.3"
        result = ProcAnalyzer._parse_maps_line(line)
        assert result is not None
        assert result.path == "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"
        assert result.basename == "libcrypto.so.3"
        assert result.deleted is False

    def test_so_with_minor_version(self):
        line = "7f1a2b3c4000-7f1a2b3c5000 r--p 00001000 08:01 131073 /lib64/libc.so.6"
        result = ProcAnalyzer._parse_maps_line(line)
        assert result is not None
        assert result.path == "/lib64/libc.so.6"
        assert result.basename == "libc.so.6"

    def test_deleted_so(self):
        line = "7f1a2b3c4000-7f1a2b3c5000 r-xp 00000000 08:01 131073 /usr/lib/libold.so.1 (deleted)"
        result = ProcAnalyzer._parse_maps_line(line)
        assert result is not None
        assert result.path == "/usr/lib/libold.so.1"
        assert result.basename == "libold.so.1"
        assert result.deleted is True

    def test_non_so_file_skip(self):
        line = "7f1a2b3c4000-7f1a2b3c5000 r-xp 00000000 08:01 131073 /usr/bin/python3"
        result = ProcAnalyzer._parse_maps_line(line)
        assert result is None

    def test_vdso_skip(self):
        line = "7fffe8ffe000-7fffe9000000 r-xp 00000000 00:00 0 [vdso]"
        result = ProcAnalyzer._parse_maps_line(line)
        assert result is None

    def test_vsyscall_skip(self):
        line = "ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0 [vsyscall]"
        result = ProcAnalyzer._parse_maps_line(line)
        assert result is None

    def test_heap_skip(self):
        line = "5555557c4000-5555557e5000 rw-p 00000000 00:00 0 [heap]"
        result = ProcAnalyzer._parse_maps_line(line)
        assert result is None

    def test_stack_skip(self):
        line = "7fffe8e00000-7fffe9000000 rw-p 00000000 00:00 0 [stack]"
        result = ProcAnalyzer._parse_maps_line(line)
        assert result is None

    def test_anonymous_skip(self):
        line = "7f1a2b3c4000-7f1a2b3c5000 rw-p 00000000 00:00 0"
        result = ProcAnalyzer._parse_maps_line(line)
        assert result is None

    def test_empty_line_skip(self):
        result = ProcAnalyzer._parse_maps_line("")
        assert result is None

    def test_whitespace_only_skip(self):
        result = ProcAnalyzer._parse_maps_line("   ")
        assert result is None

    def test_rw_data_segment(self):
        line = "7f1a2b3c5000-7f1a2b3c6000 rw-p 00001000 08:01 131073 /usr/lib/libssl.so.3"
        result = ProcAnalyzer._parse_maps_line(line)
        assert result is not None
        assert result.path == "/usr/lib/libssl.so.3"

    def test_deep_nested_path(self):
        line = "7f1a2b3c4000-7f1a2b3c5000 r-xp 00000000 08:01 131073 /opt/app/vendor/lib/x86_64/libcustom.so.2.1"
        result = ProcAnalyzer._parse_maps_line(line)
        assert result is not None
        assert result.path == "/opt/app/vendor/lib/x86_64/libcustom.so.2.1"
        assert result.basename == "libcustom.so.2.1"


class TestParseMaps:
    """Test parse_maps with mocked /proc filesystem."""

    SAMPLE_MAPS = """\
55a1b2c3d000-55a1b2c4e000 r-xp 00000000 08:01 100000 /usr/sbin/nginx
55a1b2c4e000-55a1b2c4f000 r--p 00010000 08:01 100000 /usr/sbin/nginx
7f1a2b000000-7f1a2b200000 r-xp 00000000 08:01 200001 /usr/lib/libcrypto.so.3
7f1a2b200000-7f1a2b280000 r--p 00200000 08:01 200001 /usr/lib/libcrypto.so.3
7f1a2b280000-7f1a2b2a0000 rw-p 00280000 08:01 200001 /usr/lib/libcrypto.so.3
7f1a2b300000-7f1a2b380000 r-xp 00000000 08:01 200002 /usr/lib/libssl.so.3
7f1a2b380000-7f1a2b390000 r--p 00080000 08:01 200002 /usr/lib/libssl.so.3
7f1a2b400000-7f1a2b500000 r-xp 00000000 08:01 300001 /lib64/libc.so.6
7f1a2b500000-7f1a2b510000 r--p 00100000 08:01 300001 /lib64/libc.so.6
7f1a2b600000-7f1a2b620000 r-xp 00000000 08:01 300002 /lib64/libz.so.1
7f1a2b700000-7f1a2b701000 r-xp 00000000 08:01 400001 /usr/lib/libplugin.so (deleted)
7fffe8ffe000-7fffe9000000 r-xp 00000000 00:00 0 [vdso]
5555557c4000-5555557e5000 rw-p 00000000 00:00 0 [heap]
7fffe8e00000-7fffe9000000 rw-p 00000000 00:00 0 [stack]
"""

    def test_deduplication(self):
        analyzer = ProcAnalyzer.__new__(ProcAnalyzer)
        with patch('builtins.open', mock_open(read_data=self.SAMPLE_MAPS)):
            libs = analyzer.parse_maps(1234)

        paths = [lib.path for lib in libs]
        assert len(paths) == len(set(paths)), "Should deduplicate by path"

    def test_so_files_extracted(self):
        analyzer = ProcAnalyzer.__new__(ProcAnalyzer)
        with patch('builtins.open', mock_open(read_data=self.SAMPLE_MAPS)):
            libs = analyzer.parse_maps(1234)

        paths = {lib.path for lib in libs}
        assert '/usr/lib/libcrypto.so.3' in paths
        assert '/usr/lib/libssl.so.3' in paths
        assert '/lib64/libc.so.6' in paths
        assert '/lib64/libz.so.1' in paths

    def test_executable_excluded(self):
        analyzer = ProcAnalyzer.__new__(ProcAnalyzer)
        with patch('builtins.open', mock_open(read_data=self.SAMPLE_MAPS)):
            libs = analyzer.parse_maps(1234)

        paths = {lib.path for lib in libs}
        assert '/usr/sbin/nginx' not in paths

    def test_deleted_detected(self):
        analyzer = ProcAnalyzer.__new__(ProcAnalyzer)
        with patch('builtins.open', mock_open(read_data=self.SAMPLE_MAPS)):
            libs = analyzer.parse_maps(1234)

        deleted = [lib for lib in libs if lib.deleted]
        assert len(deleted) == 1
        assert deleted[0].path == '/usr/lib/libplugin.so'

    def test_special_regions_excluded(self):
        analyzer = ProcAnalyzer.__new__(ProcAnalyzer)
        with patch('builtins.open', mock_open(read_data=self.SAMPLE_MAPS)):
            libs = analyzer.parse_maps(1234)

        paths = {lib.path for lib in libs}
        for path in paths:
            assert not path.startswith('[')

    def test_count(self):
        analyzer = ProcAnalyzer.__new__(ProcAnalyzer)
        with patch('builtins.open', mock_open(read_data=self.SAMPLE_MAPS)):
            libs = analyzer.parse_maps(1234)

        assert len(libs) == 5


class TestPlatformCheck:
    """Test platform validation."""

    def test_non_linux_raises(self):
        with patch.object(sys, 'platform', 'darwin'):
            with pytest.raises(RuntimeError, match="requires Linux"):
                ProcAnalyzer._check_platform()

    def test_linux_no_proc_raises(self):
        with patch.object(sys, 'platform', 'linux'):
            with patch('os.path.isdir', return_value=False):
                with pytest.raises(RuntimeError, match="/proc filesystem not found"):
                    ProcAnalyzer._check_platform()

    def test_is_available_non_linux(self):
        with patch.object(sys, 'platform', 'darwin'):
            assert ProcAnalyzer.is_available() is False

    def test_is_available_linux_with_proc(self):
        with patch.object(sys, 'platform', 'linux'):
            with patch('os.path.isdir', return_value=True):
                assert ProcAnalyzer.is_available() is True


class TestReadHelpers:
    """Test _read_exe, _read_cmdline, _read_status helpers."""

    def test_read_cmdline(self):
        analyzer = ProcAnalyzer.__new__(ProcAnalyzer)
        raw = b'/usr/sbin/nginx\x00-g\x00daemon off;\x00'
        with patch('builtins.open', mock_open(read_data=raw)):
            result = analyzer._read_cmdline(1234)
        assert result == '/usr/sbin/nginx -g daemon off;'

    def test_read_status(self):
        status_content = "Name:\tnginx\nPid:\t1234\nUid:\t0\t0\t0\t0\nThreads:\t5\nVmRSS:\t12800 kB\n"
        analyzer = ProcAnalyzer.__new__(ProcAnalyzer)
        with patch('builtins.open', mock_open(read_data=status_content)):
            result = analyzer._read_status(1234)
        assert result['Name'] == 'nginx'
        assert result['Pid'] == '1234'
        assert result['Threads'] == '5'
        assert result['VmRSS'] == '12800 kB'

    def test_read_exe(self):
        analyzer = ProcAnalyzer.__new__(ProcAnalyzer)
        with patch('os.readlink', return_value='/usr/sbin/nginx'):
            result = analyzer._read_exe(1234)
        assert result == '/usr/sbin/nginx'

    def test_read_exe_permission_denied(self):
        analyzer = ProcAnalyzer.__new__(ProcAnalyzer)
        with patch('os.readlink', side_effect=PermissionError("Permission denied")):
            result = analyzer._read_exe(1234)
        assert result == ''


class TestFromPid:
    """Test from_pid with mocked /proc."""

    SAMPLE_MAPS = """\
7f1a2b000000-7f1a2b200000 r-xp 00000000 08:01 200001 /usr/lib/libcrypto.so.3
7f1a2b300000-7f1a2b380000 r-xp 00000000 08:01 200002 /usr/lib/libssl.so.3
"""
    SAMPLE_STATUS = "Name:\tnginx\nPid:\t1234\nUid:\t0\t0\t0\t0\nThreads:\t5\nVmRSS:\t12800 kB\n"

    @patch.object(sys, 'platform', 'linux')
    @patch('os.path.isdir', return_value=True)
    @patch('os.readlink', return_value='/usr/sbin/nginx')
    def test_from_pid_success(self, mock_readlink, mock_isdir):
        analyzer = ProcAnalyzer()

        def open_side_effect(path, *args, **kwargs):
            if 'maps' in str(path):
                return mock_open(read_data=self.SAMPLE_MAPS)()
            elif 'status' in str(path):
                return mock_open(read_data=self.SAMPLE_STATUS)()
            elif 'cmdline' in str(path):
                return mock_open(read_data=b'/usr/sbin/nginx\x00-g\x00daemon off;\x00')()
            raise FileNotFoundError(path)

        with patch('builtins.open', side_effect=open_side_effect):
            info = analyzer.from_pid(1234)

        assert info.pid == 1234
        assert info.name == 'nginx'
        assert info.exe_path == '/usr/sbin/nginx'
        assert info.uid == 0
        assert info.threads == 5
        assert info.vm_rss_kb == 12800
        assert len(info.mapped_libraries) == 2

    @patch.object(sys, 'platform', 'linux')
    @patch('os.path.isdir')
    def test_from_pid_not_found(self, mock_isdir):
        mock_isdir.side_effect = lambda p: p == '/proc' and True or False
        analyzer = ProcAnalyzer()

        with pytest.raises(FileNotFoundError, match="Process 99999 not found"):
            analyzer.from_pid(99999)
