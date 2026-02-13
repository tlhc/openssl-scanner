
import pytest
from unittest.mock import MagicMock
import sys
import os

# Adjust path to import src
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openssl_scanner.scanner import Scanner, FileResult
from openssl_scanner.elf_analyzer import ELFInfo, Symbol

class TestScannerLogic:
    def setup_method(self):
        self.scanner = Scanner()
        self.scanner._analyzer = MagicMock()
        self.scanner._matcher = MagicMock()
        
        # Setup matcher to return exports
        self.scanner._matcher.get_openssl_exports.return_value = {
            'SSL_connect', 'EVP_sha256', 'RSA_sign'
        }
        self.scanner._matcher.filter_openssl_symbols.side_effect = lambda syms: [
            s for s in syms if s in {'SSL_connect', 'EVP_sha256', 'RSA_sign'}
        ]
        self.scanner._matcher.is_openssl_library.side_effect = lambda l: '.so' in l and ('crypto' in l or 'ssl' in l)

    def test_static_openssl_hybrid_case(self):
        """
        Test that a file with both OpenSSL imports (UND) and definitions (DEF)
        is flagged as static_openssl if it implements OpenSSL symbols.
        Regression test for Codex Finding 3.
        """
        # Mock ELFInfo
        info = MagicMock(spec=ELFInfo)
        info.elf_type = 'shared_library'
        info.arch = 'aarch64'
        info.needed_libs = ['libssl.so', 'libc.so']
        
        # UND symbols (Imports)
        info.undefined_symbols = [
            Symbol(name='SSL_connect', bind='GLOBAL', type_='FUNC', defined=False),
            Symbol(name='malloc', bind='GLOBAL', type_='FUNC', defined=False)
        ]
        
        # DEF symbols (Exports/Implementation)
        info.defined_symbols = [
            Symbol(name='EVP_sha256', bind='GLOBAL', type_='FUNC', defined=True),
            Symbol(name='my_func', bind='GLOBAL', type_='FUNC', defined=True)
        ]
        
        info.has_dlopen = False
        info.has_dlsym = False
        
        self.scanner._analyzer.analyze.return_value = info
        self.scanner._analyzer.is_elf_file.return_value = True
        
        # Mock os.path.isfile
        with pytest.MonkeyPatch.context() as m:
            m.setattr(os.path, 'isfile', lambda p: True)
            
            result = self.scanner.scan_file('/path/to/hybrid_lib.so')
            
            assert result.static_openssl is True
            assert 'EVP_sha256' in result.openssl_symbols
            assert 'SSL_connect' in result.openssl_symbols
            assert result.openssl_direct is True

    def test_static_openssl_pure_static_case(self):
        """Test pure static linking (no imports)."""
        info = MagicMock(spec=ELFInfo)
        info.elf_type = 'executable'
        info.arch = 'aarch64'
        info.needed_libs = ['libc.so']
        
        # UND symbols (No OpenSSL imports)
        info.undefined_symbols = [
            Symbol(name='malloc', bind='GLOBAL', type_='FUNC', defined=False)
        ]
        
        # DEF symbols (Exports)
        info.defined_symbols = [
            Symbol(name='RSA_sign', bind='GLOBAL', type_='FUNC', defined=True)
        ]
        
        info.has_dlopen = False
        info.has_dlsym = False
        
        self.scanner._analyzer.analyze.return_value = info
        
        with pytest.MonkeyPatch.context() as m:
            m.setattr(os.path, 'isfile', lambda p: True)
            
            result = self.scanner.scan_file('/path/to/static_app')
            
            assert result.static_openssl is True
            assert 'RSA_sign' in result.openssl_symbols
            assert 'malloc' not in result.openssl_symbols

    def test_dynamic_openssl_case(self):
        """Test standard dynamic linking (imports only)."""
        info = MagicMock(spec=ELFInfo)
        info.elf_type = 'executable'
        info.arch = 'aarch64'
        info.needed_libs = ['libssl.so', 'libcrypto.so']
        
        # UND symbols (Imports)
        info.undefined_symbols = [
            Symbol(name='SSL_connect', bind='GLOBAL', type_='FUNC', defined=False)
        ]
        
        # DEF symbols (No OpenSSL exports)
        info.defined_symbols = [
            Symbol(name='main', bind='GLOBAL', type_='FUNC', defined=True)
        ]
        
        info.has_dlopen = False
        info.has_dlsym = False
        
        self.scanner._analyzer.analyze.return_value = info
        
        with pytest.MonkeyPatch.context() as m:
            m.setattr(os.path, 'isfile', lambda p: True)
            
            result = self.scanner.scan_file('/path/to/dynamic_app')
            
            assert result.static_openssl is False
            assert 'SSL_connect' in result.openssl_symbols
