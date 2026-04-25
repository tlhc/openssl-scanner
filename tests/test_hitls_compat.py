"""Tests for HiTLS compatibility mapping loader and lookup."""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openssl_scanner.hitls_compat import HiTLSCompat

FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), 'fixtures', 'test_hitls_compat.json'
)
PRODUCTION_DATA_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'src',
    'openssl_scanner', 'data', 'hitls_compat.json'
)


def _load_expected_production_count():
    with open(PRODUCTION_DATA_PATH, encoding='utf-8') as f:
        return json.load(f)['total_mapped']


EXPECTED_PRODUCTION_COUNT = _load_expected_production_count()


class TestHiTLSCompat:

    def setup_method(self):
        self.compat = HiTLSCompat()

    def test_load_custom_path(self):
        count = self.compat.load(FIXTURE_PATH)
        assert count == 10
        assert self.compat.is_loaded()

    def test_load_missing_file(self):
        with pytest.raises(FileNotFoundError):
            self.compat.load('/nonexistent/path/hitls_compat.json')

    def test_load_invalid_json_structure(self):
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump({"version": "1.0"}, f)
            f.flush()
            try:
                with pytest.raises(ValueError, match="mapping"):
                    self.compat.load(f.name)
            finally:
                os.unlink(f.name)

    def test_lookup_available(self):
        self.compat.load(FIXTURE_PATH)
        status, hitls = self.compat.lookup('SSL_CTX_new')
        assert status == 'available'
        assert hitls == 'HITLS_CFG_NewTLSConfig'

    def test_lookup_partial(self):
        self.compat.load(FIXTURE_PATH)
        status, hitls = self.compat.lookup('SSL_read')
        assert status == 'partial'
        assert hitls == 'HITLS_Read'

    def test_lookup_not_available(self):
        self.compat.load(FIXTURE_PATH)
        status, hitls = self.compat.lookup('ENGINE_load_builtin_engines')
        assert status == 'not_available'
        assert hitls is None

    def test_lookup_unknown_symbol(self):
        self.compat.load(FIXTURE_PATH)
        status, hitls = self.compat.lookup('NONEXISTENT_func')
        assert status == 'unknown'
        assert hitls is None

    def test_lookup_not_loaded(self):
        status, hitls = self.compat.lookup('SSL_CTX_new')
        assert status == 'unknown'
        assert hitls is None

    def test_coverage_stats(self):
        self.compat.load(FIXTURE_PATH)
        symbols = {
            'SSL_CTX_new', 'SSL_connect', 'SSL_read', 'SSL_write',
            'EVP_DigestInit_ex', 'EVP_sha256',
            'ENGINE_load_builtin_engines', 'ENGINE_init',
            'RSA_public_encrypt', 'BN_new',
            'UNKNOWN_symbol',
        }
        stats = self.compat.get_coverage_stats(symbols)
        assert stats['available'] == 4
        assert stats['partial'] == 3
        assert stats['not_available'] == 3
        assert stats['unknown'] == 1

    def test_coverage_stats_not_loaded(self):
        stats = self.compat.get_coverage_stats({'SSL_CTX_new', 'EVP_sha256'})
        assert stats['unknown'] == 2
        assert stats['available'] == 0

    def test_coverage_summary_includes_counts_and_ratios(self):
        self.compat.load(FIXTURE_PATH)
        summary = self.compat.get_coverage_summary({
            'SSL_CTX_new', 'SSL_read', 'EVP_sha256',
            'ENGINE_init', 'UNKNOWN_symbol',
        })
        assert summary['total_symbols'] == 5
        assert summary['available'] == 1
        assert summary['partial'] == 2
        assert summary['not_available'] == 1
        assert summary['unknown'] == 1
        assert summary['direct_replace_ratio'] == 20.0
        assert summary['direct_or_partial_replace_ratio'] == 60.0

    def test_get_all_mappings(self):
        self.compat.load(FIXTURE_PATH)
        mappings = self.compat.get_all_mappings()
        assert len(mappings) == 10
        assert 'SSL_CTX_new' in mappings
        assert mappings['SSL_CTX_new']['status'] == 'available'

    def test_get_all_mappings_returns_copy(self):
        self.compat.load(FIXTURE_PATH)
        mappings = self.compat.get_all_mappings()
        mappings['INJECTED'] = {'status': 'available'}
        assert 'INJECTED' not in self.compat.get_all_mappings()

    def test_empty_mapping(self):
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump({"version": "1.0", "mapping": {}}, f)
            f.flush()
            try:
                count = self.compat.load(f.name)
                assert count == 0
                assert self.compat.is_loaded()
                status, hitls = self.compat.lookup('SSL_CTX_new')
                assert status == 'unknown'
                assert hitls is None
            finally:
                os.unlink(f.name)

    def test_load_builtin(self):
        """GAP-6: Verify built-in data/hitls_compat.json loads correctly."""
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.is_loaded()
        status, hitls = self.compat.lookup('SSL_CTX_new')
        assert status == 'partial'

    def test_batch_001_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'SSL_CTX_new': (
                'partial',
                'HITLS_CFG_NewTLSConfig / HITLS_CFG_NewTLS12Config / HITLS_CFG_NewTLS13Config + HITLS_New',
            ),
            'SSL_read': ('partial', 'HITLS_Read'),
            'SSL_write': ('partial', 'HITLS_Write'),
            'BIO_free': ('partial', 'BSL_UIO_Free(uio)'),
            'BIO_new_file': ('partial', 'BSL_UIO_New(BSL_UIO_FileMethod())'),
            'EVP_EncodeBlock': (
                'partial',
                'BSL_BASE64_Encode(ctx, in, inLen, out, outLen)',
            ),
            'EVP_DigestInit_ex': (
                'partial',
                'CRYPT_EAL_MdNewCtx(CRYPT_MD_*) + CRYPT_EAL_MdInit',
            ),
            'EVP_DigestUpdate': ('partial', 'CRYPT_EAL_MdUpdate'),
            'EVP_DigestFinal_ex': ('partial', 'CRYPT_EAL_MdFinal'),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_001.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_002_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'X509_new': ('available', 'HITLS_X509_CertNew()'),
            'X509_free': ('available', 'HITLS_X509_CertFree(cert)'),
            'X509_dup': ('available', 'HITLS_X509_CertDup(cert)'),
            'PEM_read_bio_X509': (
                'partial',
                'HITLS_X509_CertParseBuff(BSL_FORMAT_PEM, &encode, &cert)',
            ),
            'X509_REQ_new': ('available', 'HITLS_X509_CsrNew()'),
            'X509_REQ_free': ('available', 'HITLS_X509_CsrFree(csr)'),
            'X509_get_subject_name': (
                'partial',
                'HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SUBJECT_DN, ...)',
            ),
            'X509_get_issuer_name': (
                'partial',
                'HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN, ...)',
            ),
            'X509_get_ext_d2i': ('not_available', None),
            'X509_verify_cert': (
                'partial',
                'HITLS_X509_CertVerify(storeCtx, chain)',
            ),
            'X509_STORE_add_cert': (
                'partial',
                'HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SHALLOW_COPY_SET_CA, cert, ...)',
            ),
            'X509_STORE_free': (
                'partial',
                'HITLS_X509_StoreCtxFree(storeCtx)',
            ),
            'X509_STORE_CTX_get_error': (
                'partial',
                'HITLS_X509_StoreCtxCtrl(STORECTX_GET_ERROR)',
            ),
            'OCSP_BASICRESP_free': ('not_available', None),
            'OCSP_RESPONSE_free': ('not_available', None),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_002.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_003_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'EVP_PKEY_new': ('partial', 'CRYPT_EAL_PkeyNewCtx'),
            'EVP_PKEY_free': ('partial', 'CRYPT_EAL_PkeyFreeCtx'),
            'EVP_PKEY_CTX_new': ('partial', 'CRYPT_EAL_PkeyNewCtx'),
            'EVP_PKEY_CTX_free': ('partial', 'CRYPT_EAL_PkeyFreeCtx'),
            'EVP_PKEY_CTX_new_id': ('partial', 'CRYPT_EAL_PkeyNewCtx'),
            'EVP_PKEY_derive_init': (
                'partial',
                'CRYPT_EAL_PkeyNewCtx + CRYPT_EAL_PkeySetParaById',
            ),
            'EVP_PKEY_derive': ('partial', 'CRYPT_EAL_PkeyComputeShareKey'),
            'EVP_PKEY_CTX_set_hkdf_md': (
                'partial',
                'CRYPT_EAL_KdfSetParam(CRYPT_PARAM_KDF_MAC_ID)',
            ),
            'EVP_PKEY_CTX_set1_hkdf_key': (
                'partial',
                'CRYPT_EAL_KdfSetParam(CRYPT_PARAM_KDF_KEY)',
            ),
            'EVP_PKEY_CTX_set1_hkdf_salt': (
                'partial',
                'CRYPT_EAL_KdfSetParam(CRYPT_PARAM_KDF_SALT)',
            ),
            'EVP_PKEY_CTX_add1_hkdf_info': (
                'partial',
                'CRYPT_EAL_KdfSetParam(CRYPT_PARAM_KDF_INFO)',
            ),
            'EVP_PKEY_CTX_hkdf_mode': (
                'partial',
                'CRYPT_EAL_KdfSetParam(CRYPT_PARAM_KDF_MODE)',
            ),
            'RSA_new': ('partial', 'CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA)'),
            'RSA_free': ('partial', 'CRYPT_EAL_PkeyFreeCtx'),
            'DH_free': ('partial', 'CRYPT_EAL_PkeyFreeCtx'),
            'EC_KEY_free': ('partial', 'CRYPT_EAL_PkeyFreeCtx'),
            'EC_KEY_get0_group': (
                'partial',
                'CRYPT_EAL_PkeyGetParaId',
            ),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_003.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_004_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ERR_get_error') == (
            'available', 'BSL_ERR_GetError()')
        assert self.compat.lookup('ERR_peek_error') == (
            'available', 'BSL_ERR_PeekError()')
        assert self.compat.lookup('ERR_peek_last_error') == (
            'available', 'BSL_ERR_PeekLastError()')
        assert self.compat.lookup('ERR_GET_REASON') == (
            'partial', 'BSL_ERR_GetLastError() & 0xffff')
        assert self.compat.lookup('ERR_GET_LIB') == (
            'partial', 'BSL_ERR_GET_LIB(errCode)')
        assert self.compat.lookup('OPENSSL_free') == (
            'available', 'BSL_SAL_Free(addr)')
        assert self.compat.lookup('OBJ_obj2txt') == (
            'partial',
            'BSL_OBJ_GetOID(...) + BSL_OBJ_GetOidNumericString(...)'
        )

    def test_batch_005_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_new') == ('not_available', None)
        assert self.compat.lookup('BN_bin2bn') == ('not_available', None)
        assert self.compat.lookup('BN_num_bytes') == ('not_available', None)
        assert self.compat.lookup('BN_CTX_new') == ('not_available', None)

    def test_batch_006_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BIO_pending') == (
            'partial',
            'BSL_UIO_Ctrl(uio, BSL_UIO_PENDING, sizeof(int64_t), &pending)'
        )
        assert self.compat.lookup('BIO_get_mem_data') == (
            'not_available', None)
        assert self.compat.lookup('BIO_reset') == (
            'partial', 'BSL_UIO_Ctrl(uio, BSL_UIO_RESET, 0, NULL)')
        assert self.compat.lookup('BIO_free_all') == (
            'available', 'BSL_UIO_FreeChain')

    def test_batch_007_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_new') == (
            'available', 'HITLS_New')
        assert self.compat.lookup('SSL_free') == (
            'available', 'HITLS_Free')
        assert self.compat.lookup('SSL_CTX_free') == (
            'available', 'HITLS_CFG_FreeConfig')
        assert self.compat.lookup('SSL_CTX_get_cert_store') == (
            'available', 'HITLS_CFG_GetCertStore')
        assert self.compat.lookup('SSL_CTX_set_cert_cb') == (
            'available', 'HITLS_CFG_SetCertCb')
        assert self.compat.lookup('SSL_CTX_sess_set_new_cb') == (
            'available', 'HITLS_CFG_SetNewSessionCb')
        assert self.compat.lookup('SSL_get_SSL_CTX') == (
            'available', 'HITLS_GetGlobalConfig')
        assert self.compat.lookup('SSL_get_current_cipher') == (
            'available', 'HITLS_GetCurrentCipher')
        assert self.compat.lookup('SSL_CTX_get_ex_data') == (
            'partial', 'HITLS_CFG_GetConfigUserData')

    def test_batch_008_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('EVP_CIPHER_CTX_new') == (
            'partial', 'CRYPT_EAL_CipherNewCtx')
        assert self.compat.lookup('EVP_CIPHER_CTX_free') == (
            'available', 'CRYPT_EAL_CipherFreeCtx')
        assert self.compat.lookup('EVP_CIPHER_CTX_set_padding') == (
            'available', 'CRYPT_EAL_CipherSetPadding')
        assert self.compat.lookup('EVP_MD_CTX_new') == (
            'partial', 'CRYPT_EAL_MdNewCtx')
        assert self.compat.lookup('EVP_MD_CTX_free') == (
            'available', 'CRYPT_EAL_MdFreeCtx')
        assert self.compat.lookup('EVP_sha256') == (
            'partial', 'CRYPT_MD_SHA256')

    def test_batch_009_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('sk_X509_num') == (
            'available', 'BSL_LIST_COUNT')
        assert self.compat.lookup('sk_X509_value') == (
            'partial', 'BSL_LIST_GetIndexNode')
        assert self.compat.lookup('sk_X509_pop_free') == (
            'available', 'BSL_LIST_FREE(list, freefunc)')
        assert self.compat.lookup('sk_X509_push') == (
            'partial', 'BSL_LIST_AddElement(list, ptr, BSL_LIST_POS_END)')
        assert self.compat.lookup('ASN1_SIMPLE') == (
            'not_available', None)

    def test_batch_010_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_CTX_set_alpn_protos') == (
            'available', 'HITLS_CFG_SetAlpnProtos')
        assert self.compat.lookup('SSL_CTX_set_alpn_select_cb') == (
            'available', 'HITLS_CFG_SetAlpnProtosSelectCb')
        assert self.compat.lookup('SSL_CTX_set_cert_verify_callback') == (
            'available', 'HITLS_CFG_SetCertVerifyCb')
        assert self.compat.lookup('SSL_CTX_set_default_read_buffer_len') == (
            'available', 'HITLS_CFG_SetRecInbufferSize')
        assert self.compat.lookup('SSL_CTX_set_num_tickets') == (
            'available', 'HITLS_CFG_SetTicketNums')
        assert self.compat.lookup('SSL_CTX_set_verify_depth') == (
            'available', 'HITLS_CFG_SetVerifyDepth')
        assert self.compat.lookup('SSL_CTX_set_cipher_list') == (
            'partial', 'HITLS_CFG_SetCipherSuites')

    def test_batch_011_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_set_verify_depth') == (
            'available', 'HITLS_SetVerifyDepth')
        assert self.compat.lookup('SSL_get_verify_depth') == (
            'available', 'HITLS_GetVerifyDepth')
        assert self.compat.lookup('SSL_get1_session') == (
            'available', 'HITLS_GetDupSession')
        assert self.compat.lookup('SSL_get_session') == (
            'available', 'HITLS_GetSession')
        assert self.compat.lookup('SSL_set_verify') == (
            'partial',
            'HITLS_SetClientVerifySupport / HITLS_SetVerifyNoneSupport / HITLS_SetNoClientCertSupport / HITLS_SetVerifyCb'
        )

    def test_batch_012_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_state_string') == (
            'available', 'HITLS_GetStateString')
        assert self.compat.lookup('SSL_get_num_tickets') == (
            'available', 'HITLS_GetTicketNums')
        assert self.compat.lookup('SSL_version') == (
            'partial', 'HITLS_GetNegotiatedVersion')
        assert self.compat.lookup('SSL_get_state') == (
            'partial', 'HITLS_GetHandShakeState')
        assert self.compat.lookup('SSL_has_pending') == (
            'partial', 'HITLS_ReadHasPending')

    def test_batch_013_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_get_servername') == (
            'available', 'HITLS_GetServerName')
        assert self.compat.lookup('SSL_get_servername_type') == (
            'available', 'HITLS_GetServernameType')
        assert self.compat.lookup('SSL_get_security_callback') == (
            'available', 'HITLS_GetSecurityCb')
        assert self.compat.lookup('SSL_set_security_callback') == (
            'available', 'HITLS_SetSecurityCb')
        assert self.compat.lookup('SSL_set_security_level') == (
            'available', 'HITLS_SetSecurityLevel')
        assert self.compat.lookup('SSL_get_info_callback') == (
            'available', 'HITLS_GetInfoCb')
        assert self.compat.lookup('SSL_CTX_set_info_callback') == (
            'available', 'HITLS_CFG_SetInfoCb')
        assert self.compat.lookup('SSL_get_client_random') == (
            'partial', 'HITLS_GetHsRandom(ctx, out, outlen, true)')

    def test_batch_014_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_set_quiet_shutdown') == (
            'available', 'HITLS_SetQuietShutdown')
        assert self.compat.lookup('SSL_set_shutdown') == (
            'available', 'HITLS_SetShutdownState')
        assert self.compat.lookup('SSL_set_num_tickets') == (
            'available', 'HITLS_SetTicketNums')
        assert self.compat.lookup('SSL_get_rbio') == (
            'partial', 'HITLS_GetUio')
        assert self.compat.lookup('SSL_set_wfd') == (
            'not_available', None)

    def test_batch_015_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_set_psk_client_callback') == (
            'available', 'HITLS_SetPskClientCallback')
        assert self.compat.lookup('SSL_set_psk_server_callback') == (
            'available', 'HITLS_SetPskServerCallback')
        assert self.compat.lookup('SSL_set_psk_use_session_callback') == (
            'available', 'HITLS_SetPskUseSessionCallback')
        assert self.compat.lookup('SSL_set_psk_find_session_callback') == (
            'available', 'HITLS_SetPskFindSessionCallback')
        assert self.compat.lookup('SSL_use_psk_identity_hint') == (
            'available', 'HITLS_SetPskIdentityHint')
        assert self.compat.lookup('SSL_set_session_ticket_ext') == (
            'available', 'HITLS_SetSessionTicketExtData')
        assert self.compat.lookup('SSL_set_session_ticket_ext_cb') == (
            'available', 'HITLS_SetSessionTicketExtProcessCb')
        assert self.compat.lookup('SSL_get_psk_identity') == (
            'not_available', None)

    def test_batch_016_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_use_certificate') == (
            'available', 'HITLS_SetCertificate')
        assert self.compat.lookup('SSL_use_certificate_ASN1') == (
            'available', 'HITLS_LoadCertBuffer')
        assert self.compat.lookup('SSL_use_certificate_file') == (
            'available', 'HITLS_LoadCertFile')
        assert self.compat.lookup('SSL_use_certificate_chain_file') == (
            'available', 'HITLS_UseCertificateChainFile')
        assert self.compat.lookup('SSL_use_PrivateKey') == (
            'available', 'HITLS_SetPrivateKey')
        assert self.compat.lookup('SSL_use_PrivateKey_ASN1') == (
            'available', 'HITLS_LoadKeyBuffer')
        assert self.compat.lookup('SSL_use_PrivateKey_file') == (
            'available', 'HITLS_LoadKeyFile')
        assert self.compat.lookup('SSL_CTX_use_certificate') == (
            'available', 'HITLS_CFG_SetCertificate')
        assert self.compat.lookup('SSL_CTX_use_certificate_file') == (
            'available', 'HITLS_CFG_LoadCertFile')
        assert self.compat.lookup('SSL_CTX_use_certificate_chain_file') == (
            'available', 'HITLS_CFG_UseCertificateChainFile')

    def test_batch_017_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_get_certificate') == (
            'available', 'HITLS_GetCertificate')
        assert self.compat.lookup('SSL_get_privatekey') == (
            'available', 'HITLS_GetPrivateKey')
        assert self.compat.lookup('SSL_check_private_key') == (
            'available', 'HITLS_CheckPrivateKey')
        assert self.compat.lookup('SSL_CTX_check_private_key') == (
            'available', 'HITLS_CFG_CheckPrivateKey')
        assert self.compat.lookup('SSL_CTX_get0_certificate') == (
            'available', 'HITLS_CFG_GetCertificate')
        assert self.compat.lookup('SSL_CTX_get0_privatekey') == (
            'available', 'HITLS_CFG_GetPrivateKey')
        assert self.compat.lookup('SSL_get1_peer_certificate') == (
            'available', 'HITLS_GetPeerCertificate')
        assert self.compat.lookup('SSL_get0_peer_certificate') == (
            'partial', 'HITLS_GetPeerCertificate')

    def test_batch_018_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_pending') == (
            'available', 'HITLS_GetReadPendingBytes')
        assert self.compat.lookup('SSL_connect') == (
            'partial', 'HITLS_Connect')
        assert self.compat.lookup('SSL_accept') == (
            'partial', 'HITLS_Accept')
        assert self.compat.lookup('SSL_do_handshake') == (
            'partial', 'HITLS_DoHandShake')
        assert self.compat.lookup('SSL_read_ex') == (
            'partial', 'HITLS_Read')
        assert self.compat.lookup('SSL_write_ex') == (
            'partial', 'HITLS_Write')

    def test_batch_019_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_CTX_get0_CA_list') == (
            'partial', 'HITLS_CFG_GetCAList')
        assert self.compat.lookup('SSL_CTX_get_client_CA_list') == (
            'partial', 'HITLS_CFG_GetCAList')
        assert self.compat.lookup('SSL_CTX_set0_CA_list') == (
            'partial', 'HITLS_CFG_SetCAList')
        assert self.compat.lookup('SSL_CTX_set_client_CA_list') == (
            'partial', 'HITLS_CFG_SetCAList')
        assert self.compat.lookup('SSL_get0_peer_CA_list') == (
            'partial', 'HITLS_GetPeerCAList')
        assert self.compat.lookup('SSL_get_peer_cert_chain') == (
            'partial', 'HITLS_GetPeerCertChain')
        assert self.compat.lookup('SSL_get0_verified_chain') == (
            'not_available', None)

    def test_batch_020_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_get_verify_callback') == (
            'available', 'HITLS_GetVerifyCb')
        assert self.compat.lookup('SSL_CTX_get_verify_callback') == (
            'available', 'HITLS_CFG_GetVerifyCb')
        assert self.compat.lookup('SSL_CTX_sess_set_get_cb') == (
            'available', 'HITLS_CFG_SetSessionGetCb')
        assert self.compat.lookup('SSL_CTX_sess_set_remove_cb') == (
            'available', 'HITLS_CFG_SetSessionRemoveCb')
        assert self.compat.lookup('SSL_CTX_get_client_cert_cb') == (
            'not_available', None)
        assert self.compat.lookup('SSL_CTX_sess_get_new_cb') == (
            'not_available', None)

    def test_batch_021_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_CTX_get_info_callback') == (
            'available', 'HITLS_CFG_GetInfoCb')
        assert self.compat.lookup('SSL_CTX_get_num_tickets') == (
            'available', 'HITLS_CFG_GetTicketNums')
        assert self.compat.lookup('SSL_CTX_get_security_callback') == (
            'available', 'HITLS_CFG_GetSecurityCb')
        assert self.compat.lookup('SSL_CTX_get_verify_mode') == (
            'partial', 'HITLS_CFG_GetClientVerifySupport / HITLS_CFG_GetVerifyNoneSupport')

    def test_batch_022_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_SESSION_free') == (
            'available', 'HITLS_SESS_Free')
        assert self.compat.lookup('SSL_SESSION_get_timeout') == (
            'available', 'HITLS_SESS_GetTimeout')
        assert self.compat.lookup('SSL_SESSION_set_protocol_version') == (
            'available', 'HITLS_SESS_SetProtocolVersion')
        assert self.compat.lookup('SSL_SESSION_dup') == (
            'partial', 'HITLS_SESS_Dup')
        assert self.compat.lookup('SSL_SESSION_get0_id_context') == (
            'partial', 'HITLS_SESS_GetSessionIdCtx')

    def test_batch_023_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_SESSION_new') == (
            'available', 'HITLS_SESS_New')
        assert self.compat.lookup('SSL_SESSION_has_ticket') == (
            'available', 'HITLS_SESS_HasTicket')
        assert self.compat.lookup('SSL_SESSION_is_resumable') == (
            'available', 'HITLS_SESS_IsResumable')
        assert self.compat.lookup('SSL_SESSION_set1_master_key') == (
            'available', 'HITLS_SESS_SetMasterKey')
        assert self.compat.lookup('SSL_SESSION_get0_cipher') == (
            'partial', 'HITLS_SESS_GetCipherSuite')
        assert self.compat.lookup('SSL_SESSION_get_ex_data') == (
            'partial', 'HITLS_SESS_GetUserData')

    def test_batch_024_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_SESSION_get0_alpn_selected') == (
            'not_available', None)
        assert self.compat.lookup('SSL_SESSION_set1_alpn_selected') == (
            'not_available', None)
        assert self.compat.lookup('SSL_SESSION_get0_ticket') == (
            'not_available', None)
        assert self.compat.lookup('SSL_SESSION_get_ticket_lifetime_hint') == (
            'not_available', None)
        assert self.compat.lookup('SSL_SESSION_get_time') == (
            'not_available', None)
        assert self.compat.lookup('SSL_SESSION_set_time') == (
            'not_available', None)
        assert self.compat.lookup('SSL_SESSION_get0_peer') == (
            'not_available', None)
        assert self.compat.lookup('SSL_SESSION_get0_hostname') == (
            'not_available', None)
        assert self.compat.lookup('SSL_SESSION_set1_hostname') == (
            'not_available', None)

    def test_batch_025_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('EVP_EncryptUpdate') == (
            'partial', 'CRYPT_EAL_CipherUpdate')
        assert self.compat.lookup('EVP_EncryptFinal_ex') == (
            'partial', 'CRYPT_EAL_CipherFinal')
        assert self.compat.lookup('EVP_DecryptUpdate') == (
            'partial', 'CRYPT_EAL_CipherUpdate')
        assert self.compat.lookup('EVP_DecryptFinal_ex') == (
            'partial', 'CRYPT_EAL_CipherFinal')
        assert self.compat.lookup('EVP_aes_128_gcm') == (
            'partial', 'CRYPT_CIPHER_AES128_GCM')
        assert self.compat.lookup('EVP_aes_256_gcm') == (
            'partial', 'CRYPT_CIPHER_AES256_GCM')
        assert self.compat.lookup('EVP_aes_128_cbc') == (
            'partial', 'CRYPT_CIPHER_AES128_CBC')
        assert self.compat.lookup('EVP_aes_128_ctr') == (
            'partial', 'CRYPT_CIPHER_AES128_CTR')
        assert self.compat.lookup('EVP_aes_256_cbc') == (
            'partial', 'CRYPT_CIPHER_AES256_CBC')

    def test_batch_026_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('RAND_bytes') == (
            'partial', 'CRYPT_EAL_Randbytes')
        assert self.compat.lookup('RAND_bytes_ex') == (
            'partial', 'CRYPT_EAL_RandbytesEx')
        assert self.compat.lookup('RAND_priv_bytes') == (
            'partial', 'CRYPT_EAL_Randbytes')
        assert self.compat.lookup('RAND_priv_bytes_ex') == (
            'partial', 'CRYPT_EAL_RandbytesEx')
        assert self.compat.lookup('RAND_seed') == (
            'partial', 'CRYPT_EAL_RandSeedWithAdin')
        assert self.compat.lookup('RAND_add') == (
            'partial', 'CRYPT_EAL_RandSeedWithAdin')
        assert self.compat.lookup('RAND_poll') == (
            'partial', 'CRYPT_EAL_RandSeed')
        assert self.compat.lookup('RAND_status') == (
            'partial',
            'CRYPT_EAL_GetSeedCtx(true/false) + CRYPT_EAL_DrbgCtrl(..., CRYPT_CTRL_GET_WORKING_STATUS, ...)')

    def test_batch_027_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('HMAC_CTX_new') == (
            'partial', 'CRYPT_EAL_MacNewCtx')
        assert self.compat.lookup('HMAC_CTX_free') == (
            'available', 'CRYPT_EAL_MacFreeCtx')
        assert self.compat.lookup('HMAC_Init_ex') == (
            'partial', 'CRYPT_EAL_MacInit')
        assert self.compat.lookup('HMAC_Update') == (
            'partial', 'CRYPT_EAL_MacUpdate')
        assert self.compat.lookup('HMAC_Final') == (
            'partial', 'CRYPT_EAL_MacFinal')
        assert self.compat.lookup('HMAC') == (
            'partial',
            'CRYPT_EAL_MacNewCtx / CRYPT_EAL_MacInit / CRYPT_EAL_MacUpdate / CRYPT_EAL_MacFinal')

    def test_batch_028_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('PEM_read_bio_PrivateKey') == (
            'partial', 'CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM)')
        assert self.compat.lookup('X509_get_pubkey') == (
            'partial', 'HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, ...)')
        assert self.compat.lookup('X509_get_serialNumber') == (
            'partial', 'HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM, ...)')
        assert self.compat.lookup('d2i_X509') == (
            'partial', 'HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &encode, &cert)')
        assert self.compat.lookup('d2i_X509_bio') == (
            'partial', 'HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1)')
        assert self.compat.lookup('i2d_X509') == (
            'partial', 'HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &buf)')
        assert self.compat.lookup('PEM_write_bio_X509') == (
            'partial', 'HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, cert, &buf)')

    def test_batch_029_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SHA256') == (
            'available', 'CRYPT_EAL_Md(CRYPT_MD_SHA256, ...)')
        assert self.compat.lookup('EVP_sha1') == (
            'partial', 'CRYPT_MD_SHA1')
        assert self.compat.lookup('EVP_md5') == (
            'partial', 'CRYPT_MD_MD5')
        assert self.compat.lookup('EVP_Digest') == (
            'partial', 'CRYPT_EAL_Md')
        assert self.compat.lookup('EVP_DigestInit') == (
            'partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_*) + CRYPT_EAL_MdInit')
        assert self.compat.lookup('EVP_DigestFinal') == (
            'partial', 'CRYPT_EAL_MdFinal')

    def test_batch_030_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('EVP_PKEY_set1_RSA') == (
            'partial', 'CRYPT_EAL_PkeySetPub / CRYPT_EAL_PkeySetPrv')
        assert self.compat.lookup('RSA_set0_key') == (
            'partial', 'CRYPT_EAL_PkeySetPrv / CRYPT_EAL_PkeySetPub')
        assert self.compat.lookup('EVP_PKEY_CTX_set_rsa_padding') == (
            'partial', 'CRYPT_EAL_PkeyCtrl')
        assert self.compat.lookup('RSA_generate_key_ex') == (
            'partial', 'CRYPT_EAL_PkeyGen')
        assert self.compat.lookup('RSA_size') == (
            'partial', 'CRYPT_EAL_PkeyGetKeyLen')

    def test_batch_031_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_set_bio') == (
            'partial', 'HITLS_SetUio')
        assert self.compat.lookup('SSL_set_fd') == (
            'partial', 'BSL_UIO_New(BSL_UIO_TcpMethod()) + BSL_UIO_SetFD + HITLS_SetUio')
        assert self.compat.lookup('BIO_set_flags') == (
            'partial', 'BSL_UIO_SetFlags')
        assert self.compat.lookup('BIO_s_file') == (
            'partial', 'BSL_UIO_FileMethod()')

    def test_batch_032_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SSL_CTX_load_verify_locations') == (
            'partial', 'HITLS_CFG_LoadVerifyFile + HITLS_CFG_LoadVerifyDir')
        assert self.compat.lookup('SSL_CTX_use_PrivateKey_file') == (
            'partial', 'HITLS_CFG_LoadKeyFile')
        assert self.compat.lookup('SSL_CTX_use_PrivateKey') == (
            'partial', 'HITLS_CFG_SetPrivateKey')
        assert self.compat.lookup('TLS_server_method') == (
            'partial', 'HITLS_CFG_NewTLSConfig / HITLS_CFG_SetEndPoint')
        assert self.compat.lookup('SSL_set_connect_state') == (
            'partial', 'HITLS_SetEndPoint(ctx, true)')

    def test_batch_033_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('EVP_DigestSignInit') == (
            'partial', 'CRYPT_EAL_PkeySign')
        assert self.compat.lookup('EVP_DigestVerifyInit') == (
            'partial', 'CRYPT_EAL_PkeyVerify')
        assert self.compat.lookup('EVP_DigestSignFinal') == (
            'partial', 'CRYPT_EAL_PkeySign')
        assert self.compat.lookup('EVP_DigestVerifyFinal') == (
            'partial', 'CRYPT_EAL_PkeyVerify')
        assert self.compat.lookup('EVP_PKEY_verify') == (
            'partial', 'CRYPT_EAL_PkeyVerifyData')

    def test_batch_034_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('X509_verify_cert_error_string') == (
            'not_available', None)
        assert self.compat.lookup('X509_NAME_oneline') == (
            'partial', 'HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_DNNAME, ..., BSL_UIO*)')
        assert self.compat.lookup('X509_verify') == (
            'partial', 'HITLS_X509_CertDigest / CRYPT_EAL_PkeyVerify')
        assert self.compat.lookup('X509_EXTENSION_get_data') == (
            'partial', 'HITLS_X509_ExtCtrl(HITLS_X509_EXT_GET_GENERIC, ...)')
        assert self.compat.lookup('X509_NAME_ENTRY_get_data') == (
            'not_available', None)
        assert self.compat.lookup('X509_NAME_get_entry') == (
            'not_available', None)
        assert self.compat.lookup('X509_NAME_add_entry_by_txt') == (
            'partial', 'HITLS_X509_DnListNew / HITLS_X509_AddDnName')
        assert self.compat.lookup('X509_NAME_get_text_by_NID') == (
            'not_available', None)

    def test_batch_035_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('OBJ_obj2nid') == (
            'partial', 'BSL_OBJ_GetCID')
        assert self.compat.lookup('OBJ_nid2sn') == (
            'not_available', None)
        assert self.compat.lookup('OBJ_txt2obj') == (
            'partial', 'BSL_OBJ_GetOidFromNumericString')
        assert self.compat.lookup('EVP_get_digestbyname') == (
            'not_available', None)

    def test_batch_036_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('EC_KEY_new_by_curve_name') == (
            'partial', 'CRYPT_EAL_PkeyNewCtx / CRYPT_EAL_PkeySetParaById')
        assert self.compat.lookup('EC_GROUP_get_curve_name') == (
            'partial', 'CRYPT_EAL_PkeyCtrl(..., CRYPT_CTRL_GET_ECC_NAME, ...)')
        assert self.compat.lookup('EC_KEY_generate_key') == (
            'partial', 'CRYPT_EAL_PkeyGen')
        assert self.compat.lookup('EC_KEY_get0_private_key') == (
            'partial', 'CRYPT_EAL_PkeyGetPrv')
        assert self.compat.lookup('EC_KEY_get0_public_key') == (
            'partial', 'CRYPT_EAL_PkeyGetPub')
        assert self.compat.lookup('EC_GROUP_new_by_curve_name') == (
            'partial', 'CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA) + CRYPT_EAL_PkeySetParaById')
        assert self.compat.lookup('EC_KEY_new') == (
            'partial', 'CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA)')
        assert self.compat.lookup('EC_KEY_set_group') == (
            'partial', 'CRYPT_EAL_PkeySetParaById')

    def test_batch_037_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('X509_STORE_new') == (
            'partial', 'HITLS_X509_StoreCtxNew()')
        assert self.compat.lookup('X509_STORE_CTX_get_ex_data') == (
            'partial', 'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_GET_USR_DATA, ...)')
        assert self.compat.lookup('X509_get0_notAfter') == (
            'partial', 'HITLS_X509_CertCtrl(cert, HITLS_X509_GET_AFTER_TIME, ...)')
        assert self.compat.lookup('X509_get0_notBefore') == (
            'partial', 'HITLS_X509_CertCtrl(cert, HITLS_X509_GET_BEFORE_TIME, ...)')
        assert self.compat.lookup('X509_get0_pubkey') == (
            'partial', 'HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, ...)')
        assert self.compat.lookup('X509_up_ref') == (
            'partial', 'HITLS_X509_CertCtrl(HITLS_X509_REF_UP)')
        assert self.compat.lookup('X509_CRL_verify') == (
            'partial', 'HITLS_X509_CrlVerify(pubkey, crl)')
        assert self.compat.lookup('X509_NAME_new') == (
            'partial', 'HITLS_X509_DnListNew / HITLS_X509_AddDnName')

    def test_batch_038_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_OCTET_STRING_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_set') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_INTEGER_set') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_OBJECT_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_OCTET_STRING_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_OCTET_STRING_set') == (
            'not_available', None)

    def test_batch_039_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_bn2binpad') == (
            'not_available', None)
        assert self.compat.lookup('BN_cmp') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_exp') == (
            'not_available', None)
        assert self.compat.lookup('BN_num_bits') == (
            'not_available', None)

    def test_batch_040_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_CTX_end') == (
            'not_available', None)
        assert self.compat.lookup('BN_CTX_get') == (
            'not_available', None)
        assert self.compat.lookup('BN_CTX_new_ex') == (
            'not_available', None)
        assert self.compat.lookup('BN_CTX_secure_new') == (
            'not_available', None)
        assert self.compat.lookup('BN_CTX_secure_new_ex') == (
            'not_available', None)
        assert self.compat.lookup('BN_CTX_start') == (
            'not_available', None)

    def test_batch_041_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_GENCB_call') == (
            'not_available', None)
        assert self.compat.lookup('BN_GENCB_free') == (
            'not_available', None)
        assert self.compat.lookup('BN_GENCB_get_arg') == (
            'not_available', None)
        assert self.compat.lookup('BN_GENCB_new') == (
            'not_available', None)
        assert self.compat.lookup('BN_GENCB_set') == (
            'not_available', None)
        assert self.compat.lookup('BN_GENCB_set_old') == (
            'not_available', None)

    def test_batch_042_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_BLINDING_new') == (
            'not_available', None)
        assert self.compat.lookup('BN_BLINDING_free') == (
            'not_available', None)
        assert self.compat.lookup('BN_BLINDING_update') == (
            'not_available', None)
        assert self.compat.lookup('BN_BLINDING_convert') == (
            'partial', 'CRYPT_EAL_PkeyBlind')
        assert self.compat.lookup('BN_BLINDING_invert') == (
            'partial', 'CRYPT_EAL_PkeyUnBlind')
        assert self.compat.lookup('BN_BLINDING_set_flags') == (
            'not_available', None)

    def test_batch_043_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_BLINDING_convert_ex') == (
            'partial',
            'CRYPT_EAL_PkeyCtrl(..., CRYPT_CTRL_SET_RSA_BSSA_FACTOR_R, ...) + CRYPT_EAL_PkeyBlind')
        assert self.compat.lookup('BN_BLINDING_invert_ex') == (
            'partial',
            'CRYPT_EAL_PkeyCtrl(..., CRYPT_CTRL_SET_RSA_BSSA_FACTOR_R, ...) + CRYPT_EAL_PkeyUnBlind')
        assert self.compat.lookup('BN_BLINDING_create_param') == (
            'partial',
            'CRYPT_EAL_PkeyCtrl(..., CRYPT_CTRL_SET_RSA_BSSA_FACTOR_R, ...) / implicit creation in CRYPT_EAL_PkeyBlind')
        assert self.compat.lookup('BN_BLINDING_get_flags') == (
            'not_available', None)
        assert self.compat.lookup('BN_BLINDING_is_current_thread') == (
            'not_available', None)
        assert self.compat.lookup('BN_BLINDING_set_current_thread') == (
            'not_available', None)
        assert self.compat.lookup('BN_BLINDING_lock') == (
            'not_available', None)
        assert self.compat.lookup('BN_BLINDING_unlock') == (
            'not_available', None)

    def test_batch_044_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_copy') == (
            'not_available', None)
        assert self.compat.lookup('BN_dup') == (
            'not_available', None)
        assert self.compat.lookup('BN_get_word') == (
            'not_available', None)
        assert self.compat.lookup('BN_set_word') == (
            'not_available', None)
        assert self.compat.lookup('BN_swap') == (
            'not_available', None)
        assert self.compat.lookup('BN_with_flags') == (
            'not_available', None)

    def test_batch_045_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_get_flags') == (
            'not_available', None)
        assert self.compat.lookup('BN_set_flags') == (
            'not_available', None)
        assert self.compat.lookup('BN_is_negative') == (
            'not_available', None)
        assert self.compat.lookup('BN_set_negative') == (
            'not_available', None)
        assert self.compat.lookup('BN_is_zero') == (
            'not_available', None)
        assert self.compat.lookup('BN_is_one') == (
            'not_available', None)

    def test_batch_046_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_rand') == (
            'not_available', None)
        assert self.compat.lookup('BN_rand_ex') == (
            'not_available', None)
        assert self.compat.lookup('BN_priv_rand') == (
            'not_available', None)
        assert self.compat.lookup('BN_priv_rand_ex') == (
            'not_available', None)
        assert self.compat.lookup('BN_rand_range') == (
            'not_available', None)
        assert self.compat.lookup('BN_rand_range_ex') == (
            'not_available', None)

    def test_batch_047_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_bin2bn') == (
            'not_available', None)
        assert self.compat.lookup('BN_lebin2bn') == (
            'not_available', None)
        assert self.compat.lookup('BN_native2bn') == (
            'not_available', None)
        assert self.compat.lookup('BN_hex2bn') == (
            'not_available', None)
        assert self.compat.lookup('BN_dec2bn') == (
            'not_available', None)
        assert self.compat.lookup('BN_mpi2bn') == (
            'not_available', None)

    def test_batch_048_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_bn2hex') == (
            'not_available', None)
        assert self.compat.lookup('BN_bn2dec') == (
            'not_available', None)
        assert self.compat.lookup('BN_bn2mpi') == (
            'not_available', None)
        assert self.compat.lookup('BN_print') == (
            'not_available', None)
        assert self.compat.lookup('BN_print_fp') == (
            'not_available', None)
        assert self.compat.lookup('BN_bn2nativepad') == (
            'not_available', None)

    def test_batch_049_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_add') == (
            'not_available', None)
        assert self.compat.lookup('BN_sub') == (
            'not_available', None)
        assert self.compat.lookup('BN_add_word') == (
            'not_available', None)
        assert self.compat.lookup('BN_sub_word') == (
            'not_available', None)
        assert self.compat.lookup('BN_mul') == (
            'not_available', None)
        assert self.compat.lookup('BN_mul_word') == (
            'not_available', None)

    def test_batch_050_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_lshift') == (
            'not_available', None)
        assert self.compat.lookup('BN_lshift1') == (
            'not_available', None)
        assert self.compat.lookup('BN_rshift') == (
            'not_available', None)
        assert self.compat.lookup('BN_rshift1') == (
            'not_available', None)
        assert self.compat.lookup('BN_set_bit') == (
            'not_available', None)
        assert self.compat.lookup('BN_clear_bit') == (
            'not_available', None)

    def test_batch_051_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_MONT_CTX_new') == (
            'not_available', None)
        assert self.compat.lookup('BN_MONT_CTX_free') == (
            'not_available', None)
        assert self.compat.lookup('BN_MONT_CTX_set') == (
            'not_available', None)
        assert self.compat.lookup('BN_MONT_CTX_copy') == (
            'not_available', None)
        assert self.compat.lookup('BN_RECP_CTX_new') == (
            'not_available', None)
        assert self.compat.lookup('BN_RECP_CTX_free') == (
            'not_available', None)

    def test_batch_052_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_mod_mul_montgomery') == (
            'not_available', None)
        assert self.compat.lookup('BN_to_montgomery') == (
            'not_available', None)
        assert self.compat.lookup('BN_from_montgomery') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_exp_mont') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_exp_mont_consttime') == (
            'not_available', None)

    def test_batch_053_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_MONT_CTX_set_locked') == (
            'not_available', None)
        assert self.compat.lookup('BN_RECP_CTX_set') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_exp_recp') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_exp_mont_word') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_exp2_mont') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_exp_mont_consttime_x2') == (
            'not_available', None)

    def test_batch_054_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_div') == (
            'not_available', None)
        assert self.compat.lookup('BN_div_word') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_word') == (
            'not_available', None)
        assert self.compat.lookup('BN_nnmod') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_mul_reciprocal') == (
            'not_available', None)

    def test_batch_055_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_generate_prime') == (
            'not_available', None)
        assert self.compat.lookup('BN_generate_prime_ex') == (
            'not_available', None)
        assert self.compat.lookup('BN_generate_prime_ex2') == (
            'not_available', None)
        assert self.compat.lookup('BN_check_prime') == (
            'not_available', None)
        assert self.compat.lookup('BN_is_prime') == (
            'not_available', None)
        assert self.compat.lookup('BN_is_prime_ex') == (
            'not_available', None)

    def test_batch_056_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_GF2m_add') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_mul') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_sqr') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_inv') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_sqrt') == (
            'not_available', None)

    def test_batch_057_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_GF2m_mod_div') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_exp') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_solve_quad') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_arr') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_mul_arr') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_sqr_arr') == (
            'not_available', None)

    def test_batch_058_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_GF2m_mod_inv_arr') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_div_arr') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_exp_arr') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_sqrt_arr') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_mod_solve_quad_arr') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_poly2arr') == (
            'not_available', None)
        assert self.compat.lookup('BN_GF2m_arr2poly') == (
            'not_available', None)

    def test_batch_059_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_X931_generate_prime_ex') == (
            'not_available', None)
        assert self.compat.lookup('BN_X931_generate_Xpq') == (
            'not_available', None)
        assert self.compat.lookup('BN_X931_derive_prime_ex') == (
            'not_available', None)

    def test_batch_060_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_get_rfc2409_prime_768') == (
            'not_available', None)
        assert self.compat.lookup('BN_get_rfc2409_prime_1024') == (
            'not_available', None)
        assert self.compat.lookup('BN_get_rfc3526_prime_1536') == (
            'not_available', None)
        assert self.compat.lookup('BN_get_rfc3526_prime_2048') == (
            'not_available', None)
        assert self.compat.lookup('BN_get_rfc3526_prime_3072') == (
            'not_available', None)
        assert self.compat.lookup('BN_get_rfc3526_prime_4096') == (
            'not_available', None)

    def test_batch_061_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_get_rfc3526_prime_6144') == (
            'not_available', None)
        assert self.compat.lookup('BN_get_rfc3526_prime_8192') == (
            'not_available', None)
        assert self.compat.lookup('BN_get0_nist_prime_192') == (
            'not_available', None)
        assert self.compat.lookup('BN_get0_nist_prime_224') == (
            'not_available', None)
        assert self.compat.lookup('BN_get0_nist_prime_256') == (
            'not_available', None)
        assert self.compat.lookup('BN_get0_nist_prime_384') == (
            'not_available', None)

    def test_batch_062_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_get0_nist_prime_521') == (
            'not_available', None)
        assert self.compat.lookup('BN_value_one') == (
            'not_available', None)
        assert self.compat.lookup('BN_options') == (
            'not_available', None)
        assert self.compat.lookup('BN_security_bits') == (
            'not_available', None)
        assert self.compat.lookup('BN_are_coprime') == (
            'not_available', None)
        assert self.compat.lookup('BN_abs_is_word') == (
            'not_available', None)

    def test_batch_063_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_ucmp') == (
            'not_available', None)
        assert self.compat.lookup('BN_is_word') == (
            'not_available', None)
        assert self.compat.lookup('BN_is_odd') == (
            'not_available', None)
        assert self.compat.lookup('BN_is_bit_set') == (
            'not_available', None)
        assert self.compat.lookup('BN_consttime_swap') == (
            'not_available', None)

    def test_batch_064_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_mod_add') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_add_quick') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_sub') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_sub_quick') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_mul') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_sqr') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_inverse') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_lshift') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_lshift1') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_lshift1_quick') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_lshift_quick') == (
            'not_available', None)

    def test_batch_065_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_exp') == (
            'not_available', None)
        assert self.compat.lookup('BN_sqr') == (
            'not_available', None)
        assert self.compat.lookup('BN_gcd') == (
            'not_available', None)
        assert self.compat.lookup('BN_div_recp') == (
            'not_available', None)
        assert self.compat.lookup('BN_reciprocal') == (
            'not_available', None)
        assert self.compat.lookup('BN_kronecker') == (
            'not_available', None)
        assert self.compat.lookup('BN_uadd') == (
            'not_available', None)
        assert self.compat.lookup('BN_usub') == (
            'not_available', None)
        assert self.compat.lookup('BN_mask_bits') == (
            'not_available', None)
        assert self.compat.lookup('BN_zero_ex') == (
            'not_available', None)
        assert self.compat.lookup('BN_num_bits_word') == (
            'not_available', None)
        assert self.compat.lookup('BN_secure_new') == (
            'not_available', None)
        assert self.compat.lookup('BN_get_params') == (
            'not_available', None)
        assert self.compat.lookup('BN_set_params') == (
            'not_available', None)

    def test_batch_066_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_generate_dsa_nonce') == (
            'not_available', None)
        assert self.compat.lookup('BN_is_prime_fasttest') == (
            'not_available', None)
        assert self.compat.lookup('BN_is_prime_fasttest_ex') == (
            'not_available', None)
        assert self.compat.lookup('BN_priv_rand_range') == (
            'not_available', None)
        assert self.compat.lookup('BN_priv_rand_range_ex') == (
            'not_available', None)
        assert self.compat.lookup('BN_pseudo_rand') == (
            'not_available', None)
        assert self.compat.lookup('BN_pseudo_rand_range') == (
            'not_available', None)
        assert self.compat.lookup('BN_signed_bin2bn') == (
            'not_available', None)
        assert self.compat.lookup('BN_signed_bn2bin') == (
            'not_available', None)
        assert self.compat.lookup('BN_signed_bn2lebin') == (
            'not_available', None)
        assert self.compat.lookup('BN_signed_bn2native') == (
            'not_available', None)
        assert self.compat.lookup('BN_signed_lebin2bn') == (
            'not_available', None)
        assert self.compat.lookup('BN_signed_native2bn') == (
            'not_available', None)

    def test_batch_067_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BN_asc2bn') == (
            'not_available', None)
        assert self.compat.lookup('BN_bn2lebinpad') == (
            'not_available', None)
        assert self.compat.lookup('BN_bntest_rand') == (
            'not_available', None)
        assert self.compat.lookup('BN_clear') == (
            'not_available', None)
        assert self.compat.lookup('BN_mod_sqrt') == (
            'not_available', None)
        assert self.compat.lookup('BN_nist_mod_192') == (
            'not_available', None)
        assert self.compat.lookup('BN_nist_mod_224') == (
            'not_available', None)
        assert self.compat.lookup('BN_nist_mod_256') == (
            'not_available', None)
        assert self.compat.lookup('BN_nist_mod_384') == (
            'not_available', None)
        assert self.compat.lookup('BN_nist_mod_521') == (
            'not_available', None)
        assert self.compat.lookup('BN_nist_mod_func') == (
            'not_available', None)
        assert self.compat.lookup('BN_to_ASN1_ENUMERATED') == (
            'not_available', None)
        assert self.compat.lookup('BN_to_ASN1_INTEGER') == (
            'not_available', None)

    def test_batch_068_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('AES_set_encrypt_key') == (
            'partial',
            'CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES{128,192,256}_ECB) + CRYPT_EAL_CipherInit(enc=true)')
        assert self.compat.lookup('AES_set_decrypt_key') == (
            'partial',
            'CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES{128,192,256}_ECB) + CRYPT_EAL_CipherInit(enc=false)')
        assert self.compat.lookup('AES_encrypt') == (
            'partial',
            'CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES{128,192,256}_ECB) + CRYPT_EAL_CipherInit(enc=true) + CRYPT_EAL_CipherUpdate + CRYPT_EAL_CipherFinal')
        assert self.compat.lookup('AES_decrypt') == (
            'partial',
            'CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES{128,192,256}_ECB) + CRYPT_EAL_CipherInit(enc=false) + CRYPT_EAL_CipherUpdate + CRYPT_EAL_CipherFinal')
        assert self.compat.lookup('AES_ecb_encrypt') == (
            'partial',
            'CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES{128,192,256}_ECB) + CRYPT_EAL_CipherInit + CRYPT_EAL_CipherUpdate + CRYPT_EAL_CipherFinal')
        assert self.compat.lookup('AES_cbc_encrypt') == (
            'partial',
            'CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES{128,192,256}_CBC) + CRYPT_EAL_CipherInit + CRYPT_EAL_CipherUpdate + CRYPT_EAL_CipherFinal')

    def test_batch_069_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('DES_cbc_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_ecb_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_cfb64_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_ofb_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_set_key_unchecked') == (
            'not_available', None)
        assert self.compat.lookup('DES_set_odd_parity') == (
            'not_available', None)

    def test_batch_070_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('AES_cfb128_encrypt') == (
            'partial',
            'CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES{128,192,256}_CFB) + CRYPT_EAL_CipherInit + CRYPT_EAL_CipherCtrl(CRYPT_CTRL_SET_FEEDBACKSIZE=128) + CRYPT_EAL_CipherUpdate + CRYPT_EAL_CipherFinal')
        assert self.compat.lookup('AES_cfb1_encrypt') == (
            'partial',
            'CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES{128,192,256}_CFB) + CRYPT_EAL_CipherInit + CRYPT_EAL_CipherCtrl(CRYPT_CTRL_SET_FEEDBACKSIZE=1) + CRYPT_EAL_CipherUpdate + CRYPT_EAL_CipherFinal')
        assert self.compat.lookup('AES_cfb8_encrypt') == (
            'partial',
            'CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES{128,192,256}_CFB) + CRYPT_EAL_CipherInit + CRYPT_EAL_CipherCtrl(CRYPT_CTRL_SET_FEEDBACKSIZE=8) + CRYPT_EAL_CipherUpdate + CRYPT_EAL_CipherFinal')
        assert self.compat.lookup('AES_ofb128_encrypt') == (
            'partial',
            'CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES{128,192,256}_OFB) + CRYPT_EAL_CipherInit + CRYPT_EAL_CipherUpdate + CRYPT_EAL_CipherFinal')
        assert self.compat.lookup('AES_wrap_key') == (
            'partial',
            'CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES{128,192,256}_WRAP_NOPAD) + CRYPT_EAL_CipherInit(enc=true) + CRYPT_EAL_CipherUpdate + CRYPT_EAL_CipherFinal')
        assert self.compat.lookup('AES_unwrap_key') == (
            'partial',
            'CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES{128,192,256}_WRAP_NOPAD) + CRYPT_EAL_CipherInit(enc=false) + CRYPT_EAL_CipherUpdate + CRYPT_EAL_CipherFinal')
        assert self.compat.lookup('AES_ige_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('AES_bi_ige_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('AES_options') == (
            'not_available', None)

    def test_batch_071_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('DES_cbc_cksum') == (
            'not_available', None)
        assert self.compat.lookup('DES_cfb_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_check_key_parity') == (
            'not_available', None)
        assert self.compat.lookup('DES_crypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_decrypt3') == (
            'not_available', None)
        assert self.compat.lookup('DES_ecb3_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_ede3_cbc_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_ede3_cfb64_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_ede3_cfb_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_ede3_ofb64_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_encrypt1') == (
            'not_available', None)
        assert self.compat.lookup('DES_encrypt2') == (
            'not_available', None)
        assert self.compat.lookup('DES_encrypt3') == (
            'not_available', None)
        assert self.compat.lookup('DES_fcrypt') == (
            'not_available', None)

    def test_batch_072_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('DES_is_weak_key') == (
            'not_available', None)
        assert self.compat.lookup('DES_key_sched') == (
            'not_available', None)
        assert self.compat.lookup('DES_ncbc_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_ofb64_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_options') == (
            'not_available', None)
        assert self.compat.lookup('DES_pcbc_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('DES_quad_cksum') == (
            'not_available', None)
        assert self.compat.lookup('DES_random_key') == (
            'not_available', None)
        assert self.compat.lookup('DES_set_key') == (
            'not_available', None)
        assert self.compat.lookup('DES_set_key_checked') == (
            'not_available', None)
        assert self.compat.lookup('DES_string_to_2keys') == (
            'not_available', None)
        assert self.compat.lookup('DES_string_to_key') == (
            'not_available', None)
        assert self.compat.lookup('DES_xcbc_encrypt') == (
            'not_available', None)

    def test_batch_073_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('BF_cbc_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('BF_cfb64_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('BF_decrypt') == (
            'not_available', None)
        assert self.compat.lookup('BF_ecb_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('BF_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('BF_ofb64_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('BF_options') == (
            'not_available', None)
        assert self.compat.lookup('BF_set_key') == (
            'not_available', None)

    def test_batch_074_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('Camellia_cbc_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('Camellia_cfb128_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('Camellia_cfb1_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('Camellia_cfb8_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('Camellia_ctr128_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('Camellia_decrypt') == (
            'not_available', None)
        assert self.compat.lookup('Camellia_ecb_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('Camellia_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('Camellia_ofb128_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('Camellia_set_key') == (
            'not_available', None)

    def test_batch_075_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('IDEA_cbc_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('IDEA_cfb64_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('IDEA_ecb_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('IDEA_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('IDEA_ofb64_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('IDEA_options') == (
            'not_available', None)
        assert self.compat.lookup('IDEA_set_decrypt_key') == (
            'not_available', None)
        assert self.compat.lookup('IDEA_set_encrypt_key') == (
            'not_available', None)

    def test_batch_076_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('RC2_cbc_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('RC2_cfb64_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('RC2_decrypt') == (
            'not_available', None)
        assert self.compat.lookup('RC2_ecb_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('RC2_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('RC2_ofb64_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('RC2_set_key') == (
            'not_available', None)

    def test_batch_077_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('SEED_cbc_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('SEED_cfb128_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('SEED_decrypt') == (
            'not_available', None)
        assert self.compat.lookup('SEED_ecb_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('SEED_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('SEED_ofb128_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('SEED_set_key') == (
            'not_available', None)

    def test_batch_078_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('CAST_cbc_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('CAST_cfb64_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('CAST_decrypt') == (
            'not_available', None)
        assert self.compat.lookup('CAST_ecb_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('CAST_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('CAST_ofb64_encrypt') == (
            'not_available', None)
        assert self.compat.lookup('CAST_set_key') == (
            'not_available', None)

    def test_batch_079_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_BIT_STRING_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_BIT_STRING_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_BIT_STRING_set') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_BIT_STRING_get_bit') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_BIT_STRING_set_bit') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_BIT_STRING_check') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_BIT_STRING_num_asc') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_BIT_STRING_set_asc') == (
            'not_available', None)

    def test_batch_080_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_BMPSTRING_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_BMPSTRING_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_BMPSTRING_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_BOOLEAN_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_ENUMERATED_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_ENUMERATED_get_int64') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_ENUMERATED_it') == (
            'not_available', None)

    def test_batch_081_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_ENUMERATED_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_ENUMERATED_set') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_ENUMERATED_set_int64') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_ENUMERATED_to_BN') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_FBOOLEAN_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_GENERALIZEDTIME_adj') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_GENERALIZEDTIME_dup') == (
            'not_available', None)

    def test_batch_082_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_GENERALIZEDTIME_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_GENERALIZEDTIME_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_GENERALIZEDTIME_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_GENERALIZEDTIME_set') == (
            'partial',
            'BSL_SAL_UtcTimeToDateConvert + BSL_ASN1_EncodeTemplate(BSL_ASN1_TAG_GENERALIZEDTIME, BSL_TIME)')
        assert self.compat.lookup('ASN1_GENERALIZEDTIME_set_string') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_GENERALSTRING_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_GENERALSTRING_it') == (
            'not_available', None)

    def test_batch_083_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_GENERALSTRING_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_IA5STRING_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_IA5STRING_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_IA5STRING_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_INTEGER_cmp') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_INTEGER_dup') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_INTEGER_free') == (
            'not_available', None)

    def test_batch_084_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_INTEGER_get_int64') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_INTEGER_get_uint64') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_INTEGER_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_INTEGER_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_INTEGER_set_int64') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_INTEGER_set_uint64') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_INTEGER_to_BN') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_NULL_free') == (
            'not_available', None)

    def test_batch_085_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_NULL_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_NULL_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_OBJECT_create') == (
            'partial',
            'BSL_OBJ_Create + BSL_OBJ_GetCID/BSL_OBJ_GetOID')
        assert self.compat.lookup('ASN1_OBJECT_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_OBJECT_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_OCTET_STRING_NDEF_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_OCTET_STRING_cmp') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_OCTET_STRING_dup') == (
            'not_available', None)

    def test_batch_086_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_OCTET_STRING_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PCTX_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PCTX_get_cert_flags') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PCTX_get_flags') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PCTX_get_nm_flags') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PCTX_get_oid_flags') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PCTX_get_str_flags') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PCTX_new') == (
            'not_available', None)

    def test_batch_087_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_PCTX_set_cert_flags') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PCTX_set_flags') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PCTX_set_nm_flags') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PCTX_set_oid_flags') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PCTX_set_str_flags') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PRINTABLESTRING_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PRINTABLESTRING_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PRINTABLESTRING_new') == (
            'not_available', None)

    def test_batch_088_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_PRINTABLE_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PRINTABLE_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PRINTABLE_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_PRINTABLE_type') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_SCTX_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_SCTX_get_app_data') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_SCTX_get_flags') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_SCTX_get_item') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_SCTX_get_template') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_SCTX_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_SCTX_set_app_data') == (
            'not_available', None)

    def test_batch_089_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_SEQUENCE_ANY_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_SEQUENCE_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_SET_ANY_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_TABLE_add') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_TABLE_cleanup') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_TABLE_get') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_clear_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_cmp') == (
            'not_available', None)

    def test_batch_090_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_STRING_copy') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_dup') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_get_default_mask') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_length_set') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_print') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_print_ex') == (
            'not_available', None)

    def test_batch_091_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_STRING_print_ex_fp') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_set0') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_set_by_NID') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_set_default_mask') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_set_default_mask_asc') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_type') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_STRING_type_new') == (
            'not_available', None)

    def test_batch_092_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_T61STRING_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_T61STRING_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_T61STRING_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_TBOOLEAN_it') == (
            'not_available', None)

    def test_batch_093_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_TIME_dup') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_TIME_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_TIME_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_TIME_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_TIME_normalize') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_TIME_set') == (
            'partial',
            'BSL_SAL_UtcTimeToDateConvert + BSL_ASN1_EncodeTemplate(BSL_ASN1_TAG_{UTC,GENERALIZED}TIME, BSL_TIME)')

    def test_batch_094_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_TIME_set_string') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_TIME_set_string_X509') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_TIME_to_generalizedtime') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_UTCTIME_dup') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_UTCTIME_free') == (
            'not_available', None)

    def test_batch_095_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_UTCTIME_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_UTCTIME_new') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_UTCTIME_set') == (
            'partial',
            'BSL_SAL_UtcTimeToDateConvert + BSL_ASN1_EncodeTemplate(BSL_ASN1_TAG_UTCTIME, BSL_TIME)')
        assert self.compat.lookup('ASN1_UTCTIME_set_string') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_UTF8STRING_free') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_UTF8STRING_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_UTF8STRING_new') == (
            'not_available', None)

    def test_batch_096_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        for sym in (
            'ASN1_UNIVERSALSTRING_free',
            'ASN1_UNIVERSALSTRING_it',
            'ASN1_UNIVERSALSTRING_new',
            'ASN1_UNIVERSALSTRING_to_string',
            'ASN1_VISIBLESTRING_free',
            'ASN1_VISIBLESTRING_it',
            'ASN1_VISIBLESTRING_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)

    def test_batch_097_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_ANY_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_BIT_STRING_it') == (
            'not_available', None)
        assert self.compat.lookup('ASN1_BIT_STRING_name_print') == (
            'not_available', None)

    def test_batch_098_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        for sym in (
            'ASN1_TYPE_cmp',
            'ASN1_TYPE_free',
            'ASN1_TYPE_get',
            'ASN1_TYPE_get_int_octetstring',
            'ASN1_TYPE_get_octetstring',
            'ASN1_TYPE_new',
            'ASN1_TYPE_pack_sequence',
            'ASN1_TYPE_set',
            'ASN1_TYPE_set1',
            'ASN1_TYPE_set_int_octetstring',
            'ASN1_TYPE_set_octetstring',
            'ASN1_TYPE_unpack_sequence',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)

    def test_batch_099_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ASN1_item_d2i') == (
            'partial',
            'BSL_ASN1_DecodeTemplate(&templ, cb, &buf, &bufLen, asn, count)'
        )
        assert self.compat.lookup('ASN1_item_i2d') == (
            'partial',
            'BSL_ASN1_EncodeTemplate(&templ, asn, count, &buf, &bufLen)'
        )
        for sym in (
            'ASN1_ANY_it',
            'ASN1_SEQUENCE_ANY_it',
            'ASN1_SEQUENCE_it',
            'ASN1_SET_ANY_it',
            'ASN1_ITEM_get',
            'ASN1_ITEM_lookup',
            'ASN1_d2i_bio',
            'ASN1_i2d_bio',
            'ASN1_item_d2i_bio',
            'ASN1_item_d2i_bio_ex',
            'ASN1_item_d2i_ex',
            'ASN1_item_d2i_fp',
            'ASN1_item_d2i_fp_ex',
            'ASN1_item_digest',
            'ASN1_item_dup',
            'ASN1_item_ex_d2i',
            'ASN1_item_ex_free',
            'ASN1_item_ex_i2d',
            'ASN1_item_ex_new',
            'ASN1_item_free',
            'ASN1_item_i2d_bio',
            'ASN1_item_i2d_fp',
            'ASN1_item_i2d_mem_bio',
            'ASN1_item_ndef_i2d',
            'ASN1_item_new',
            'ASN1_item_new_ex',
            'ASN1_item_pack',
            'ASN1_item_print',
            'ASN1_item_sign',
            'ASN1_item_sign_ctx',
            'ASN1_item_sign_ex',
            'ASN1_item_unpack',
            'ASN1_item_unpack_ex',
            'ASN1_item_verify',
            'ASN1_item_verify_ctx',
            'ASN1_item_verify_ex',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)

    def test_batch_100_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        for sym in (
            'ASN1_get_object',
            'ASN1_put_object',
            'ASN1_put_eoc',
            'ASN1_check_infinite_end',
            'ASN1_const_check_infinite_end',
            'ASN1_object_size',
            'ASN1_sign',
            'ASN1_verify',
            'ASN1_digest',
            'ASN1_dup',
            'ASN1_generate_nconf',
            'ASN1_generate_v3',
            'ASN1_mbstring_copy',
            'ASN1_mbstring_ncopy',
            'ASN1_tag2bit',
            'ASN1_tag2str',
            'ASN1_str2mask',
            'ASN1_parse',
            'ASN1_parse_dump',
            'ASN1_bn_print',
            'ASN1_buf_print',
            'ASN1_add_oid_module',
            'ASN1_add_stable_module',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)

    def test_batch_101_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        assert self.compat.lookup('ACCESS_DESCRIPTION_free') == (
            'not_available', None)
        assert self.compat.lookup('ACCESS_DESCRIPTION_it') == (
            'not_available', None)
        assert self.compat.lookup('ACCESS_DESCRIPTION_new') == (
            'not_available', None)

    def test_batch_102_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        for sym in (
            'ADMISSION_SYNTAX_free',
            'ADMISSION_SYNTAX_get0_admissionAuthority',
            'ADMISSION_SYNTAX_get0_contentsOfAdmissions',
            'ADMISSION_SYNTAX_it',
            'ADMISSION_SYNTAX_new',
            'ADMISSION_SYNTAX_set0_admissionAuthority',
            'ADMISSION_SYNTAX_set0_contentsOfAdmissions',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)

    def test_batch_103_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        for sym in (
            'ADMISSIONS_free',
            'ADMISSIONS_get0_admissionAuthority',
            'ADMISSIONS_get0_namingAuthority',
            'ADMISSIONS_get0_professionInfos',
            'ADMISSIONS_it',
            'ADMISSIONS_new',
            'ADMISSIONS_set0_admissionAuthority',
            'ADMISSIONS_set0_namingAuthority',
            'ADMISSIONS_set0_professionInfos',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)

    def test_batch_104_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'AUTHORITY_INFO_ACCESS_free',
            'AUTHORITY_INFO_ACCESS_it',
            'AUTHORITY_INFO_ACCESS_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_104.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_130_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'MD5': ('available', 'CRYPT_EAL_Md(CRYPT_MD_MD5, ...)'),
            'MD5_Init': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_MD5) + CRYPT_EAL_MdInit'),
            'MD5_Update': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_MD5) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate'),
            'MD5_Final': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_MD5) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate + CRYPT_EAL_MdFinal'),
            'SHA1': ('available', 'CRYPT_EAL_Md(CRYPT_MD_SHA1, ...)'),
            'SHA1_Init': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1) + CRYPT_EAL_MdInit'),
            'SHA1_Update': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate'),
            'SHA1_Final': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate + CRYPT_EAL_MdFinal'),
            'SHA224': ('available', 'CRYPT_EAL_Md(CRYPT_MD_SHA224, ...)'),
            'SHA224_Init': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA224) + CRYPT_EAL_MdInit'),
            'SHA224_Update': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA224) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate'),
            'SHA224_Final': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA224) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate + CRYPT_EAL_MdFinal'),
            'SHA256': ('available', 'CRYPT_EAL_Md(CRYPT_MD_SHA256, ...)'),
            'SHA256_Init': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256) + CRYPT_EAL_MdInit'),
            'SHA256_Update': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate'),
            'SHA256_Final': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate + CRYPT_EAL_MdFinal'),
            'SHA384': ('available', 'CRYPT_EAL_Md(CRYPT_MD_SHA384, ...)'),
            'SHA384_Init': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA384) + CRYPT_EAL_MdInit'),
            'SHA384_Update': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA384) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate'),
            'SHA384_Final': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA384) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate + CRYPT_EAL_MdFinal'),
            'SHA512': ('available', 'CRYPT_EAL_Md(CRYPT_MD_SHA512, ...)'),
            'SHA512_Init': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA512) + CRYPT_EAL_MdInit'),
            'SHA512_Update': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA512) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate'),
            'SHA512_Final': ('partial', 'CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA512) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate + CRYPT_EAL_MdFinal'),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_130.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_131_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'SMIME_crlf_copy',
            'SMIME_read_ASN1',
            'SMIME_read_ASN1_ex',
            'SMIME_read_CMS',
            'SMIME_read_CMS_ex',
            'SMIME_read_PKCS7',
            'SMIME_read_PKCS7_ex',
            'SMIME_text',
            'SMIME_write_ASN1',
            'SMIME_write_ASN1_ex',
            'SMIME_write_CMS',
            'SMIME_write_PKCS7',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_131.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_132_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'SRP_Calc_A',
            'SRP_Calc_A_param',
            'SRP_Calc_B',
            'SRP_Calc_B_ex',
            'SRP_Calc_client_key',
            'SRP_Calc_client_key_ex',
            'SRP_Calc_server_key',
            'SRP_Calc_u',
            'SRP_Calc_u_ex',
            'SRP_Calc_x',
            'SRP_Calc_x_ex',
            'SRP_VBASE_add0_user',
            'SRP_VBASE_free',
            'SRP_VBASE_get1_by_user',
            'SRP_VBASE_get_by_user',
            'SRP_VBASE_init',
            'SRP_VBASE_new',
            'SRP_Verify_A_mod_N',
            'SRP_Verify_B_mod_N',
            'SRP_check_known_gN_param',
            'SRP_create_verifier',
            'SRP_create_verifier_BN',
            'SRP_create_verifier_BN_ex',
            'SRP_create_verifier_ex',
            'SRP_get_default_gN',
            'SRP_user_pwd_free',
            'SRP_user_pwd_new',
            'SRP_user_pwd_set0_sv',
            'SRP_user_pwd_set1_ids',
            'SRP_user_pwd_set_gN',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_132.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_133_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'SSL_CIPHER_description': ('available', 'HITLS_CFG_GetDescription'),
            'SSL_CIPHER_find': ('partial', 'HITLS_CFG_GetCipherByID'),
            'SSL_CIPHER_get_auth_nid': ('partial', 'HITLS_CFG_GetAuthId'),
            'SSL_CIPHER_get_cipher_nid': ('partial', 'HITLS_CFG_GetCipherId'),
            'SSL_CIPHER_get_digest_nid': ('partial', 'HITLS_CFG_GetHashId'),
            'SSL_CIPHER_get_handshake_digest': ('not_available', None),
            'SSL_CIPHER_get_id': ('partial', 'HITLS_CFG_GetCipherSuite'),
            'SSL_CIPHER_get_kx_nid': ('partial', 'HITLS_CFG_GetKeyExchId'),
            'SSL_CIPHER_get_name': ('available', 'HITLS_CFG_GetCipherSuiteName'),
            'SSL_CIPHER_get_protocol_id': ('available', 'HITLS_CFG_GetCipherSuite'),
            'SSL_CIPHER_get_version': ('partial', 'HITLS_CFG_GetCipherVersion'),
            'SSL_CIPHER_is_aead': ('available', 'HITLS_CIPHER_IsAead'),
            'SSL_CIPHER_standard_name': ('available', 'HITLS_CFG_GetCipherSuiteStdName'),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_133.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_134_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'SSL_COMP_add_compression_method',
            'SSL_COMP_get0_name',
            'SSL_COMP_get_compression_methods',
            'SSL_COMP_get_id',
            'SSL_COMP_get_name',
            'SSL_COMP_set0_compression_methods',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_134.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_135_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'SSL_CONF_CTX_clear_flags',
            'SSL_CONF_CTX_finish',
            'SSL_CONF_CTX_free',
            'SSL_CONF_CTX_new',
            'SSL_CONF_CTX_set1_prefix',
            'SSL_CONF_CTX_set_flags',
            'SSL_CONF_CTX_set_ssl',
            'SSL_CONF_CTX_set_ssl_ctx',
            'SSL_CONF_cmd',
            'SSL_CONF_cmd_argv',
            'SSL_CONF_cmd_value_type',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_135.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_136_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'SSL_CTX_SRP_CTX_free': ('not_available', None),
            'SSL_CTX_SRP_CTX_init': ('not_available', None),
            'SSL_CTX_add1_to_CA_list': ('partial', 'HITLS_CFG_AddCAIndication'),
            'SSL_CTX_add_client_CA': ('partial', 'HITLS_CFG_AddCAIndication'),
            'SSL_CTX_add_client_custom_ext': ('available', 'HITLS_CFG_AddCustomExtension'),
            'SSL_CTX_add_custom_ext': ('available', 'HITLS_CFG_AddCustomExtension'),
            'SSL_CTX_add_server_custom_ext': ('available', 'HITLS_CFG_AddCustomExtension'),
            'SSL_CTX_add_session': ('not_available', None),
            'SSL_CTX_callback_ctrl': ('not_available', None),
            'SSL_CTX_clear_options': ('partial', 'HITLS_CFG_SetRenegotiationSupport / HITLS_CFG_SetSessionTicketSupport / HITLS_CFG_SetVersionForbid / HITLS_CFG_SetExtendedMasterSecretSupport / HITLS_CFG_SetPostHandshakeAuthSupport / HITLS_CFG_SetDtlsCookieExchangeSupport (call with false)'),
            'SSL_CTX_config': ('not_available', None),
            'SSL_CTX_ctrl': ('not_available', None),
            'SSL_CTX_flush_sessions': ('available', 'HITLS_CFG_ClearTimeoutSession'),
            'SSL_CTX_flush_sessions_ex': ('available', 'HITLS_CFG_ClearTimeoutSession'),
            'SSL_CTX_get0_CA_list': ('partial', 'HITLS_CFG_GetCAList'),
            'SSL_CTX_get0_param': ('not_available', None),
            'SSL_CTX_get0_security_ex_data': ('available', 'HITLS_CFG_GetSecurityExData'),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_136.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_137_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'SSL_CTX_get1_compressed_cert': ('not_available', None),
            'SSL_CTX_get_ciphers': ('partial', 'HITLS_CFG_GetCipherSuites'),
            'SSL_CTX_get_default_passwd_cb': ('available', 'HITLS_CFG_GetDefaultPasswordCb'),
            'SSL_CTX_get_default_passwd_cb_userdata': ('available', 'HITLS_CFG_GetDefaultPasswordCbUserdata'),
            'SSL_CTX_get_keylog_callback': ('partial', 'HITLS_CFG_GetKeyLogCb (include/tls/hitls_cert.h:999/1008)'),
            'SSL_CTX_get_max_early_data': ('not_available', None),
            'SSL_CTX_get_record_padding_callback_arg': ('available', 'HITLS_CFG_GetRecordPaddingCbArg'),
            'SSL_CTX_get_recv_max_early_data': ('not_available', None),
            'SSL_CTX_get_ssl_method': ('not_available', None),
            'SSL_CTX_has_client_custom_ext': ('not_available', None),
            'SSL_CTX_load_verify_dir': ('available', 'HITLS_CFG_LoadVerifyDir'),
            'SSL_CTX_load_verify_file': ('available', 'HITLS_CFG_LoadVerifyFile'),
            'SSL_CTX_load_verify_store': ('not_available', None),
            'SSL_CTX_new_ex': ('partial', 'HITLS_CFG_ProviderNewTLSConfig'),
            'SSL_CTX_remove_session': ('available', 'HITLS_CFG_RemoveSession'),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_137.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_138_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'SSL_CTX_sessions': ('not_available', None),
            'SSL_CTX_set0_ctlog_store': ('not_available', None),
            'SSL_CTX_set0_security_ex_data': ('available', 'HITLS_CFG_SetSecurityExData'),
            'SSL_CTX_set0_tmp_dh_pkey': ('partial', 'HITLS_CFG_SetTmpDh'),
            'SSL_CTX_set1_cert_comp_preference': ('not_available', None),
            'SSL_CTX_set1_cert_store': ('partial', 'HITLS_CFG_SetVerifyStore'),
            'SSL_CTX_set1_client_cert_type': ('not_available', None),
            'SSL_CTX_set1_compressed_cert': ('not_available', None),
            'SSL_CTX_set1_param': ('not_available', None),
            'SSL_CTX_set1_server_cert_type': ('not_available', None),
            'SSL_CTX_set_allow_early_data_cb': ('not_available', None),
            'SSL_CTX_set_async_callback': ('not_available', None),
            'SSL_CTX_set_async_callback_arg': ('not_available', None),
            'SSL_CTX_set_block_padding': ('partial', 'HITLS_CFG_SetRecordPaddingCb'),
            'SSL_CTX_set_cert_store': ('partial', 'HITLS_CFG_SetVerifyStore / HITLS_CFG_SetChainStore'),
            'SSL_CTX_set_client_hello_cb': ('available', 'HITLS_CFG_SetClientHelloCb'),
            'SSL_CTX_set_cookie_generate_cb': ('available', 'HITLS_CFG_SetCookieGenCb'),
            'SSL_CTX_set_cookie_verify_cb': ('available', 'HITLS_CFG_SetCookieVerifyCb'),
            'SSL_CTX_set_ct_validation_callback': ('not_available', None),
            'SSL_CTX_set_default_passwd_cb': ('available', 'HITLS_CFG_SetDefaultPasswordCb'),
            'SSL_CTX_set_default_passwd_cb_userdata': ('available', 'HITLS_CFG_SetDefaultPasswordCbUserdata'),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_138.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_139_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'BIO_f_base64': ('partial', 'BSL_BASE64_CtxNew / BSL_BASE64_EncodeInit / BSL_BASE64_DecodeInit'),
            'EVP_ENCODE_CTX_new': ('available', 'BSL_BASE64_CtxNew'),
            'EVP_ENCODE_CTX_free': ('available', 'BSL_BASE64_CtxFree'),
            'EVP_DecodeInit': ('available', 'BSL_BASE64_DecodeInit'),
            'EVP_DecodeUpdate': ('available', 'BSL_BASE64_DecodeUpdate'),
            'EVP_DecodeFinal': ('available', 'BSL_BASE64_DecodeFinal'),
            'OPENSSL_cleanse': ('available', 'BSL_SAL_CleanseData'),
            'CRYPTO_memcmp': ('not_available', None),
            'EVP_aes_192_ctr': ('partial', 'CRYPT_CIPHER_AES192_CTR'),
            'EVP_aes_192_gcm': ('partial', 'CRYPT_CIPHER_AES192_GCM'),
            'EVP_get_cipherbyname': ('not_available', None),
            'EVP_CIPHER_CTX_set_key_length': ('not_available', None),
            'd2i_PUBKEY': ('available', 'CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_DER, CRYPT_PUBKEY_SUBKEY, ...)'),
            'EVP_VerifyFinal': ('partial', 'CRYPT_EAL_MdFinal + CRYPT_EAL_PkeyVerifyData'),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_139.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_141_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'EVP_PKEY_new_raw_private_key': ('partial', 'CRYPT_EAL_PkeyNewCtx + CRYPT_EAL_PkeySetPrv'),
            'EVP_PKEY_new_raw_private_key_ex': ('partial', 'CRYPT_EAL_ProviderPkeyNewCtx / CRYPT_EAL_PkeySetPrv'),
            'EVP_PKEY_new_raw_public_key': ('partial', 'CRYPT_EAL_PkeyNewCtx + CRYPT_EAL_PkeySetPub'),
            'EVP_PKEY_new_raw_public_key_ex': ('partial', 'CRYPT_EAL_ProviderPkeyNewCtx / CRYPT_EAL_PkeySetPub'),
            'EVP_PKEY_get_raw_private_key': ('partial', 'CRYPT_EAL_PkeyGetPrv / CRYPT_EAL_PkeyGetPrvEx'),
            'EVP_PKEY_get_raw_public_key': ('partial', 'CRYPT_EAL_PkeyGetPub / CRYPT_EAL_PkeyGetPubEx'),
            'EVP_PKEY_get_bn_param': ('not_available', None),
            'X509_PUBKEY_free': ('not_available', None),
            'X509_PUBKEY_get0_param': ('not_available', None),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_141.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_105_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'AUTHORITY_KEYID_free',
            'AUTHORITY_KEYID_it',
            'AUTHORITY_KEYID_new',
        ):
            assert self.compat.lookup(sym) == (
                'partial', 'HITLS_X509_ExtCtrl(HITLS_X509_EXT_GET_AKI)'
            )
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_105.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_106_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'BASIC_CONSTRAINTS_free',
            'BASIC_CONSTRAINTS_it',
            'BASIC_CONSTRAINTS_new',
        ):
            assert self.compat.lookup(sym) == (
                'partial', 'HITLS_X509_ExtCtrl(HITLS_X509_EXT_GET_BCONS)'
            )
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_106.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_107_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'CERTIFICATEPOLICIES_free',
            'CERTIFICATEPOLICIES_it',
            'CERTIFICATEPOLICIES_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_107.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_108_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'CRL_DIST_POINTS_free',
            'CRL_DIST_POINTS_it',
            'CRL_DIST_POINTS_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_108.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_109_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'DIST_POINT_NAME_dup',
            'DIST_POINT_NAME_free',
            'DIST_POINT_NAME_it',
            'DIST_POINT_NAME_new',
            'DIST_POINT_free',
            'DIST_POINT_it',
            'DIST_POINT_new',
            'DIST_POINT_set_dpname',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_109.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_110_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'GENERAL_NAMES_free',
            'GENERAL_NAMES_it',
            'GENERAL_NAMES_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_110.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_111_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'GENERAL_NAME_cmp': ('not_available', None),
            'GENERAL_NAME_dup': ('not_available', None),
            'GENERAL_NAME_free': ('partial', 'HITLS_X509_FreeGeneralName'),
            'GENERAL_NAME_get0_otherName': ('not_available', None),
            'GENERAL_NAME_get0_value': ('not_available', None),
            'GENERAL_NAME_it': ('not_available', None),
            'GENERAL_NAME_new': ('not_available', None),
            'GENERAL_NAME_print': ('not_available', None),
            'GENERAL_NAME_set0_othername': ('not_available', None),
            'GENERAL_NAME_set0_value': ('not_available', None),
            'GENERAL_NAME_set1_X509_NAME': ('not_available', None),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_111.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_112_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'GENERAL_SUBTREE_free',
            'GENERAL_SUBTREE_it',
            'GENERAL_SUBTREE_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_112.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_113_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'ISSUING_DIST_POINT_free',
            'ISSUING_DIST_POINT_it',
            'ISSUING_DIST_POINT_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_113.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_114_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'NAME_CONSTRAINTS_check',
            'NAME_CONSTRAINTS_check_CN',
            'NAME_CONSTRAINTS_free',
            'NAME_CONSTRAINTS_it',
            'NAME_CONSTRAINTS_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_114.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_115_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'ASIdOrRange_free',
            'ASIdOrRange_it',
            'ASIdOrRange_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_115.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_116_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'ASIdentifierChoice_free',
            'ASIdentifierChoice_it',
            'ASIdentifierChoice_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_116.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_117_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'ASIdentifiers_free',
            'ASIdentifiers_it',
            'ASIdentifiers_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_117.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_118_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'ASRange_free',
            'ASRange_it',
            'ASRange_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_118.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_119_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'POLICY_CONSTRAINTS_free',
            'POLICY_CONSTRAINTS_it',
            'POLICY_CONSTRAINTS_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_119.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_120_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'POLICY_MAPPINGS_it',
            'POLICY_MAPPING_free',
            'POLICY_MAPPING_it',
            'POLICY_MAPPING_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_120.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_121_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'PROXY_CERT_INFO_EXTENSION_free',
            'PROXY_CERT_INFO_EXTENSION_it',
            'PROXY_CERT_INFO_EXTENSION_new',
            'PROXY_POLICY_free',
            'PROXY_POLICY_it',
            'PROXY_POLICY_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_121.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_122_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'SXNETID_free',
            'SXNETID_it',
            'SXNETID_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_122.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_123_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'SXNET_add_id_INTEGER',
            'SXNET_add_id_asc',
            'SXNET_add_id_ulong',
            'SXNET_free',
            'SXNET_get_id_INTEGER',
            'SXNET_get_id_asc',
            'SXNET_get_id_ulong',
            'SXNET_it',
            'SXNET_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_123.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_124_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'NOTICEREF_free',
            'NOTICEREF_it',
            'NOTICEREF_new',
            'USERNOTICE_free',
            'USERNOTICE_it',
            'USERNOTICE_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_124.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_125_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'POLICYINFO_free',
            'POLICYINFO_it',
            'POLICYINFO_new',
            'POLICYQUALINFO_free',
            'POLICYQUALINFO_it',
            'POLICYQUALINFO_new',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_125.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_126_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'X509_ALGORS_it',
            'X509_ALGOR_cmp',
            'X509_ALGOR_copy',
            'X509_ALGOR_dup',
            'X509_ALGOR_free',
            'X509_ALGOR_get0',
            'X509_ALGOR_it',
            'X509_ALGOR_new',
            'X509_ALGOR_set0',
            'X509_ALGOR_set_md',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_126.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_127_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        for sym in (
            'X509_ATTRIBUTE_count',
            'X509_ATTRIBUTE_create',
            'X509_ATTRIBUTE_create_by_NID',
            'X509_ATTRIBUTE_create_by_OBJ',
            'X509_ATTRIBUTE_create_by_txt',
            'X509_ATTRIBUTE_dup',
            'X509_ATTRIBUTE_free',
            'X509_ATTRIBUTE_get0_data',
            'X509_ATTRIBUTE_get0_object',
            'X509_ATTRIBUTE_get0_type',
            'X509_ATTRIBUTE_it',
            'X509_ATTRIBUTE_new',
            'X509_ATTRIBUTE_set1_data',
            'X509_ATTRIBUTE_set1_object',
        ):
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_127.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_128_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'UTF8_getc': ('not_available', None),
            'UTF8_putc': ('not_available', None),
            'WHIRLPOOL': ('not_available', None),
            'WHIRLPOOL_BitUpdate': ('not_available', None),
            'WHIRLPOOL_Final': ('not_available', None),
            'WHIRLPOOL_Init': ('not_available', None),
            'WHIRLPOOL_Update': ('not_available', None),
            'X509V3_EXT_CRL_add_conf': ('not_available', None),
            'X509V3_EXT_CRL_add_nconf': ('not_available', None),
            'X509V3_EXT_REQ_add_conf': ('not_available', None),
            'X509V3_EXT_REQ_add_nconf': ('not_available', None),
            'X509V3_EXT_add': ('not_available', None),
            'X509V3_EXT_add_alias': ('not_available', None),
            'X509V3_EXT_add_conf': ('not_available', None),
            'X509V3_EXT_add_list': ('not_available', None),
            'X509V3_EXT_add_nconf': ('not_available', None),
            'X509V3_EXT_add_nconf_sk': ('not_available', None),
            'X509V3_EXT_cleanup': ('not_available', None),
            'X509V3_EXT_conf': ('not_available', None),
            'X509V3_EXT_conf_nid': ('not_available', None),
            'X509V3_EXT_d2i': ('not_available', None),
            'X509V3_EXT_get': ('not_available', None),
            'X509V3_EXT_get_nid': ('not_available', None),
            'X509V3_EXT_i2d': ('not_available', None),
            'X509V3_EXT_nconf': ('not_available', None),
            'X509V3_EXT_nconf_nid': ('not_available', None),
            'X509V3_EXT_print': ('not_available', None),
            'X509V3_EXT_print_fp': ('not_available', None),
            'X509V3_EXT_val_prn': ('not_available', None),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_128.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_129_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'X509V3_NAME_from_section': ('not_available', None),
            'X509V3_add1_i2d': (
                'partial',
                'HITLS_X509_ExtNew + HITLS_X509_ExtCtrl(HITLS_X509_EXT_SET_*|HITLS_X509_EXT_SET_GENERIC)',
            ),
            'X509V3_add_standard_extensions': ('not_available', None),
            'X509V3_add_value': ('not_available', None),
            'X509V3_add_value_bool': ('not_available', None),
            'X509V3_add_value_bool_nf': ('not_available', None),
            'X509V3_add_value_int': ('not_available', None),
            'X509V3_add_value_uchar': ('not_available', None),
            'X509V3_conf_free': ('not_available', None),
            'X509V3_extensions_print': ('not_available', None),
            'X509V3_get_d2i': (
                'partial',
                'HITLS_X509_ExtCtrl(HITLS_X509_EXT_GET_*|HITLS_X509_EXT_GET_GENERIC)',
            ),
            'X509V3_get_section': ('not_available', None),
            'X509V3_get_string': ('not_available', None),
            'X509V3_get_value_bool': ('not_available', None),
            'X509V3_get_value_int': ('not_available', None),
            'X509V3_parse_list': ('not_available', None),
            'X509V3_section_free': ('not_available', None),
            'X509V3_set_conf_lhash': ('not_available', None),
            'X509V3_set_ctx': ('not_available', None),
            'X509V3_set_issuer_pkey': ('not_available', None),
            'X509V3_set_nconf': ('not_available', None),
            'X509V3_string_free': ('not_available', None),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_129.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_142_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'OpenSSL_add_all_algorithms': (
                'partial', 'BSL_GLOBAL_Init + CRYPT_EAL_Init'
            ),
            'OpenSSL_add_ssl_algorithms': (
                'partial', 'HITLS_CryptMethodInit + HITLS_CertMethodInit'
            ),
            'SSL_library_init': (
                'partial', 'HITLS_CryptMethodInit + HITLS_CertMethodInit'
            ),
            'SSL_load_error_strings': (
                'partial', 'BSL_ERR_Init + BSL_ERR_GetString'
            ),
            'ERR_load_crypto_strings': (
                'partial', 'BSL_ERR_Init + BSL_ERR_GetString'
            ),
            'SSL_CTX_set_mode': ('available', 'HITLS_CFG_SetModeSupport'),
            'SSL_CTX_set1_curves_list': ('available', 'HITLS_CFG_SetGroupList'),
            'SSL_CTX_set_max_proto_version': (
                'partial', 'HITLS_CFG_SetVersion(config, min, max)'
            ),
            'SSL_CTX_set_min_proto_version': (
                'partial', 'HITLS_CFG_SetVersion(config, min, max)'
            ),
            'SSL_get_peer_certificate': ('available', 'HITLS_GetPeerCertificate'),
            'SSL_get_cipher': (
                'available',
                'HITLS_GetCurrentCipher + HITLS_CFG_GetCipherSuiteName',
            ),
            'SSL_set_tlsext_host_name': (
                'available', 'HITLS_SetServerName / HITLS_CFG_SetServerName'
            ),
            'SSL_get_app_data': ('available', 'HITLS_GetUserData'),
            'SSL_set_app_data': ('available', 'HITLS_SetUserData'),
            'SSL_want_read': ('available', 'HITLS_GetRwstate == HITLS_READING'),
            'SSL_want_write': ('available', 'HITLS_GetRwstate == HITLS_WRITING'),
            'SSL_set_mtu': ('available', 'HITLS_SetMtu'),
            'SSL_get_shared_sigalgs': ('available', 'HITLS_GetSharedSigAlgs'),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_142.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_143_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'BIO_flush': (
                'partial',
                'BSL_UIO_Ctrl(uio, BSL_UIO_FLUSH, 0, NULL)',
            ),
            'BIO_get_mem_ptr': (
                'partial',
                'BSL_UIO_Ctrl(uio, BSL_UIO_MEM_GET_PTR, sizeof(BSL_BufMem *), &buf)',
            ),
            'BIO_clear_retry_flags': (
                'partial',
                'BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY)',
            ),
            'BIO_set_nbio': ('not_available', None),
            'BIO_number_written': (
                'partial',
                'BSL_UIO_Ctrl(uio, BSL_UIO_GET_WRITE_NUM, sizeof(int64_t), &written)',
            ),
            'BIO_set_init': ('available', 'BSL_UIO_SetInit'),
            'BIO_vfree': ('available', 'BSL_UIO_Free'),
            'OPENSSL_malloc': ('available', 'BSL_SAL_Malloc'),
            'OPENSSL_clear_free': ('available', 'BSL_SAL_ClearFree'),
            'OPENSSL_strdup': (
                'partial',
                'BSL_SAL_Dump(str, strlen(str) + 1)',
            ),
            'EVP_EncodeInit': ('available', 'BSL_BASE64_EncodeInit'),
            'EVP_EncodeUpdate': ('available', 'BSL_BASE64_EncodeUpdate'),
            'EVP_EncodeFinal': ('available', 'BSL_BASE64_EncodeFinal'),
            'EVP_MD_CTX_set_flags': ('not_available', None),
            'EVP_MD_CTX_init': (
                'partial', 'CRYPT_EAL_MdNewCtx + CRYPT_EAL_MdInit'
            ),
            'EVP_MD_CTX_create': ('partial', 'CRYPT_EAL_MdNewCtx'),
            'EVP_MD_CTX_destroy': ('available', 'CRYPT_EAL_MdFreeCtx'),
            'EVP_VerifyInit_ex': (
                'partial', 'CRYPT_EAL_MdNewCtx + CRYPT_EAL_MdInit'
            ),
            'EVP_VerifyUpdate': ('partial', 'CRYPT_EAL_MdUpdate'),
            'EVP_get_digestbynid': ('not_available', None),
            'EVP_MD_type': ('partial', 'CRYPT_EAL_MdGetId'),
            'EVP_PKEY_id': ('partial', 'CRYPT_EAL_PkeyGetId'),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_143.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_144_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'ERR_GET_REASON': ('partial', 'BSL_ERR_GetLastError() & 0xffff'),
            'ERR_get_error_all': ('available', 'BSL_ERR_GetErrAll'),
            'ERR_get_error_line': ('available', 'BSL_ERR_GetErrorFileLine'),
            'ERR_get_error_line_data': ('not_available', None),
            'ERR_print_errors_fp': (
                'partial', 'BSL_ERR_RegErrStackLog + BSL_ERR_OutputErrorStack'
            ),
            'ERR_func_error_string': ('not_available', None),
            'ERR_raise': ('not_available', None),
            'ERR_PACK': ('not_available', None),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_144.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_145_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'PKCS7_new': (
                'partial',
                'HITLS_CMS_ProviderNew(..., BSL_CID_PKCS7_SIGNEDDATA)',
            ),
            'PKCS7_new_ex': (
                'partial',
                'HITLS_CMS_ProviderNew(libCtx, attrName, BSL_CID_PKCS7_SIGNEDDATA)',
            ),
            'PKCS7_free': ('partial', 'HITLS_CMS_Free'),
            'PKCS7_get_signer_info': ('not_available', None),
            'X509_add_ext': (
                'partial',
                'HITLS_X509_CertCtrl(HITLS_X509_EXT_SET_*|HITLS_X509_EXT_SET_GENERIC)',
            ),
            'X509_subject_name_hash': ('not_available', None),
            'ENGINE_by_id': ('not_available', None),
            'ENGINE_init': ('not_available', None),
            'ENGINE_free': ('not_available', None),
            'ENGINE_ctrl_cmd_string': ('not_available', None),
            'OBJ_nid2ln': ('not_available', None),
            'SSL_alert_desc_string_long': ('not_available', None),
            'SSL_alert_type_string_long': ('not_available', None),
            'X509_load_http': ('not_available', None),
            'BIO_do_connect_retry': ('not_available', None),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_145.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_146_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'CRYPTO_cleanup_all_ex_data': ('partial', 'No-op; drop call'),
            'CRYPTO_num_locks': (
                'partial', 'No-op compatibility constant; drop call'
            ),
            'CRYPTO_THREADID_set_numeric': ('partial', 'No-op; drop call'),
            'CRYPTO_set_locking_callback': ('partial', 'No-op; drop call'),
            'CRYPTO_get_locking_callback': (
                'partial', 'No-op compatibility macro; always absent'
            ),
            'sk_PKCS7_SIGNER_INFO_num': ('not_available', None),
            'sk_SSL_CIPHER_num': (
                'partial', 'HITLS_GetCipherSuites(..., &cipherSuitesSize)'
            ),
            'sk_X509_CRL_pop_free': (
                'available',
                'BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree)',
            ),
            'OPENSSL_sk_value': ('available', 'BSL_LIST_GetIndexNode(idx, list)'),
            'OSSL_PARAM_uint': (
                'partial',
                'BSL_PARAM_InitValue(&param, key, BSL_PARAM_TYPE_UINT32, addr, sizeof(*addr))',
            ),
            'BN_mod': ('partial', 'BN_Mod'),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_146.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_147_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = {
            'OSSL_PROVIDER_try_load': (
                'partial',
                'CRYPT_EAL_ProviderLoad + CRYPT_EAL_ProviderIsLoaded',
            ),
            'EC_KEY_dup': ('partial', 'CRYPT_EAL_PkeyDupCtx'),
            'EC_POINT_point2oct': (
                'partial',
                'CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_SET_ECC_POINT_FORMAT) + CRYPT_EAL_PkeyGetPubEx(CRYPT_PARAM_PKEY_ENCODE_PUBKEY)',
            ),
            'EC_KEY_key2buf': (
                'partial',
                'CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_SET_ECC_POINT_FORMAT) + CRYPT_EAL_PkeyGetPub / CRYPT_EAL_PkeyGetPubEx',
            ),
            'OSSL_PARAM_construct_uint': (
                'partial',
                'BSL_PARAM_InitValue(&param, key, BSL_PARAM_TYPE_UINT32, addr, sizeof(*addr))',
            ),
            'OSSL_PARAM_construct_uint32': (
                'partial',
                'BSL_PARAM_InitValue(&param, key, BSL_PARAM_TYPE_UINT32, addr, sizeof(*addr))',
            ),
            'OSSL_PARAM_construct_uint64': (
                'partial',
                'BSL_PARAM_InitValue(&param, key, BSL_PARAM_TYPE_UINT64, addr, sizeof(*addr))',
            ),
            'OSSL_PARAM_uint32': (
                'partial',
                'BSL_PARAM_InitValue(&param, key, BSL_PARAM_TYPE_UINT32, addr, sizeof(*addr))',
            ),
            'OSSL_PARAM_uint64': (
                'partial',
                'BSL_PARAM_InitValue(&param, key, BSL_PARAM_TYPE_UINT64, addr, sizeof(*addr))',
            ),
        }
        for sym, expected_lookup in expected.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_147.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_148_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()

        not_available = {
            'EC_KEY_METHOD_free',
            'EC_KEY_METHOD_get_compute_key',
            'EC_KEY_METHOD_get_init',
            'EC_KEY_METHOD_get_keygen',
            'EC_KEY_METHOD_get_sign',
            'EC_KEY_METHOD_get_verify',
            'EC_KEY_METHOD_new',
            'EC_KEY_METHOD_set_compute_key',
            'EC_KEY_METHOD_set_init',
            'EC_KEY_METHOD_set_keygen',
            'EC_KEY_METHOD_set_sign',
            'EC_KEY_METHOD_set_verify',
            'EC_KEY_OpenSSL',
            'EC_KEY_decoded_from_explicit_params',
            'EC_KEY_get0_engine',
            'EC_KEY_get_default_method',
            'EC_KEY_get_method',
            'EC_KEY_new_method',
            'EC_KEY_precompute_mult',
            'EC_KEY_print',
            'EC_KEY_print_fp',
            'EC_KEY_set_asn1_flag',
            'EC_KEY_set_default_method',
            'EC_KEY_set_method',
        }
        for sym in not_available:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_148.md'
            )

        expected_partial = {
            'EC_KEY_can_sign': ('partial', 'CRYPT_EAL_PkeyGetId'),
            'EC_KEY_check_key': (
                'partial', 'CRYPT_EAL_PkeyPrvCheck / CRYPT_EAL_PkeyPairCheck'
            ),
            'EC_KEY_clear_flags': (
                'partial', 'CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_CLR_FLAG)'
            ),
            'EC_KEY_copy': ('partial', 'CRYPT_EAL_PkeyCopyCtx'),
            'EC_KEY_get_conv_form': (
                'partial', 'CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_GET_ECC_POINT_FORMAT)'
            ),
            'EC_KEY_get_enc_flags': (
                'partial', 'CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_GET_FLAG)'
            ),
            'EC_KEY_get_ex_data': ('partial', 'CRYPT_EAL_PkeyGetExtData'),
            'EC_KEY_get_flags': (
                'partial', 'CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_GET_FLAG)'
            ),
            'EC_KEY_new_by_curve_name_ex': (
                'partial',
                'CRYPT_EAL_ProviderPkeyNewCtx + CRYPT_EAL_PkeySetParaById',
            ),
            'EC_KEY_new_ex': ('partial', 'CRYPT_EAL_ProviderPkeyNewCtx'),
            'EC_KEY_oct2key': (
                'partial',
                'CRYPT_EAL_PkeySetPubEx(CRYPT_PARAM_EC_PUBKEY / CRYPT_PARAM_PKEY_ENCODE_PUBKEY)',
            ),
            'EC_KEY_oct2priv': (
                'partial', 'CRYPT_EAL_PkeySetPrvEx(CRYPT_PARAM_EC_PRVKEY)'
            ),
            'EC_KEY_priv2buf': (
                'partial', 'CRYPT_EAL_PkeyGetPrv / CRYPT_EAL_PkeyGetPrvEx'
            ),
            'EC_KEY_priv2oct': (
                'partial', 'CRYPT_EAL_PkeyGetPrvEx(CRYPT_PARAM_EC_PRVKEY)'
            ),
            'EC_KEY_set_conv_form': (
                'partial', 'CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_SET_ECC_POINT_FORMAT)'
            ),
            'EC_KEY_set_enc_flags': (
                'partial', 'CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_SET_FLAG)'
            ),
            'EC_KEY_set_ex_data': ('partial', 'CRYPT_EAL_PkeySetExtData'),
            'EC_KEY_set_flags': (
                'partial', 'CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_SET_FLAG)'
            ),
            'EC_KEY_set_private_key': (
                'partial', 'CRYPT_EAL_PkeySetPrv / CRYPT_EAL_PkeySetPrvEx'
            ),
            'EC_KEY_set_public_key': (
                'partial', 'CRYPT_EAL_PkeySetPub / CRYPT_EAL_PkeySetPubEx'
            ),
            'EC_KEY_set_public_key_affine_coordinates': (
                'partial', 'CRYPT_EAL_PkeySetPara(CRYPT_EAL_PkeyPara.para.eccPara.x/y)'
            ),
            'EC_KEY_up_ref': ('partial', 'CRYPT_EAL_PkeyUpRef'),
        }
        for sym, expected_lookup in expected_partial.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_148.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_149_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = (
            'EC_GROUP_check', 'EC_GROUP_check_discriminant', 'EC_GROUP_check_named_curve',
            'EC_GROUP_clear_free', 'EC_GROUP_cmp', 'EC_GROUP_copy', 'EC_GROUP_dup',
            'EC_GROUP_get0_cofactor', 'EC_GROUP_get0_field', 'EC_GROUP_get0_generator',
            'EC_GROUP_get0_order', 'EC_GROUP_get0_seed', 'EC_GROUP_get_asn1_flag',
            'EC_GROUP_get_basis_type', 'EC_GROUP_get_cofactor', 'EC_GROUP_get_curve',
            'EC_GROUP_get_curve_GF2m', 'EC_GROUP_get_curve_GFp', 'EC_GROUP_get_degree',
            'EC_GROUP_get_ecparameters', 'EC_GROUP_get_ecpkparameters',
            'EC_GROUP_get_field_type', 'EC_GROUP_get_mont_data', 'EC_GROUP_get_order',
            'EC_GROUP_get_pentanomial_basis', 'EC_GROUP_get_point_conversion_form',
            'EC_GROUP_get_seed_len', 'EC_GROUP_get_trinomial_basis',
            'EC_GROUP_have_precompute_mult', 'EC_GROUP_method_of', 'EC_GROUP_new',
            'EC_GROUP_new_by_curve_name_ex', 'EC_GROUP_new_curve_GF2m',
            'EC_GROUP_new_curve_GFp', 'EC_GROUP_new_from_ecparameters',
            'EC_GROUP_new_from_ecpkparameters', 'EC_GROUP_new_from_params',
            'EC_GROUP_order_bits', 'EC_GROUP_precompute_mult',
            'EC_GROUP_set_asn1_flag', 'EC_GROUP_set_curve', 'EC_GROUP_set_curve_GF2m',
            'EC_GROUP_set_curve_GFp', 'EC_GROUP_set_curve_name',
            'EC_GROUP_set_generator', 'EC_GROUP_set_point_conversion_form',
            'EC_GROUP_set_seed', 'EC_GROUP_to_params',
            'EC_POINT_add', 'EC_POINT_bn2point', 'EC_POINT_clear_free',
            'EC_POINT_cmp', 'EC_POINT_copy', 'EC_POINT_dbl', 'EC_POINT_dup',
            'EC_POINT_free', 'EC_POINT_get_Jprojective_coordinates_GFp',
            'EC_POINT_get_affine_coordinates', 'EC_POINT_get_affine_coordinates_GF2m',
            'EC_POINT_get_affine_coordinates_GFp', 'EC_POINT_hex2point',
            'EC_POINT_invert', 'EC_POINT_is_at_infinity', 'EC_POINT_is_on_curve',
            'EC_POINT_make_affine', 'EC_POINT_method_of', 'EC_POINT_mul',
            'EC_POINT_oct2point', 'EC_POINT_point2bn', 'EC_POINT_point2buf',
            'EC_POINT_point2hex', 'EC_POINT_set_Jprojective_coordinates_GFp',
            'EC_POINT_set_affine_coordinates', 'EC_POINT_set_affine_coordinates_GF2m',
            'EC_POINT_set_affine_coordinates_GFp',
            'EC_POINT_set_compressed_coordinates',
            'EC_POINT_set_compressed_coordinates_GF2m',
            'EC_POINT_set_compressed_coordinates_GFp', 'EC_POINT_set_to_infinity',
        )
        for sym in expected:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_149.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_150_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = (
            'EC_GF2m_simple_method',
            'EC_GFp_mont_method',
            'EC_GFp_nist_method',
            'EC_GFp_simple_method',
            'EC_METHOD_get_field_type',
            'EC_POINTs_make_affine',
            'EC_POINTs_mul',
            'EC_curve_nid2nist',
            'EC_curve_nist2nid',
            'EC_get_builtin_curves',
        )
        for sym in expected:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_150.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_151_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()

        available = {
            'EVP_CIPHER_CTX_copy': ('available', 'CRYPT_EAL_CipherCopyCtx'),
            'EVP_CIPHER_CTX_dup': ('available', 'CRYPT_EAL_CipherDupCtx'),
            'EVP_CIPHER_CTX_get_block_size': (
                'available', 'CRYPT_EAL_CipherCtrl(CRYPT_CTRL_GET_BLOCKSIZE)'
            ),
            'EVP_CIPHER_CTX_reset': ('available', 'CRYPT_EAL_CipherDeinit'),
        }
        for sym, expected_lookup in available.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_151.md'
            )

        partial = {
            'EVP_CIPHER_CTX_get_params': ('partial', 'CRYPT_EAL_CipherCtrl'),
            'EVP_CIPHER_CTX_get_updated_iv': (
                'partial', 'CRYPT_EAL_CipherCtrl(CRYPT_CTRL_GET_IV)'
            ),
            'EVP_CIPHER_CTX_set_params': ('partial', 'CRYPT_EAL_CipherCtrl'),
        }
        for sym, expected_lookup in partial.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_151.md'
            )

        not_available = {
            'EVP_CIPHER_CTX_buf_noconst',
            'EVP_CIPHER_CTX_cipher',
            'EVP_CIPHER_CTX_clear_flags',
            'EVP_CIPHER_CTX_get0_cipher',
            'EVP_CIPHER_CTX_get1_cipher',
            'EVP_CIPHER_CTX_get_app_data',
            'EVP_CIPHER_CTX_get_cipher_data',
            'EVP_CIPHER_CTX_get_iv_length',
            'EVP_CIPHER_CTX_get_key_length',
            'EVP_CIPHER_CTX_get_nid',
            'EVP_CIPHER_CTX_get_num',
            'EVP_CIPHER_CTX_get_original_iv',
            'EVP_CIPHER_CTX_get_tag_length',
            'EVP_CIPHER_CTX_gettable_params',
            'EVP_CIPHER_CTX_is_encrypting',
            'EVP_CIPHER_CTX_iv',
            'EVP_CIPHER_CTX_iv_noconst',
            'EVP_CIPHER_CTX_original_iv',
            'EVP_CIPHER_CTX_rand_key',
            'EVP_CIPHER_CTX_set_app_data',
            'EVP_CIPHER_CTX_set_cipher_data',
            'EVP_CIPHER_CTX_set_flags',
            'EVP_CIPHER_CTX_set_num',
            'EVP_CIPHER_CTX_settable_params',
            'EVP_CIPHER_CTX_test_flags',
        }
        for sym in not_available:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_151.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_152_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()

        partial = {
            'EVP_CIPHER_get_block_size': (
                'partial', 'CRYPT_EAL_CipherGetInfo(CRYPT_INFO_BLOCK_LEN)'
            ),
            'EVP_CIPHER_get_iv_length': (
                'partial', 'CRYPT_EAL_CipherGetInfo(CRYPT_INFO_IV_LEN)'
            ),
            'EVP_CIPHER_get_key_length': (
                'partial', 'CRYPT_EAL_CipherGetInfo(CRYPT_INFO_KEY_LEN)'
            ),
            'EVP_CIPHER_get_params': ('partial', 'CRYPT_EAL_CipherGetInfo'),
        }
        for sym, expected_lookup in partial.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_152.md'
            )

        not_available = {
            'EVP_CIPHER_asn1_to_param',
            'EVP_CIPHER_do_all',
            'EVP_CIPHER_do_all_provided',
            'EVP_CIPHER_do_all_sorted',
            'EVP_CIPHER_fetch',
            'EVP_CIPHER_free',
            'EVP_CIPHER_get0_description',
            'EVP_CIPHER_get0_name',
            'EVP_CIPHER_get0_provider',
            'EVP_CIPHER_get_asn1_iv',
            'EVP_CIPHER_get_flags',
            'EVP_CIPHER_get_mode',
            'EVP_CIPHER_get_nid',
            'EVP_CIPHER_get_type',
            'EVP_CIPHER_gettable_ctx_params',
            'EVP_CIPHER_gettable_params',
            'EVP_CIPHER_impl_ctx_size',
            'EVP_CIPHER_is_a',
            'EVP_CIPHER_meth_dup',
            'EVP_CIPHER_meth_free',
            'EVP_CIPHER_meth_get_cleanup',
            'EVP_CIPHER_meth_get_ctrl',
            'EVP_CIPHER_meth_get_do_cipher',
            'EVP_CIPHER_meth_get_get_asn1_params',
            'EVP_CIPHER_meth_get_init',
            'EVP_CIPHER_meth_get_set_asn1_params',
            'EVP_CIPHER_meth_new',
            'EVP_CIPHER_meth_set_cleanup',
            'EVP_CIPHER_meth_set_ctrl',
            'EVP_CIPHER_meth_set_do_cipher',
            'EVP_CIPHER_meth_set_flags',
            'EVP_CIPHER_meth_set_get_asn1_params',
            'EVP_CIPHER_meth_set_impl_ctx_size',
            'EVP_CIPHER_meth_set_init',
            'EVP_CIPHER_meth_set_iv_length',
            'EVP_CIPHER_meth_set_set_asn1_params',
            'EVP_CIPHER_names_do_all',
            'EVP_CIPHER_param_to_asn1',
            'EVP_CIPHER_set_asn1_iv',
            'EVP_CIPHER_settable_ctx_params',
            'EVP_CIPHER_up_ref',
        }
        for sym in not_available:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_152.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_153_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()

        available = {
            'EVP_MD_CTX_copy': ('available', 'CRYPT_EAL_MdCopyCtx'),
            'EVP_MD_CTX_copy_ex': ('available', 'CRYPT_EAL_MdCopyCtx'),
            'EVP_MD_CTX_dup': ('available', 'CRYPT_EAL_MdDupCtx'),
            'EVP_MD_CTX_reset': ('available', 'CRYPT_EAL_MdDeinit'),
        }
        for sym, expected_lookup in available.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_153.md'
            )

        partial = {
            'EVP_MD_CTX_get0_md': ('partial', 'CRYPT_EAL_MdGetId'),
            'EVP_MD_get_size': ('partial', 'CRYPT_EAL_MdGetDigestSize'),
        }
        for sym, expected_lookup in partial.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_153.md'
            )

        not_available = {
            'EVP_MD_CTX_clear_flags',
            'EVP_MD_CTX_ctrl',
            'EVP_MD_CTX_get0_md_data',
            'EVP_MD_CTX_get1_md',
            'EVP_MD_CTX_get_params',
            'EVP_MD_CTX_get_pkey_ctx',
            'EVP_MD_CTX_gettable_params',
            'EVP_MD_CTX_md',
            'EVP_MD_CTX_set_params',
            'EVP_MD_CTX_set_pkey_ctx',
            'EVP_MD_CTX_set_update_fn',
            'EVP_MD_CTX_settable_params',
            'EVP_MD_CTX_test_flags',
            'EVP_MD_CTX_update_fn',
            'EVP_MD_do_all',
            'EVP_MD_do_all_provided',
            'EVP_MD_do_all_sorted',
            'EVP_MD_fetch',
            'EVP_MD_free',
            'EVP_MD_get0_description',
            'EVP_MD_get0_name',
            'EVP_MD_get0_provider',
            'EVP_MD_get_block_size',
            'EVP_MD_get_flags',
            'EVP_MD_get_params',
            'EVP_MD_get_pkey_type',
            'EVP_MD_get_type',
            'EVP_MD_gettable_ctx_params',
            'EVP_MD_gettable_params',
            'EVP_MD_is_a',
            'EVP_MD_meth_dup',
            'EVP_MD_meth_free',
            'EVP_MD_meth_get_app_datasize',
            'EVP_MD_meth_get_cleanup',
            'EVP_MD_meth_get_copy',
            'EVP_MD_meth_get_ctrl',
            'EVP_MD_meth_get_final',
            'EVP_MD_meth_get_flags',
            'EVP_MD_meth_get_init',
            'EVP_MD_meth_get_input_blocksize',
            'EVP_MD_meth_get_result_size',
            'EVP_MD_meth_get_update',
            'EVP_MD_meth_new',
            'EVP_MD_meth_set_app_datasize',
            'EVP_MD_meth_set_cleanup',
            'EVP_MD_meth_set_copy',
            'EVP_MD_meth_set_ctrl',
            'EVP_MD_meth_set_final',
            'EVP_MD_meth_set_flags',
            'EVP_MD_meth_set_init',
            'EVP_MD_meth_set_input_blocksize',
            'EVP_MD_meth_set_result_size',
            'EVP_MD_meth_set_update',
            'EVP_MD_names_do_all',
            'EVP_MD_settable_ctx_params',
            'EVP_MD_up_ref',
        }
        for sym in not_available:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_153.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_154_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()

        available = {
            'EVP_KDF_CTX_dup': ('available', 'CRYPT_EAL_KdfDupCtx'),
            'EVP_KDF_CTX_free': ('available', 'CRYPT_EAL_KdfFreeCtx'),
            'EVP_KDF_CTX_reset': ('available', 'CRYPT_EAL_KdfDeInitCtx'),
            'EVP_KDF_CTX_set_params': ('available', 'CRYPT_EAL_KdfSetParam'),
            'EVP_KDF_derive': ('available', 'CRYPT_EAL_KdfDerive'),
        }
        for sym, expected_lookup in available.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_154.md'
            )

        partial = {
            'EVP_KDF_CTX_new': (
                'partial',
                'CRYPT_EAL_KdfNewCtx / CRYPT_EAL_ProviderKdfNewCtx',
            ),
        }
        for sym, expected_lookup in partial.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_154.md'
            )

        not_available = {
            'EVP_KDF_CTX_get_kdf_size',
            'EVP_KDF_CTX_get_params',
            'EVP_KDF_CTX_gettable_params',
            'EVP_KDF_CTX_kdf',
            'EVP_KDF_CTX_settable_params',
            'EVP_KDF_do_all_provided',
            'EVP_KDF_fetch',
            'EVP_KDF_free',
            'EVP_KDF_get0_description',
            'EVP_KDF_get0_name',
            'EVP_KDF_get0_provider',
            'EVP_KDF_get_params',
            'EVP_KDF_gettable_ctx_params',
            'EVP_KDF_gettable_params',
            'EVP_KDF_is_a',
            'EVP_KDF_names_do_all',
            'EVP_KDF_settable_ctx_params',
            'EVP_KDF_up_ref',
        }
        for sym in not_available:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_154.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_155_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()

        available = {
            'EVP_MAC_CTX_dup': ('available', 'CRYPT_EAL_MacDupCtx'),
            'EVP_MAC_CTX_free': ('available', 'CRYPT_EAL_MacFreeCtx'),
            'EVP_MAC_CTX_get_mac_size': ('available', 'CRYPT_EAL_GetMacLen'),
            'EVP_MAC_final': ('available', 'CRYPT_EAL_MacFinal'),
            'EVP_MAC_init': ('available', 'CRYPT_EAL_MacInit'),
            'EVP_MAC_update': ('available', 'CRYPT_EAL_MacUpdate'),
        }
        for sym, expected_lookup in available.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_155.md'
            )

        partial = {
            'EVP_MAC_CTX_new': (
                'partial',
                'CRYPT_EAL_MacNewCtx / CRYPT_EAL_ProviderMacNewCtx',
            ),
            'EVP_MAC_CTX_set_params': ('partial', 'CRYPT_EAL_MacSetParam'),
        }
        for sym, expected_lookup in partial.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_155.md'
            )

        not_available = {
            'EVP_MAC_CTX_get0_mac',
            'EVP_MAC_CTX_get_block_size',
            'EVP_MAC_CTX_get_params',
            'EVP_MAC_CTX_gettable_params',
            'EVP_MAC_CTX_settable_params',
            'EVP_MAC_do_all_provided',
            'EVP_MAC_fetch',
            'EVP_MAC_finalXOF',
            'EVP_MAC_free',
            'EVP_MAC_get0_description',
            'EVP_MAC_get0_name',
            'EVP_MAC_get0_provider',
            'EVP_MAC_get_params',
            'EVP_MAC_gettable_ctx_params',
            'EVP_MAC_gettable_params',
            'EVP_MAC_is_a',
            'EVP_MAC_names_do_all',
            'EVP_MAC_settable_ctx_params',
            'EVP_MAC_up_ref',
        }
        for sym in not_available:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_155.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_156_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = (
            'EVP_KEYMGMT_do_all_provided',
            'EVP_KEYMGMT_fetch',
            'EVP_KEYMGMT_free',
            'EVP_KEYMGMT_gen_gettable_params',
            'EVP_KEYMGMT_gen_settable_params',
            'EVP_KEYMGMT_get0_description',
            'EVP_KEYMGMT_get0_name',
            'EVP_KEYMGMT_get0_provider',
            'EVP_KEYMGMT_gettable_params',
            'EVP_KEYMGMT_is_a',
            'EVP_KEYMGMT_names_do_all',
            'EVP_KEYMGMT_settable_params',
            'EVP_KEYMGMT_up_ref',
            'EVP_KEYEXCH_do_all_provided',
            'EVP_KEYEXCH_fetch',
            'EVP_KEYEXCH_free',
            'EVP_KEYEXCH_get0_description',
            'EVP_KEYEXCH_get0_name',
            'EVP_KEYEXCH_get0_provider',
            'EVP_KEYEXCH_gettable_ctx_params',
            'EVP_KEYEXCH_is_a',
            'EVP_KEYEXCH_names_do_all',
            'EVP_KEYEXCH_settable_ctx_params',
            'EVP_KEYEXCH_up_ref',
            'EVP_KEM_do_all_provided',
            'EVP_KEM_fetch',
            'EVP_KEM_free',
            'EVP_KEM_get0_description',
            'EVP_KEM_get0_name',
            'EVP_KEM_get0_provider',
            'EVP_KEM_gettable_ctx_params',
            'EVP_KEM_is_a',
            'EVP_KEM_names_do_all',
            'EVP_KEM_settable_ctx_params',
            'EVP_KEM_up_ref',
        )
        for sym in expected:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_156.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_157_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = (
            'EVP_SIGNATURE_do_all_provided',
            'EVP_SIGNATURE_fetch',
            'EVP_SIGNATURE_free',
            'EVP_SIGNATURE_get0_description',
            'EVP_SIGNATURE_get0_name',
            'EVP_SIGNATURE_get0_provider',
            'EVP_SIGNATURE_gettable_ctx_params',
            'EVP_SIGNATURE_is_a',
            'EVP_SIGNATURE_names_do_all',
            'EVP_SIGNATURE_settable_ctx_params',
            'EVP_SIGNATURE_up_ref',
            'EVP_ASYM_CIPHER_do_all_provided',
            'EVP_ASYM_CIPHER_fetch',
            'EVP_ASYM_CIPHER_free',
            'EVP_ASYM_CIPHER_get0_description',
            'EVP_ASYM_CIPHER_get0_name',
            'EVP_ASYM_CIPHER_get0_provider',
            'EVP_ASYM_CIPHER_gettable_ctx_params',
            'EVP_ASYM_CIPHER_is_a',
            'EVP_ASYM_CIPHER_names_do_all',
            'EVP_ASYM_CIPHER_settable_ctx_params',
            'EVP_ASYM_CIPHER_up_ref',
        )
        for sym in expected:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_157.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_158_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()

        available = {
            'EVP_PKEY_CTX_dup': ('available', 'CRYPT_EAL_PkeyDupCtx'),
            'EVP_PKEY_CTX_get_data': ('available', 'CRYPT_EAL_PkeyGetExtData'),
            'EVP_PKEY_CTX_set_data': ('available', 'CRYPT_EAL_PkeySetExtData'),
            'EVP_PKEY_CTX_get_app_data': ('available', 'CRYPT_EAL_PkeyGetExtData'),
            'EVP_PKEY_CTX_set_app_data': ('available', 'CRYPT_EAL_PkeySetExtData'),
        }
        for sym, expected_lookup in available.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_158.md'
            )

        not_available = {
            'EVP_PKEY_CTX_get0_pkey',
            'EVP_PKEY_CTX_get0_peerkey',
            'EVP_PKEY_CTX_get0_libctx',
            'EVP_PKEY_CTX_get0_propq',
            'EVP_PKEY_CTX_get0_provider',
            'EVP_PKEY_CTX_get_operation',
            'EVP_PKEY_CTX_new_from_name',
            'EVP_PKEY_CTX_new_from_pkey',
            'EVP_PKEY_CTX_is_a',
        }
        for sym in not_available:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_158.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_159_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()

        available = {
            'EVP_PKEY_decapsulate': ('available', 'CRYPT_EAL_PkeyDecaps'),
            'EVP_PKEY_decapsulate_init': ('available', 'CRYPT_EAL_PkeyDecapsInit'),
            'EVP_PKEY_encapsulate': ('available', 'CRYPT_EAL_PkeyEncaps'),
            'EVP_PKEY_encapsulate_init': ('available', 'CRYPT_EAL_PkeyEncapsInit'),
        }
        for sym, expected_lookup in available.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_159.md'
            )

        partial = {
            'EVP_PKEY_Q_keygen': (
                'partial',
                'CRYPT_EAL_PkeyNewCtx / CRYPT_EAL_ProviderPkeyNewCtx + '
                'CRYPT_EAL_PkeySetParaById|Ex + CRYPT_EAL_PkeyGen',
            ),
            'EVP_PKEY_check': ('partial', 'CRYPT_EAL_PkeyPrvCheck'),
            'EVP_PKEY_cmp': ('partial', 'CRYPT_EAL_PkeyCmp'),
            'EVP_PKEY_cmp_parameters': ('partial', 'CRYPT_EAL_PkeyCmp'),
            'EVP_PKEY_copy_parameters': (
                'partial',
                'CRYPT_EAL_PkeyGetPara + CRYPT_EAL_PkeySetPara',
            ),
            'EVP_PKEY_decrypt': ('partial', 'CRYPT_EAL_PkeyDecrypt'),
            'EVP_PKEY_derive_init_ex': (
                'partial',
                'CRYPT_EAL_PkeyNewCtx + CRYPT_EAL_PkeySetParaById|Ex + '
                'CRYPT_EAL_PkeyCtrl',
            ),
            'EVP_PKEY_derive_set_peer': (
                'partial',
                'CRYPT_EAL_PkeyComputeShareKey',
            ),
            'EVP_PKEY_dup': ('partial', 'CRYPT_EAL_PkeyDupCtx'),
            'EVP_PKEY_encrypt': ('partial', 'CRYPT_EAL_PkeyEncrypt'),
            'EVP_PKEY_export': (
                'partial',
                'CRYPT_EAL_ProviderEncodeBuffKey / CRYPT_EAL_PkeyGetPubEx / '
                'CRYPT_EAL_PkeyGetPrvEx',
            ),
            'EVP_PKEY_fromdata': (
                'partial',
                'CRYPT_EAL_PkeySetParaEx / CRYPT_EAL_PkeySetPubEx / '
                'CRYPT_EAL_PkeySetPrvEx',
            ),
            'EVP_PKEY_fromdata_init': (
                'partial',
                'CRYPT_EAL_PkeyNewCtx / CRYPT_EAL_ProviderPkeyNewCtx + '
                'CRYPT_EAL_PkeySetParaEx',
            ),
            'EVP_PKEY_generate': ('partial', 'CRYPT_EAL_PkeyGen'),
            'EVP_PKEY_get0_DH': (
                'partial',
                'CRYPT_EAL_PkeyGetPub / CRYPT_EAL_PkeyGetPrv',
            ),
            'EVP_PKEY_get0_DSA': (
                'partial',
                'CRYPT_EAL_PkeyGetPub / CRYPT_EAL_PkeyGetPrv',
            ),
            'EVP_PKEY_get0_EC_KEY': (
                'partial',
                'CRYPT_EAL_PkeyGetPub / CRYPT_EAL_PkeyGetPrv',
            ),
            'EVP_PKEY_get0_RSA': (
                'partial',
                'CRYPT_EAL_PkeyGetPub / CRYPT_EAL_PkeyGetPrv',
            ),
            'EVP_PKEY_get1_DH': (
                'partial',
                'CRYPT_EAL_PkeyGetPub / CRYPT_EAL_PkeyGetPrv',
            ),
            'EVP_PKEY_get1_DSA': (
                'partial',
                'CRYPT_EAL_PkeyGetPub / CRYPT_EAL_PkeyGetPrv',
            ),
            'EVP_PKEY_get1_EC_KEY': (
                'partial',
                'CRYPT_EAL_PkeyGetPub / CRYPT_EAL_PkeyGetPrv',
            ),
            'EVP_PKEY_get1_RSA': (
                'partial',
                'CRYPT_EAL_PkeyGetPub / CRYPT_EAL_PkeyGetPrv',
            ),
            'EVP_PKEY_get1_encoded_public_key': (
                'partial',
                'CRYPT_EAL_PkeyGetPub / CRYPT_EAL_PkeyGetPrv',
            ),
            'EVP_PKEY_get_base_id': ('partial', 'CRYPT_EAL_PkeyGetId'),
            'EVP_PKEY_get_bits': ('partial', 'CRYPT_EAL_PkeyGetKeyBits'),
            'EVP_PKEY_get_ec_point_conv_form': (
                'partial',
                'CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_GET_ECC_POINT_FORMAT)',
            ),
            'EVP_PKEY_get_ex_data': ('partial', 'CRYPT_EAL_PkeyGetExtData'),
            'EVP_PKEY_get_group_name': (
                'partial',
                'CRYPT_EAL_PkeyGetParaId + BSL_OBJ_GetOID',
            ),
            'EVP_PKEY_get_id': ('partial', 'CRYPT_EAL_PkeyGetId'),
            'EVP_PKEY_get_security_bits': (
                'partial',
                'CRYPT_EAL_PkeyGetSecurityBits',
            ),
            'EVP_PKEY_get_size': ('partial', 'CRYPT_EAL_PkeyGetKeyLen'),
            'EVP_PKEY_keygen': ('partial', 'CRYPT_EAL_PkeyGen'),
            'EVP_PKEY_keygen_init': ('partial', 'CRYPT_EAL_PkeySetPara'),
            'EVP_PKEY_pairwise_check': (
                'partial',
                'CRYPT_EAL_PkeyPairCheck',
            ),
            'EVP_PKEY_parameters_eq': (
                'partial',
                'CRYPT_EAL_PkeyGetPara + CRYPT_EAL_PkeySetPara + '
                'CRYPT_EAL_PkeyCmp',
            ),
            'EVP_PKEY_paramgen': (
                'partial',
                'CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_GEN_PARA)',
            ),
            'EVP_PKEY_paramgen_init': ('partial', 'CRYPT_EAL_PkeySetPara'),
            'EVP_PKEY_private_check': (
                'partial',
                'CRYPT_EAL_PkeyPrvCheck',
            ),
            'EVP_PKEY_set1_DH': (
                'partial',
                'CRYPT_EAL_PkeySetPub / CRYPT_EAL_PkeySetPrv',
            ),
            'EVP_PKEY_set1_DSA': (
                'partial',
                'CRYPT_EAL_PkeySetPub / CRYPT_EAL_PkeySetPrv',
            ),
            'EVP_PKEY_set1_EC_KEY': (
                'partial',
                'CRYPT_EAL_PkeySetPub / CRYPT_EAL_PkeySetPrv',
            ),
            'EVP_PKEY_set1_encoded_public_key': (
                'partial',
                'CRYPT_EAL_PkeySetPub / CRYPT_EAL_PkeySetPrv',
            ),
            'EVP_PKEY_set_ex_data': ('partial', 'CRYPT_EAL_PkeySetExtData'),
            'EVP_PKEY_sign': ('partial', 'CRYPT_EAL_PkeySignData'),
            'EVP_PKEY_sign_init_ex': (
                'partial',
                'CRYPT_EAL_PkeyCtrl + CRYPT_EAL_PkeySign|SignData',
            ),
            'EVP_PKEY_type': ('partial', 'CRYPT_EAL_PkeyGetId'),
            'EVP_PKEY_up_ref': ('partial', 'CRYPT_EAL_PkeyUpRef'),
            'EVP_PKEY_verify_init_ex': (
                'partial',
                'CRYPT_EAL_PkeyCtrl + CRYPT_EAL_PkeyVerify|VerifyData',
            ),
            'EVP_PKEY_verify_recover': (
                'partial',
                'CRYPT_EAL_PkeyVerifyRecover',
            ),
            'EVP_PKEY_verify_recover_init_ex': (
                'partial',
                'CRYPT_EAL_PkeyCtrl + CRYPT_EAL_PkeyVerifyRecover',
            ),
        }
        for sym, expected_lookup in partial.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_159.md'
            )

        not_available = {
            'EVP_PKEY_add1_attr',
            'EVP_PKEY_add1_attr_by_NID',
            'EVP_PKEY_add1_attr_by_OBJ',
            'EVP_PKEY_add1_attr_by_txt',
            'EVP_PKEY_asn1_add0',
            'EVP_PKEY_asn1_add_alias',
            'EVP_PKEY_asn1_copy',
            'EVP_PKEY_asn1_find',
            'EVP_PKEY_asn1_find_str',
            'EVP_PKEY_asn1_free',
            'EVP_PKEY_asn1_get0',
            'EVP_PKEY_asn1_get0_info',
            'EVP_PKEY_asn1_get_count',
            'EVP_PKEY_asn1_new',
            'EVP_PKEY_asn1_set_check',
            'EVP_PKEY_asn1_set_ctrl',
            'EVP_PKEY_asn1_set_free',
            'EVP_PKEY_asn1_set_get_priv_key',
            'EVP_PKEY_asn1_set_get_pub_key',
            'EVP_PKEY_asn1_set_item',
            'EVP_PKEY_asn1_set_param',
            'EVP_PKEY_asn1_set_param_check',
            'EVP_PKEY_asn1_set_private',
            'EVP_PKEY_asn1_set_public',
            'EVP_PKEY_asn1_set_public_check',
            'EVP_PKEY_asn1_set_security_bits',
            'EVP_PKEY_asn1_set_set_priv_key',
            'EVP_PKEY_asn1_set_set_pub_key',
            'EVP_PKEY_asn1_set_siginf',
            'EVP_PKEY_assign',
            'EVP_PKEY_auth_decapsulate_init',
            'EVP_PKEY_auth_encapsulate_init',
            'EVP_PKEY_can_sign',
            'EVP_PKEY_decrypt_init_ex',
            'EVP_PKEY_decrypt_old',
            'EVP_PKEY_delete_attr',
            'EVP_PKEY_derive_set_peer_ex',
            'EVP_PKEY_digestsign_supports_digest',
            'EVP_PKEY_encrypt_init_ex',
            'EVP_PKEY_encrypt_old',
            'EVP_PKEY_eq',
            'EVP_PKEY_fromdata_settable',
            'EVP_PKEY_get0',
            'EVP_PKEY_get0_asn1',
            'EVP_PKEY_get0_description',
            'EVP_PKEY_get0_engine',
            'EVP_PKEY_get0_hmac',
            'EVP_PKEY_get0_poly1305',
            'EVP_PKEY_get0_provider',
            'EVP_PKEY_get0_siphash',
            'EVP_PKEY_get0_type_name',
            'EVP_PKEY_get_attr',
            'EVP_PKEY_get_attr_by_NID',
            'EVP_PKEY_get_attr_by_OBJ',
            'EVP_PKEY_get_attr_count',
            'EVP_PKEY_get_default_digest_name',
            'EVP_PKEY_get_default_digest_nid',
            'EVP_PKEY_get_field_type',
            'EVP_PKEY_get_int_param',
            'EVP_PKEY_get_octet_string_param',
            'EVP_PKEY_get_params',
            'EVP_PKEY_get_size_t_param',
            'EVP_PKEY_get_utf8_string_param',
            'EVP_PKEY_gettable_params',
            'EVP_PKEY_is_a',
            'EVP_PKEY_meth_add0',
            'EVP_PKEY_meth_copy',
            'EVP_PKEY_meth_find',
            'EVP_PKEY_meth_free',
            'EVP_PKEY_meth_get0',
            'EVP_PKEY_meth_get0_info',
            'EVP_PKEY_meth_get_check',
            'EVP_PKEY_meth_get_cleanup',
            'EVP_PKEY_meth_get_copy',
            'EVP_PKEY_meth_get_count',
            'EVP_PKEY_meth_get_ctrl',
            'EVP_PKEY_meth_get_decrypt',
            'EVP_PKEY_meth_get_derive',
            'EVP_PKEY_meth_get_digest_custom',
            'EVP_PKEY_meth_get_digestsign',
            'EVP_PKEY_meth_get_digestverify',
            'EVP_PKEY_meth_get_encrypt',
            'EVP_PKEY_meth_get_init',
            'EVP_PKEY_meth_get_keygen',
            'EVP_PKEY_meth_get_param_check',
            'EVP_PKEY_meth_get_paramgen',
            'EVP_PKEY_meth_get_public_check',
            'EVP_PKEY_meth_get_sign',
            'EVP_PKEY_meth_get_signctx',
            'EVP_PKEY_meth_get_verify',
            'EVP_PKEY_meth_get_verify_recover',
            'EVP_PKEY_meth_get_verifyctx',
            'EVP_PKEY_meth_new',
            'EVP_PKEY_meth_remove',
            'EVP_PKEY_meth_set_check',
            'EVP_PKEY_meth_set_cleanup',
            'EVP_PKEY_meth_set_copy',
            'EVP_PKEY_meth_set_ctrl',
            'EVP_PKEY_meth_set_decrypt',
            'EVP_PKEY_meth_set_derive',
            'EVP_PKEY_meth_set_digest_custom',
            'EVP_PKEY_meth_set_digestsign',
            'EVP_PKEY_meth_set_digestverify',
            'EVP_PKEY_meth_set_encrypt',
            'EVP_PKEY_meth_set_init',
            'EVP_PKEY_meth_set_keygen',
            'EVP_PKEY_meth_set_param_check',
            'EVP_PKEY_meth_set_paramgen',
            'EVP_PKEY_meth_set_public_check',
            'EVP_PKEY_meth_set_sign',
            'EVP_PKEY_meth_set_signctx',
            'EVP_PKEY_meth_set_verify',
            'EVP_PKEY_meth_set_verify_recover',
            'EVP_PKEY_meth_set_verifyctx',
            'EVP_PKEY_missing_parameters',
            'EVP_PKEY_new_CMAC_key',
            'EVP_PKEY_new_mac_key',
            'EVP_PKEY_param_check',
            'EVP_PKEY_param_check_quick',
            'EVP_PKEY_print_params',
            'EVP_PKEY_print_params_fp',
            'EVP_PKEY_print_private',
            'EVP_PKEY_print_private_fp',
            'EVP_PKEY_print_public',
            'EVP_PKEY_print_public_fp',
            'EVP_PKEY_public_check',
            'EVP_PKEY_public_check_quick',
            'EVP_PKEY_save_parameters',
            'EVP_PKEY_set1_engine',
            'EVP_PKEY_set_bn_param',
            'EVP_PKEY_set_int_param',
            'EVP_PKEY_set_octet_string_param',
            'EVP_PKEY_set_params',
            'EVP_PKEY_set_size_t_param',
            'EVP_PKEY_set_type',
            'EVP_PKEY_set_type_by_keymgmt',
            'EVP_PKEY_set_type_str',
            'EVP_PKEY_set_utf8_string_param',
            'EVP_PKEY_settable_params',
            'EVP_PKEY_todata',
            'EVP_PKEY_type_names_do_all',
        }
        for sym in not_available:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_159.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_160_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()

        expected = [
            sym for sym, meta in mappings.items()
            if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_160.md'
        ]
        assert len(expected) == 151
        assert all(sym.startswith('OSSL_CMP_') for sym in expected)

        for sym in expected:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_161_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()

        expected = [
            sym for sym, meta in mappings.items()
            if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_161.md'
        ]
        assert len(expected) == 108
        assert all(sym.startswith('X509_STORE') for sym in expected)

        available = {
            'X509_STORE_CTX_free': ('available', 'HITLS_X509_StoreCtxFree'),
            'X509_STORE_CTX_new': ('available', 'HITLS_X509_StoreCtxNew'),
            'X509_STORE_CTX_verify': ('available', 'HITLS_X509_CertVerify'),
            'X509_STORE_CTX_set_verify_cb': (
                'available',
                'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_SET_VERIFY_CB)',
            ),
            'X509_STORE_CTX_get_verify_cb': (
                'available',
                'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_GET_VERIFY_CB)',
            ),
            'X509_STORE_CTX_set_flags': (
                'available',
                'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_SET_PARAM_FLAGS)',
            ),
            'X509_STORE_CTX_set_depth': (
                'available',
                'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_SET_PARAM_DEPTH)',
            ),
            'X509_STORE_CTX_set_time': (
                'available',
                'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_SET_TIME)',
            ),
            'X509_STORE_CTX_set_error': (
                'available',
                'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_SET_ERROR)',
            ),
            'X509_STORE_CTX_get_error_depth': (
                'available',
                'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_GET_CUR_DEPTH)',
            ),
            'X509_STORE_CTX_set_error_depth': (
                'available',
                'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_SET_CUR_DEPTH)',
            ),
            'X509_STORE_CTX_get_current_cert': (
                'available',
                'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_GET_CUR_CERT)',
            ),
            'X509_STORE_CTX_get0_chain': (
                'available',
                'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_GET_CERT_CHAIN)',
            ),
            'X509_STORE_CTX_set_ex_data': (
                'available',
                'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_SET_USR_DATA)',
            ),
            'X509_STORE_CTX_set_purpose': (
                'available',
                'HITLS_X509_StoreCtxCtrl(HITLS_X509_STORECTX_SET_PURPOSE)',
            ),
        }
        for sym, expected_lookup in available.items():
            assert self.compat.lookup(sym) == expected_lookup
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_161.md'
            )

        partial = {
            'X509_STORE_CTX_cleanup',
            'X509_STORE_CTX_get0_untrusted',
            'X509_STORE_CTX_get1_chain',
            'X509_STORE_CTX_init',
            'X509_STORE_CTX_init_rpk',
            'X509_STORE_CTX_new_ex',
            'X509_STORE_CTX_set0_crls',
            'X509_STORE_CTX_set0_untrusted',
            'X509_STORE_add_crl',
            'X509_STORE_load_path',
            'X509_STORE_set1_param',
            'X509_STORE_set_default_paths',
            'X509_STORE_set_default_paths_ex',
            'X509_STORE_set_depth',
            'X509_STORE_set_flags',
            'X509_STORE_set_purpose',
            'X509_STORE_set_verify_cb',
            'X509_STORE_get_verify_cb',
            'X509_STORE_up_ref',
        }
        for sym in partial:
            status, _ = self.compat.lookup(sym)
            assert status == 'partial'
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_161.md'
            )

        statuses = {mappings[sym]['status'] for sym in expected}
        assert statuses == {'available', 'partial', 'not_available'}
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 15
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 19
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 74

    def test_batch_162_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()

        expected = [
            sym for sym, meta in mappings.items()
            if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_162.md'
        ]
        assert len(expected) == 94
        assert all(sym.startswith('EVP_PKEY_CTX_') for sym in expected)

        partial = {
            'EVP_PKEY_CTX_ctrl',
            'EVP_PKEY_CTX_get0_dh_kdf_oid',
            'EVP_PKEY_CTX_get0_dh_kdf_ukm',
            'EVP_PKEY_CTX_get0_ecdh_kdf_ukm',
            'EVP_PKEY_CTX_get0_rsa_oaep_label',
            'EVP_PKEY_CTX_get1_id',
            'EVP_PKEY_CTX_get1_id_len',
            'EVP_PKEY_CTX_get_cb',
            'EVP_PKEY_CTX_get_dh_kdf_md',
            'EVP_PKEY_CTX_get_dh_kdf_outlen',
            'EVP_PKEY_CTX_get_dh_kdf_type',
            'EVP_PKEY_CTX_get_ecdh_cofactor_mode',
            'EVP_PKEY_CTX_get_ecdh_kdf_md',
            'EVP_PKEY_CTX_get_ecdh_kdf_outlen',
            'EVP_PKEY_CTX_get_ecdh_kdf_type',
            'EVP_PKEY_CTX_get_group_name',
            'EVP_PKEY_CTX_get_keygen_info',
            'EVP_PKEY_CTX_get_params',
            'EVP_PKEY_CTX_get_rsa_mgf1_md',
            'EVP_PKEY_CTX_get_rsa_mgf1_md_name',
            'EVP_PKEY_CTX_get_rsa_oaep_md',
            'EVP_PKEY_CTX_get_rsa_oaep_md_name',
            'EVP_PKEY_CTX_get_rsa_padding',
            'EVP_PKEY_CTX_get_rsa_pss_saltlen',
            'EVP_PKEY_CTX_get_signature_md',
            'EVP_PKEY_CTX_gettable_params',
            'EVP_PKEY_CTX_set0_dh_kdf_oid',
            'EVP_PKEY_CTX_set0_dh_kdf_ukm',
            'EVP_PKEY_CTX_set0_ecdh_kdf_ukm',
            'EVP_PKEY_CTX_set0_keygen_info',
            'EVP_PKEY_CTX_set0_rsa_oaep_label',
            'EVP_PKEY_CTX_set1_id',
            'EVP_PKEY_CTX_set1_pbe_pass',
            'EVP_PKEY_CTX_set1_rsa_keygen_pubexp',
            'EVP_PKEY_CTX_set1_scrypt_salt',
            'EVP_PKEY_CTX_set1_tls1_prf_secret',
            'EVP_PKEY_CTX_set_cb',
            'EVP_PKEY_CTX_set_dh_kdf_md',
            'EVP_PKEY_CTX_set_dh_kdf_outlen',
            'EVP_PKEY_CTX_set_dh_kdf_type',
            'EVP_PKEY_CTX_set_dh_nid',
            'EVP_PKEY_CTX_set_dh_pad',
            'EVP_PKEY_CTX_set_dh_paramgen_generator',
            'EVP_PKEY_CTX_set_dh_paramgen_gindex',
            'EVP_PKEY_CTX_set_dh_paramgen_prime_len',
            'EVP_PKEY_CTX_set_dh_paramgen_seed',
            'EVP_PKEY_CTX_set_dh_paramgen_subprime_len',
            'EVP_PKEY_CTX_set_dh_paramgen_type',
            'EVP_PKEY_CTX_set_dh_rfc5114',
            'EVP_PKEY_CTX_set_dhx_rfc5114',
            'EVP_PKEY_CTX_set_dsa_paramgen_bits',
            'EVP_PKEY_CTX_set_dsa_paramgen_gindex',
            'EVP_PKEY_CTX_set_dsa_paramgen_md',
            'EVP_PKEY_CTX_set_dsa_paramgen_md_props',
            'EVP_PKEY_CTX_set_dsa_paramgen_q_bits',
            'EVP_PKEY_CTX_set_dsa_paramgen_seed',
            'EVP_PKEY_CTX_set_dsa_paramgen_type',
            'EVP_PKEY_CTX_set_ec_param_enc',
            'EVP_PKEY_CTX_set_ec_paramgen_curve_nid',
            'EVP_PKEY_CTX_set_ecdh_cofactor_mode',
            'EVP_PKEY_CTX_set_ecdh_kdf_md',
            'EVP_PKEY_CTX_set_ecdh_kdf_outlen',
            'EVP_PKEY_CTX_set_ecdh_kdf_type',
            'EVP_PKEY_CTX_set_group_name',
            'EVP_PKEY_CTX_set_hkdf_mode',
            'EVP_PKEY_CTX_set_kem_op',
            'EVP_PKEY_CTX_set_mac_key',
            'EVP_PKEY_CTX_set_params',
            'EVP_PKEY_CTX_set_rsa_keygen_bits',
            'EVP_PKEY_CTX_set_rsa_keygen_primes',
            'EVP_PKEY_CTX_set_rsa_keygen_pubexp',
            'EVP_PKEY_CTX_set_rsa_mgf1_md',
            'EVP_PKEY_CTX_set_rsa_mgf1_md_name',
            'EVP_PKEY_CTX_set_rsa_oaep_md',
            'EVP_PKEY_CTX_set_rsa_oaep_md_name',
            'EVP_PKEY_CTX_set_rsa_pss_keygen_md',
            'EVP_PKEY_CTX_set_rsa_pss_keygen_md_name',
            'EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md',
            'EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name',
            'EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen',
            'EVP_PKEY_CTX_set_rsa_pss_saltlen',
            'EVP_PKEY_CTX_set_scrypt_N',
            'EVP_PKEY_CTX_set_scrypt_maxmem_bytes',
            'EVP_PKEY_CTX_set_scrypt_p',
            'EVP_PKEY_CTX_set_scrypt_r',
            'EVP_PKEY_CTX_set_signature_md',
            'EVP_PKEY_CTX_set_tls1_prf_md',
            'EVP_PKEY_CTX_settable_params',
        }
        for sym in partial:
            status, _ = self.compat.lookup(sym)
            assert status == 'partial'
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_162.md'
            )

        not_available = {
            'EVP_PKEY_CTX_add1_tls1_prf_seed',
            'EVP_PKEY_CTX_ctrl_str',
            'EVP_PKEY_CTX_ctrl_uint64',
            'EVP_PKEY_CTX_hex2ctrl',
            'EVP_PKEY_CTX_md',
            'EVP_PKEY_CTX_str2ctrl',
        }
        for sym in not_available:
            assert self.compat.lookup(sym) == ('not_available', None)
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_162.md'
            )

        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 88
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 6

    def test_batch_163_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()

        expected = [
            sym for sym, meta in mappings.items()
            if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_163.md'
        ]
        assert len(expected) == 76
        assert all(sym.startswith('OSSL_PARAM') for sym in expected)

        for sym in expected:
            status, _ = self.compat.lookup(sym)
            assert status == 'partial'
            assert mappings[sym]['analysis_doc'] == (
                'docs/hitls-compat/hitls_compat_validation_batch_163.md'
            )
            assert os.path.exists(os.path.join(
                os.path.dirname(__file__), '..', mappings[sym]['analysis_doc']
            ))

    def test_batch_164_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_164.md']
        assert len(expected) == 26
        assert all(sym.startswith('OSSL_STORE_INFO_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_165_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_165.md']
        assert len(expected) == 22
        assert all(sym.startswith('OSSL_STORE_LOADER_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_166_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_166.md']
        assert len(expected) == 11
        assert all(sym.startswith('OSSL_STORE_SEARCH_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_167_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_167.md']
        assert len(expected) == 13
        assert all(sym.startswith('OSSL_STORE_') and not sym.startswith('OSSL_STORE_INFO_')
                   and not sym.startswith('OSSL_STORE_LOADER_')
                   and not sym.startswith('OSSL_STORE_SEARCH_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_168_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_168.md']
        assert len(expected) == 3
        assert set(expected) == {
            'OSSL_STORE_do_all_loaders',
            'OSSL_STORE_register_loader',
            'OSSL_STORE_unregister_loader',
        }
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_169_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_169.md']
        assert len(expected) == 19
        assert all(
            sym.startswith('OSSL_CRMF_ATTRIBUTETYPEANDVALUE_')
            or sym.startswith('OSSL_CRMF_CERTID_')
            or sym.startswith('OSSL_CRMF_CERTTEMPLATE_')
            for sym in expected
        )
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_170_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_170.md']
        assert len(expected) == 13
        assert all(
            sym.startswith('OSSL_CRMF_ENCRYPTEDVALUE_')
            or sym.startswith('OSSL_CRMF_PBMPARAMETER_')
            or sym.startswith('OSSL_CRMF_PKIPUBLICATIONINFO_')
            or sym.startswith('OSSL_CRMF_SINGLEPUBINFO_')
            for sym in expected
        )
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_171_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_171.md']
        assert len(expected) == 6
        assert all(
            sym.startswith('OSSL_CRMF_MSGS_') or sym in {'OSSL_CRMF_pbm_new', 'OSSL_CRMF_pbmp_new'}
            for sym in expected
        )
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_172_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_172.md']
        assert len(expected) == 15
        assert all(
            sym.startswith('OSSL_CRMF_MSG_get0_') or sym.startswith('OSSL_CRMF_MSG_set1_')
            for sym in expected
        )
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_173_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_173.md']
        assert len(expected) == 13
        assert all(sym.startswith('OSSL_CRMF_MSG_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_174_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_174.md']
        assert len(expected) == 65
        assert all(sym.startswith('PEM_write_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 38
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 27

    def test_batch_175_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_175.md']
        assert len(expected) == 54
        assert all(sym.startswith('PEM_read_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 30
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 24

    def test_batch_176_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_176.md']
        assert len(expected) == 41
        assert all(sym.startswith('OSSL_DECODER_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_177_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_177.md']
        assert len(expected) == 38
        assert all(sym.startswith('OSSL_ENCODER_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_178_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_178.md']
        assert len(expected) == 41
        assert all(sym.startswith('ENGINE_get_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_179_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_179.md']
        assert len(expected) == 33
        assert all(sym.startswith('ENGINE_set_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_180_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_180.md']
        assert len(expected) == 33
        assert all(sym.startswith('RSA_meth_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_181_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_181.md']
        assert len(expected) == 27
        assert all(sym.startswith('DSA_meth_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_182_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_182.md']
        assert len(expected) == 30
        assert all(sym.startswith('EVP_RAND_') for sym in expected)
        assert all(self.compat.lookup(sym)[0] == 'partial' for sym in expected)

    def test_batch_183_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_183.md']
        assert len(expected) == 24
        assert all(sym.startswith('OPENSSL_sk_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 19
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 5

    def test_batch_184_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_184.md']
        assert len(expected) == 18
        assert all(sym.startswith('OSSL_PROVIDER_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 10
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 8

    def test_batch_185_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_185.md']
        assert len(expected) == 17
        assert all(sym.startswith('UI_method_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 8
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 9

    def test_batch_186_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_186.md']
        assert len(expected) == 11
        assert all(sym.startswith('OPENSSL_LH_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 11

    def test_batch_187_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_187.md']
        assert len(expected) == 20
        assert all(sym.startswith('ENGINE_register_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_188_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_188.md']
        assert len(expected) == 21
        assert all(sym.startswith('DH_meth_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_189_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_189.md']
        assert len(expected) == 32
        assert all(sym.startswith('ERR_load_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 30
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 2

    def test_batch_190_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_190.md']
        assert len(expected) == 23
        assert all(sym.startswith('OSSL_HTTP_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_191_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_191.md']
        assert len(expected) == 20
        assert all(sym.startswith('OSSL_HPKE_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_192_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_192.md']
        assert len(expected) == 37
        assert all(sym.startswith('X509_LOOKUP_') for sym in expected)
        assert all(self.compat.lookup(sym) == ('not_available', None) for sym in expected)

    def test_batch_193_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_193.md']
        assert len(expected) == 55
        assert all(sym.startswith('SSL_CTX_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 16
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 14
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 25

    def test_batch_194_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_194.md']
        assert len(expected) == 36
        assert all(sym.startswith('SSL_get_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 4
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 6
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 26

    def test_batch_195_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_195.md']
        assert len(expected) == 36
        assert all(sym.startswith('SSL_set_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 17
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 6
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 13

    def test_batch_196_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_196.md']
        assert len(expected) == 38
        assert all(sym.startswith('X509_VERIFY_PARAM_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 18
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 20

    def test_batch_197_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_197.md']
        assert len(expected) == 52
        assert all(sym.startswith('X509_CRL') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 2
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 22
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 28

    def test_batch_198_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_198.md']
        assert len(expected) == 18
        assert all(sym.startswith('X509_REVOKED') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 2
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 5
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 11

    def test_batch_199_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_199.md']
        assert len(expected) == 46
        assert all(sym.startswith('X509_REQ') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 16
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 30

    def test_batch_200_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_200.md']
        assert len(expected) == 47
        assert all(sym.startswith('X509_ACERT') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 47

    def test_batch_201_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_201.md']
        assert len(expected) == 128
        assert all(sym.startswith('CMS_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 12
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 116

    def test_batch_202_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_202.md']
        assert len(expected) == 21
        assert all(sym.startswith('d2i_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 21
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 0

    def test_batch_203_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_203.md']
        assert len(expected) == 22
        assert all(sym.startswith('d2i_ASN1_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 22

    def test_batch_204_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_204.md']
        assert len(expected) == 80
        assert all(sym.startswith('d2i_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 7
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 73

    def test_batch_205_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_205.md']
        assert len(expected) == 23
        assert all(sym.startswith('d2i_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 19
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 4

    def test_batch_206_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_206.md']
        assert len(expected) == 20
        assert all(sym.startswith('d2i_OSSL_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 20

    def test_batch_207_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_207.md']
        assert len(expected) == 24
        assert all(sym.startswith('d2i_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 24

    def test_batch_208_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_208.md']
        assert len(expected) == 7
        assert all(sym.startswith('d2i_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 4
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 3

    def test_batch_209_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_209.md']
        assert len(expected) == 13
        assert all(sym.startswith('d2i_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 13

    def test_batch_210_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_210.md']
        assert len(expected) == 18
        assert all(sym.startswith('d2i_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 18

    def test_batch_211_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_211.md']
        assert len(expected) == 22
        assert all(sym.startswith('ASYNC_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 22

    def test_batch_212_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_212.md']
        assert len(expected) == 34
        assert all(sym.startswith('BIO_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 6
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 28

    def test_batch_213_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_213.md']
        assert len(expected) == 152
        assert all(sym.startswith('BIO_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 61
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 91

    def test_batch_214_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_214.md']
        assert len(expected) == 12
        assert all(sym.startswith('i2d_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 12
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 0

    def test_batch_215_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_215.md']
        assert len(expected) == 21
        assert all(sym.startswith('i2d_X509_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 21

    def test_batch_216_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_216.md']
        assert len(expected) == 11
        assert all(sym.startswith('i2d_CMS_') or sym.startswith('i2d_PKCS7') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 11

    def test_batch_217_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_217.md']
        assert len(expected) == 11
        assert all(sym.startswith('i2d_PKCS8') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 11
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 0

    def test_batch_218_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_218.md']
        assert len(expected) == 20
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 9
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 11

    def test_batch_219_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_219.md']
        assert len(expected) == 15
        assert all(sym.startswith('i2d_OCSP_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 15

    def test_batch_220_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_220.md']
        assert len(expected) == 14
        assert all(sym.startswith('i2d_TS_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 14

    def test_batch_221_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_221.md']
        assert len(expected) == 22
        assert all(sym.startswith('i2d_ASN1_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 22

    def test_batch_222_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_222.md']
        assert len(expected) == 20
        assert all(sym.startswith('i2d_OSSL_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 20

    def test_batch_223_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_223.md']
        assert len(expected) == 24
        assert all(sym.startswith('i2d_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 24

    def test_batch_224_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_224.md']
        assert len(expected) == 8
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 8

    def test_batch_225_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_225.md']
        assert len(expected) == 5
        assert all(sym.startswith('i2d_ESS_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 5

    def test_batch_226_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_226.md']
        assert len(expected) == 3
        assert all(sym.startswith('i2d_NETSCAPE_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 3

    def test_batch_227_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_227.md']
        assert len(expected) == 5
        assert all(sym.startswith('i2d_DSA') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 5

    def test_batch_228_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_228.md']
        assert len(expected) == 3
        assert set(expected) == {
            'i2d_re_X509_tbs',
            'i2d_re_X509_REQ_tbs',
            'i2d_re_X509_CRL_tbs',
        }
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 3

    def test_batch_229_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_229.md']
        assert len(expected) == 5
        assert set(expected) == {
            'i2d_PBE2PARAM',
            'i2d_PBEPARAM',
            'i2d_PBKDF2PARAM',
            'i2d_PBMAC1PARAM',
            'i2d_SCRYPT_PARAMS',
        }
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 5

    def test_batch_230_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_230.md']
        assert len(expected) == 13
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 13
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 0

    def test_batch_231_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_231.md']
        assert len(expected) == 3
        assert set(expected) == {
            'i2d_PKCS12_BAGS',
            'i2d_PKCS12_MAC_DATA',
            'i2d_PKCS12_SAFEBAG',
        }
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 3

    def test_batch_232_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_232.md']
        assert len(expected) == 3
        assert set(expected) == {
            'i2d_GENERAL_NAME',
            'i2d_GENERAL_NAMES',
            'i2d_CRL_DIST_POINTS',
        }
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 3

    def test_batch_233_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_233.md']
        assert len(expected) == 5
        assert set(expected) == {
            'i2d_ISSUER_SIGN_TOOL',
            'i2d_SCT_LIST',
            'i2d_SXNET',
            'i2d_SXNETID',
            'i2d_SSL_SESSION',
        }
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 5

    def test_batch_234_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_234.md']
        assert len(expected) == 2
        assert set(expected) == {
            'i2d_KeyParams',
            'i2d_KeyParams_bio',
        }
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 2

    def test_batch_235_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_235.md']
        assert len(expected) == 137
        assert all(sym.startswith('OCSP_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 137

    def test_batch_236_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_236.md']
        assert len(expected) == 155
        assert all(sym.startswith('TS_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 155

    def test_batch_237_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_237.md']
        assert len(expected) == 81
        assert all(sym.startswith('PKCS7_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 9
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 72

    def test_batch_238_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_238.md']
        assert len(expected) == 52
        assert all(sym.startswith(('X509_NAME_', 'X509_NAME_ENTRY_', 'X509_EXTENSION_', 'X509_PUBKEY_'))
                   for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 17
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 35

    def test_batch_239_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_239.md']
        assert len(expected) == 60
        assert all(sym.startswith((
            'X509_OBJECT_', 'X509_PURPOSE_', 'X509_TRUST_', 'X509_policy_',
            'X509_SIG_', 'X509_issuer_', 'X509_load_'
        )) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 60

    def test_batch_240_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_240.md']
        assert len(expected) == 54
        assert all(sym.startswith(('X509_get_', 'X509_get0_', 'X509_set_', 'X509_check_'))
                   for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 18
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 36

    def test_batch_241_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_241.md']
        assert len(expected) == 69
        assert all(sym.startswith('X509_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 14
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 55

    def test_batch_242_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_242.md']
        assert len(expected) == 92
        assert all(sym.startswith((
            'EVP_aria_', 'EVP_camellia_', 'EVP_des_', 'EVP_rc2_', 'EVP_rc4',
            'EVP_bf_', 'EVP_cast5_', 'EVP_idea_', 'EVP_seed_'
        )) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 92

    def test_batch_243_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_243.md']
        assert len(expected) == 55
        assert all(sym.startswith((
            'EVP_aes_', 'EVP_sm4', 'EVP_chacha20', 'EVP_Cipher', 'EVP_Encrypt', 'EVP_Decrypt'
        )) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 47
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 8

    def test_batch_244_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_244.md']
        assert len(expected) == 64
        assert all(sym.startswith('EVP_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 21
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 43

    def test_batch_245_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_245.md']
        assert len(expected) == 91
        assert all(sym.startswith('SSL_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 28
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 63

    def test_batch_246_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_246.md']
        assert len(expected) == 93
        assert all(sym.startswith('PKCS12') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 38
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 55

    def test_batch_247_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_247.md']
        assert len(expected) == 99
        assert all(sym.startswith('CRYPTO_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 49
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 50

    def test_batch_248_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_248.md']
        assert len(expected) == 91
        assert all(sym.startswith('OSSL_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 2
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 89

    def test_batch_249_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_249.md']
        assert len(expected) == 77
        assert all(sym.startswith('RSA_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 32
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 45

    def test_batch_250_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_250.md']
        assert len(expected) == 63
        assert all(sym.startswith(('DH_', 'DSA_')) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 23
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 40

    def test_batch_251_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_251.md']
        assert len(expected) == 92
        assert all(sym.startswith(('OPENSSL_', 'UI_')) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 24
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 68

    def test_batch_252_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_252.md']
        assert len(expected) == 80
        assert all(sym.startswith(('ERR_', 'CONF_', 'NCONF_', 'OBJ_')) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 5
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 9
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 66

    def test_batch_253_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_253.md']
        assert len(expected) == 54
        assert all(sym.startswith(('CT_', 'CTLOG_', 'SCT_')) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 54

    def test_batch_254_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_254.md']
        assert len(expected) == 57
        assert all(sym.startswith(('PEM_', 'PKCS5_', 'PKCS8_')) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 7
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 50

    def test_batch_255_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_255.md']
        assert len(expected) == 68
        assert all(sym.startswith(('ENGINE_', 'RAND_', 'COMP_', 'DSO_')) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 4
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 64

    def test_batch_256_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_256.md']
        assert len(expected) == 92
        assert all(sym.startswith(('X509v3_', 'ESS_', 'NETSCAPE_', 'NAMING_', 'PROFESSION_', 'X509at_')) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 92

    def test_batch_257_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_257.md']
        assert len(expected) == 61
        assert all(sym.startswith((
            'ECDSA_', 'ECDH_', 'CMAC_', 'HMAC_', 'BUF_', 'TXT_DB_',
            'MD4', 'MDC2', 'RIPEMD160', 'RC4', 'PKCS1_MGF1'
        )) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 1
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 15
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 45

    def test_batch_258_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_258.md']
        assert len(expected) == 104
        exact = {
            'BIGNUM_it', 'CBIGNUM_it', 'INT32_it', 'INT64_it', 'LONG_it',
            'UINT32_it', 'UINT64_it', 'ZINT32_it', 'ZINT64_it', 'ZLONG_it',
            'ZUINT32_it', 'ZUINT64_it', 'PBMAC1_get1_pbkdf2_param'
        }
        prefixes = (
            'a2d_', 'a2i_', 'i2a_', 'i2s_', 'i2t_', 'i2v_', 's2i_', 'v2i_',
            'DIRECTORYSTRING_', 'DISPLAYTEXT_', 'EDIPARTYNAME_', 'IPAddress',
            'OTHERNAME_', 'EXTENDED_KEY_USAGE_', 'ISSUER_SIGN_TOOL_',
            'PKEY_USAGE_PERIOD_', 'TLS_FEATURE_', 'PBE2PARAM_', 'PBEPARAM_',
            'PBKDF2PARAM_', 'PBMAC1PARAM_', 'SCRYPT_PARAMS_', 'ECPARAMETERS_',
            'ECPKPARAMETERS_', 'RSAPrivateKey_', 'RSAPublicKey_'
        )
        assert all(sym in exact or sym.startswith(prefixes) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 2
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 102

    def test_batch_259_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_259.md']
        assert len(expected) == 22
        assert all(sym.startswith((
            'DTLS_', 'DTLSv1_', 'DTLSv1_2_', 'TLS_', 'TLSv1_', 'TLSv1_1_', 'TLSv1_2_'
        )) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 12
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 10

    def test_batch_260_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_260.md']
        assert len(expected) == 28
        prefixes = (
            'DHparams_', 'DSAparams_', 'ECParameters_', 'ECPKParameters_',
            'b2i_', 'i2b_', 'i2o_', 'o2i_'
        )
        exact = {'asn1_d2i_read_bio'}
        assert all(sym in exact or sym.startswith(prefixes) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 4
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 24

    def test_batch_261_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_261.md']
        assert len(expected) == 10
        exact = {
            'OpenSSL_version', 'OpenSSL_version_num', 'err_free_strings_int',
            'MD5_Transform', 'SHA1_Transform', 'SHA256_Transform', 'SHA512_Transform'
        }
        assert all(sym in exact or sym.startswith('conf_ssl_') for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 2
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 8

    def test_batch_262_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_262.md']
        assert len(expected) == 424
        assert all(sym.startswith(('sk_', 'lh_')) for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 424

    def test_batch_263_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_263.md']
        assert len(expected) == 96
        macroish = {
            'ADB_ENTRY', 'EXT_BITSTRING', 'EXT_IA5STRING', 'EXT_UTF8STRING',
            'IMPLEMENT_EXTERN_ASN1', 'IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS',
            'DECLARE_OBJ_BSEARCH_CMP_FN', 'DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN',
            'IMPLEMENT_OBJ_BSEARCH_CMP_FN', 'IMPLEMENT_OBJ_BSEARCH_GLOBAL_CMP_FN',
            'DECLARE_PEM_rw', 'DECLARE_PEM_rw_attr', 'DECLARE_PEM_rw_cb_attr',
            'DECLARE_PEM_rw_cb_ex', 'DECLARE_PEM_rw_ex', 'DECLARE_PEM_write',
            'DECLARE_PEM_write_attr', 'IMPLEMENT_PEM_rw', 'IMPLEMENT_PEM_write',
            'IMPLEMENT_PEM_write_cb', 'PEM_write_cb_ex_fnsig',
            'PEM_write_cb_fnsig', 'PEM_write_fnsig'
        }
        assert all(
            sym in macroish or sym.startswith((
                'ASN1_', 'DECLARE_ASN1_', 'IMPLEMENT_ASN1_', 'M_ASN1_', 'static_ASN1_'
            ))
            for sym in expected
        )
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 96

    def test_batch_264_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_264.md']
        assert len(expected) == 136
        assert all(sym.startswith(('SSL_', 'SSL_CTX_', 'SSL_SESSION_', 'DTLS', 'TLS1_'))
                   for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 62
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 74

    def test_batch_265_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_265.md']
        assert len(expected) == 139
        assert all(
            sym.startswith(('BIO_', 'EVP_', 'ERR_', 'CRYPTO_', 'ENGINE_'))
            or sym in {'DSA_get_ex_new_index', 'ECerr', 'EVPerr',
                       'RSA_get_ex_new_index', 'RSAerr', 'SSLerr'}
            for sym in expected
        )
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 1
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 52
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 86

    def test_batch_266_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_266.md']
        assert len(expected) == 54
        assert all(
            sym.startswith(('X509_', 'PKCS7_', 'PKCS12_', 'OCSP_', 'X509V3_', 'BN_', 'NCONF_', 'CONF_'))
            or sym in {
                'd2i_ECPKParameters_bio', 'd2i_ECPKParameters_fp', 'd2i_OCSP_REQUEST_bio',
                'd2i_OCSP_RESPONSE_bio', 'd2i_SSL_SESSION_bio', 'i2d_ECPKParameters_bio',
                'i2d_ECPKParameters_fp', 'i2d_OCSP_REQUEST_bio', 'i2d_OCSP_RESPONSE_bio',
                'i2d_SSL_SESSION_bio'
            }
            for sym in expected
        )
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 9
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 45

    def test_batch_267_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_267.md']
        assert len(expected) == 44
        assert all(
            sym.startswith(('OPENSSL_', 'OSSL_', 'IMPLEMENT_DYNAMIC_'))
            or sym in {'OpenSSL_add_all_digests', 'PKCS12err', 'SSLeay_add_ssl_algorithms'}
            for sym in expected
        )
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 8
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 36

    def test_batch_268_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_268.md']
        assert len(expected) == 75
        assert all(sym.startswith(('SSL_', 'SSL_CTX_', 'SSL_SESSION_'))
                   for sym in expected)
        assert all(mappings[sym]['domain'] == 'tls' for sym in expected)
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 15
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 60


    def test_batch_269_truth_entries(self):
        count = self.compat.load()
        assert count == EXPECTED_PRODUCTION_COUNT
        mappings = self.compat.get_all_mappings()
        expected = [sym for sym, meta in mappings.items()
                    if meta.get('analysis_doc') == 'docs/hitls-compat/hitls_compat_validation_batch_269.md']
        assert len(expected) == 105
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'available') == 0
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'partial') == 4
        assert sum(1 for sym in expected if mappings[sym]['status'] == 'not_available') == 101

    def test_partial_with_null_hitls(self):
        """Partial entries with null hitls should return ('partial', None)."""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump({"version": "1.0", "mapping": {
                "EVP_DigestSignUpdate": {
                    "status": "partial",
                    "hitls": None,
                    "notes": "No streaming sign"
                }
            }}, f)
            f.flush()
            try:
                self.compat.load(f.name)
                status, hitls = self.compat.lookup('EVP_DigestSignUpdate')
                assert status == 'partial'
                assert hitls is None
            finally:
                os.unlink(f.name)


class TestProductionDataInvariants:
    """GAP-NEW: Validate structural invariants of the built-in mapping."""

    def setup_method(self):
        self.compat = HiTLSCompat()
        self.compat.load()

    def test_all_statuses_valid(self):
        mapping = self.compat.get_all_mappings()
        valid = {'available', 'partial', 'not_available'}
        for sym, entry in mapping.items():
            assert entry['status'] in valid, f"{sym}: invalid status '{entry['status']}'"

    def test_available_has_hitls(self):
        mapping = self.compat.get_all_mappings()
        for sym, entry in mapping.items():
            if entry['status'] == 'available':
                assert entry.get('hitls') is not None, (
                    f"{sym}: available but hitls is null")

    def test_not_available_has_null_hitls(self):
        mapping = self.compat.get_all_mappings()
        for sym, entry in mapping.items():
            if entry['status'] == 'not_available':
                assert entry.get('hitls') is None, (
                    f"{sym}: not_available but hitls is {entry['hitls']}")

    def test_all_entries_have_valid_domain(self):
        mapping = self.compat.get_all_mappings()
        valid = {'crypto', 'tls', 'pki_infra'}
        for sym, entry in mapping.items():
            assert entry.get('domain') in valid, (
                f"{sym}: invalid domain '{entry.get('domain')}'")

    def test_known_domain_assignments(self):
        mapping = self.compat.get_all_mappings()
        expected = {
            'EVP_sha256': 'crypto',
            'SSL_CTX_new': 'tls',
            'X509_new': 'pki_infra',
        }
        for sym, domain in expected.items():
            assert mapping[sym]['domain'] == domain

    def test_analysis_docs_live_under_hitls_compat_directory(self):
        repo_root = os.path.join(os.path.dirname(__file__), '..')
        mapping = self.compat.get_all_mappings()
        for sym, entry in mapping.items():
            doc = entry.get('analysis_doc')
            assert doc is not None, f"{sym}: missing analysis_doc"
            assert doc.startswith('docs/hitls-compat/'), (
                f"{sym}: analysis_doc outside docs/hitls-compat: {doc}")
            assert os.path.exists(os.path.join(repo_root, doc)), (
                f"{sym}: analysis_doc path does not exist: {doc}")

    def test_no_top_level_hitls_analysis_docs(self):
        docs_root = os.path.join(os.path.dirname(__file__), '..', 'docs')
        top_level = sorted(
            name for name in os.listdir(docs_root)
            if name.startswith('hitls_compat') and name.endswith('.md')
        )
        assert top_level == []

    def test_total_count(self):
        mapping = self.compat.get_all_mappings()
        assert len(mapping) == EXPECTED_PRODUCTION_COUNT

    def test_top_level_metadata_matches_mapping(self):
        import os
        path = os.path.join(
            os.path.dirname(__file__), '..', 'src',
            'openssl_scanner', 'data', 'hitls_compat.json'
        )
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        mapping = data['mapping']
        assert data['total_mapped'] == len(mapping)
        from collections import Counter
        ctr = Counter(v.get('status') for v in mapping.values())
        assert data['coverage'] == {
            'not_available': ctr['not_available'],
            'partial': ctr['partial'],
            'available': ctr['available'],
        }
