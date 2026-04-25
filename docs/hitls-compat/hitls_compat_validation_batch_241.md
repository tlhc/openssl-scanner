# openHiTLS Compatibility Validation Batch 241

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)
- OpenSSL docs:
  - https://docs.openssl.org/3.0/man3/X509_sign/
  - https://docs.openssl.org/3.5/man3/X509_digest/
  - https://docs.openssl.org/3.0/man3/X509_check_host/

Scope:
- remaining X509 misc wrappers lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a mixed residual `X509_*` wrapper/helper surface here, including:
  - construction / aux wrapper helpers
  - digest / sign helpers
  - print helpers
  - time mutation/access helpers
  - chain/self-signed helpers
  - trust / alias / keyid convenience helpers
- openHiTLS public installed tree exposes adjacent public surfaces for some of these:
  - certificate allocation:
    - `HITLS_X509_ProviderCertNew`
  - digest/sign:
    - `HITLS_X509_CertDigest`
    - `HITLS_X509_CertSign`
  - print:
    - `HITLS_PKI_PrintCtrl`
    - `HITLS_PKI_PRINT_CERT`
    - `HITLS_PKI_PRINT_CERT_BRIEF`
  - time getters/setters:
    - `HITLS_X509_GET_BEFORE_TIME`
    - `HITLS_X509_GET_AFTER_TIME`
    - `HITLS_X509_SET_BEFORE_TIME`
    - `HITLS_X509_SET_AFTER_TIME`
  - chain/self-signed:
    - `HITLS_X509_CertChainBuild`
    - `HITLS_X509_IS_SELF_SIGNED`
- The rest of the residual family still has no practical public replacement path.

Verdict:
- keep `available = 0`
- adjust to `partial = 14`
- adjust to `not_available = 55`

Reasoning boundary:
- `partial` is justified for the residual helpers that have a practical public replacement path:
  - `X509_build_chain`
  - `X509_digest`
  - `X509_getm_notAfter`
  - `X509_getm_notBefore`
  - `X509_new_ex`
  - `X509_print`
  - `X509_print_ex`
  - `X509_print_ex_fp`
  - `X509_print_fp`
  - `X509_self_signed`
  - `X509_set1_notAfter`
  - `X509_set1_notBefore`
  - `X509_sign`
  - `X509_sign_ctx`
- These remain `partial` because the public replacement path differs materially from OpenSSL:
  - print goes through a two-step `HITLS_PKI_PrintCtrl(HITLS_PKI_SET_PRINT_FLAG, ...)` plus `HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_CERT, ...)` sequence on `BSL_UIO`, not OpenSSL `BIO * / FILE *` and its flag contract
  - time accessors/setters use `BSL_TIME` or `CertCtrl`, not mutable `ASN1_TIME *`
  - signing is one-shot `CertSign`, with no `EVP_MD_CTX` contract for `X509_sign_ctx`
  - chain building uses `StoreCtx + CertChainBuild`, not OpenSSL `STACK_OF(X509) *` contract
  - self-signed check only exposes the boolean helper path, not the full OpenSSL helper contract
- `not_available` remains correct for the rest, including:
  - `X509_CERT_AUX_*`
  - `X509_CINF_*`
  - `X509_INFO_*`
  - `X509_PKEY_*`
  - `X509_VAL_*`
  - `X509_add1_ext_i2d`
  - `X509_add1_reject_object`
  - `X509_add1_trust_object`
  - `X509_add_cert`
  - `X509_add_certs`
  - `X509_alias_*`
  - `X509_aux_print`
  - `X509_certificate_type`
  - `X509_chain_check_suiteb`
  - `X509_chain_up_ref`
  - `X509_cmp*`
  - `X509_delete_ext`
  - `X509_digest_sig`
  - `X509_get1_email`
  - `X509_get1_ocsp`
  - `X509_keyid_*`
  - `X509_ocspid_print`
  - `X509_pubkey_digest`
  - `X509_reject_clear`
  - `X509_signature_*`
  - `X509_subject_name_cmp`
  - `X509_subject_name_hash_old`
  - `X509_supported_extension`
  - `X509_time_adj*`
  - `X509_to_X509_REQ`
  - `X509_trust_clear`
  - `X509_trusted`
- These interfaces either require standalone wrapper families, specific OpenSSL stack/object semantics, or helper contracts that openHiTLS public APIs do not expose.

Representative evidence:
- OpenSSL declarations:
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L331)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L350)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L360)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L575)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L670)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L671)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L673)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L674)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L828)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L837)
- OpenSSL implementation evidence:
  - [x_x509.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_x509.c#L155)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L94)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L120)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L538)
  - [x509_set.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_set.c#L90)
  - [x509_set.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_set.c#L98)
  - [x509_set.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_set.c#L143)
  - [x509_set.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_set.c#L148)
  - [t_x509.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/t_x509.c#L27)
  - [t_x509.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/t_x509.c#L48)
  - [x509_vfy.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_vfy.c#L102)
  - [x509_vfy.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_vfy.c#L3995)
- openHiTLS public declarations:
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L45)
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L79)
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L95)
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L59)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L68)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L77)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L394)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L45)
  - [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L154)
- openHiTLS implementation boundary:
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L576)
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L602)
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L711)
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L1100)
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L1155)
  - [hitls_pki_print.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/print/src/hitls_pki_print.c#L1138)
  - [hitls_pki_print.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/print/src/hitls_pki_print.c#L1172)
  - [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L1181)

Batch 241 inventory:
- total interfaces: `69`
- `partial = 14`
- `not_available = 55`
