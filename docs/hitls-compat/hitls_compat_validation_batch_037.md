# openHiTLS Compatibility Validation Batch 037

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `X509_STORE_new`
- `X509_STORE_CTX_get_ex_data`
- `X509_get0_notAfter`
- `X509_get0_notBefore`
- `X509_get0_pubkey`
- `X509_up_ref`
- `X509_CRL_verify`
- `X509_NAME_new`

Status:
- completed

Initial evidence:
- This is the next coherent X509 accessor/store cluster without `analysis_doc`.
- Current scan aggregation shows:
  - `X509_STORE_new`: 10 repos
  - `X509_STORE_CTX_get_ex_data`: 8 repos
  - `X509_get0_notAfter`: 8 repos
  - `X509_get0_notBefore`: 8 repos
  - `X509_get0_pubkey`: 8 repos
  - `X509_up_ref`: 8 repos
  - `X509_CRL_verify`: 8 repos
  - `X509_NAME_new`: 8 repos
- This batch confirms one stable rule:
  - getter-by-value through public ctrl APIs counts as `partial`
  - raw typed object/pointer getters would be needed for `available`

## 1. `X509_STORE_new`
- OpenSSL declaration/implementation: [x509_vfy.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509_vfy.h.in#L396), [x509_lu.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509_lu.c#L180)
- openHiTLS declaration/implementation: [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L49), [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L211)
- Verdict: keep `partial`
- Why: `HITLS_X509_StoreCtxNew()` is the closest public allocator, but openHiTLS merges store and store-context responsibilities into one object.

## 2. `X509_STORE_CTX_get_ex_data`
- OpenSSL declaration/implementation: [x509_vfy.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509_vfy.h.in#L657), [x509_vfy.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509_vfy.c#L2130)
- openHiTLS declaration/implementation: [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L118), [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L103), [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L573), [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L843)
- Verdict: keep `partial`
- Why: `HITLS_X509_StoreCtxCtrl(..., HITLS_X509_STORECTX_GET_USR_DATA, ...)` can retrieve user data, but openHiTLS only exposes a dedicated user-data slot rather than OpenSSL's indexed `ex_data` table.

## 3. `X509_get0_notAfter`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L650), [x509_set.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509_set.c#L121)
- openHiTLS declaration/implementation: [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L69), [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L459), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L602)
- Verdict: keep `partial`
- Why: openHiTLS can return the validity end time through `HITLS_X509_CertCtrl(..., HITLS_X509_GET_AFTER_TIME, ...)`, but as a copied `BSL_TIME` value, not a borrowed `ASN1_TIME *`.

## 4. `X509_get0_notBefore`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L647), [x509_set.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509_set.c#L116)
- openHiTLS declaration/implementation: [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L68), [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L445), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L602)
- Verdict: keep `partial`
- Why: same pattern as `X509_get0_notAfter`, but for the validity start time.

## 5. `X509_get0_pubkey`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L675), [x509_cmp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509_cmp.c#L378)
- openHiTLS declaration/implementation: [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L54), [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L624), [hitls_x509_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ctrl.c#L83)
- Verdict: change to `partial`
- Why: openHiTLS can return the certificate public key through `HITLS_X509_CertCtrl(..., HITLS_X509_GET_PUBKEY, ...)`, but it up-refs and returns a `CRYPT_EAL_PkeyCtx *`, which is closer to OpenSSL `get1` semantics than `get0`.

## 6. `X509_up_ref`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L654), [x509_set.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509_set.c#L99)
- openHiTLS declaration/implementation: [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L50), [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L751)
- Verdict: keep `partial`
- Why: the refcount increment is publicly available via `HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, ...)`, but it is a generic ctrl path rather than a dedicated function.

## 7. `X509_CRL_verify`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L323), [x_crl.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x_crl.c#L374)
- openHiTLS declaration/implementation: [hitls_pki_crl.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_crl.h#L181), [hitls_x509_crl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_crl/src/hitls_x509_crl.c#L1209)
- Verdict: keep `partial`
- Why: `HITLS_X509_CrlVerify(pubkey, crl)` exists publicly, but the parameter order is reversed and the public-key object type differs.

## 8. `X509_NAME_new`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L799), [cmp_hdr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/cmp/cmp_hdr.c#L94)
- openHiTLS declaration/implementation: [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L110), [hitls_x509_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ctrl.c#L404)
- Verdict: keep `partial`
- Why: `HITLS_X509_DnListNew()` is the public DN-list allocator, but it returns a `BslList *` of DN nodes rather than an OpenSSL `X509_NAME *`.

## Batch 037 summary

Change to `partial`:
- `X509_get0_pubkey`

Keep `partial`:
- `X509_STORE_new`
- `X509_STORE_CTX_get_ex_data`
- `X509_get0_notAfter`
- `X509_get0_notBefore`
- `X509_up_ref`
- `X509_CRL_verify`
- `X509_NAME_new`

Main observation:
- This batch confirms one more stable rule:
  - getter-by-value through public ctrl APIs counts as `partial`
  - getter-by-object with matching pointer semantics would be needed for `available`
