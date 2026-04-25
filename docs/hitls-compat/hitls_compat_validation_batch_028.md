# openHiTLS Compatibility Validation Batch 028

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `PEM_read_bio_PrivateKey`
- `X509_get_pubkey`
- `X509_get_serialNumber`
- `d2i_X509`
- `d2i_X509_bio`
- `i2d_X509`
- `PEM_write_bio_X509`

Status:
- completed

Initial evidence:
- This family is the next highest-value coherent group among entries that lacked `analysis_doc`.
- Current scan aggregation shows:
  - `PEM_read_bio_PrivateKey`: 14 repos
  - `X509_get_pubkey`: 14 repos
  - `X509_get_serialNumber`: 13 repos
  - `d2i_X509`: 11 repos
  - `d2i_X509_bio`: 11 repos
  - `PEM_write_bio_X509`: 10 repos
  - `i2d_X509`: 9 repos
- All seven already had directionally correct mappings. The job here is to make ownership and I/O-shape differences explicit enough for truth-library use.

## 1. `PEM_read_bio_PrivateKey`
- OpenSSL declaration/implementation: [pem.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/pem.h#L473), [pem_pkey.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/pem/pem_pkey.c#L309)
- openHiTLS declaration/implementation: [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L184), [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L418)
- Verdict: keep `partial`
- Why: openHiTLS can decode PEM private keys through `CRYPT_EAL_DecodeBuffKey`, but only from a caller-provided buffer, not directly from `BIO *`. Callers must first extract the BIO contents into a buffer and pass explicit format/type arguments.

## 2. `X509_get_pubkey`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L676), [x509_cmp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509_cmp.c#L385)
- openHiTLS declaration/implementation: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L745), [hitls_x509_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ctrl.c#L83)
- Verdict: keep `partial`
- Why: openHiTLS can return the certificate public key through `HITLS_X509_CertCtrl(..., HITLS_X509_GET_PUBKEY, ...)`, and it does up-ref the underlying `CRYPT_EAL_PkeyCtx`. The remaining mismatch is API shape: OpenSSL returns `EVP_PKEY *` directly, while openHiTLS requires a generic ctrl call and typed out-pointer.

## 3. `X509_get_serialNumber`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L641), [x509_cmp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509_cmp.c#L125)
- openHiTLS declaration/implementation: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L745), [hitls_x509_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ctrl.c#L471)
- Verdict: keep `partial`
- Why: openHiTLS exposes the serial number through `HITLS_X509_CertCtrl(..., HITLS_X509_GET_SERIALNUM, ...)`, but returns it as a shallow `BSL_Buffer` view rather than an `ASN1_INTEGER *`.

## 4. `d2i_X509`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L295), [x_x509.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x_x509.c#L201)
- openHiTLS declaration/implementation: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L128), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L377)
- Verdict: keep `partial`
- Why: openHiTLS can parse DER/ASN.1 certificate buffers with `HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, ...)`, but it does not support OpenSSL's `unsigned char **pp` in-place decode cursor contract or in/out reuse semantics.

## 5. `d2i_X509_bio`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L415), [x_all.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x_all.c#L185)
- openHiTLS declaration/implementation: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L128), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L377)
- Verdict: keep `partial`
- Why: the closest public replacement is still `HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, ...)`. openHiTLS has no direct `BIO *` certificate decode entrypoint, so callers must first materialize the BIO into a buffer.

## 6. `i2d_X509`
- OpenSSL declaration/implementation: [x_x509.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x_x509.c#L236), [statem_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/statem/statem_lib.c#L902)
- openHiTLS declaration/implementation: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L283), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L1059)
- Verdict: keep `partial`
- Why: openHiTLS can generate DER/ASN.1 into a `BSL_Buffer` via `HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, ...)`, but it allocates/returns a buffer object instead of using OpenSSL's `unsigned char **pp` cursor-and-length convention.

## 7. `PEM_write_bio_X509`
- OpenSSL declaration/implementation: [pem.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/pem.h#L436), [ocsp_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/ocsp/ocsp_prn.c#L124)
- openHiTLS declaration/implementation: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L283), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L1046), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L1059)
- Verdict: keep `partial`
- Why: openHiTLS can generate PEM text through `HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, ...)`, but it writes into a returned buffer, not directly into `BIO *`.

## Batch 028 summary

Keep `partial`:
- `PEM_read_bio_PrivateKey`
- `X509_get_pubkey`
- `X509_get_serialNumber`
- `d2i_X509`
- `d2i_X509_bio`
- `i2d_X509`
- `PEM_write_bio_X509`

Main observation:
- This batch is strongly covered at the function level.
- The reason none of the entries upgrade to `available` is the repeated OpenSSL vs openHiTLS shape mismatch:
  - `BIO *` vs caller-owned buffer
  - direct typed return vs generic ctrl + outparam
  - `**pp` cursor/length encoding APIs vs allocated `BSL_Buffer`
