# openHiTLS Compatibility Validation Batch 076

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `RC2_cbc_encrypt`
- `RC2_cfb64_encrypt`
- `RC2_decrypt`
- `RC2_ecb_encrypt`
- `RC2_encrypt`
- `RC2_ofb64_encrypt`
- `RC2_set_key`

Status:
- completed

Initial evidence:
- openHiTLS does surface RC2-related object IDs in [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L340), but that does not extend to public `CRYPT_CIPHER_AlgId`, provider dispatch, or EAL cipher ctx construction.
- The same pattern already appeared in Blowfish: OID/CID presence is weaker than public cipher availability.

## 1. `RC2_cbc_encrypt`
- OpenSSL declaration/implementation: [rc2.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rc2.h#L47), [rc2_cbc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rc2/rc2_cbc.c#L19)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L340), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L42)
- Verdict: keep `not_available`
- Why: RC2 OIDs exist, but there is no public RC2 CBC family or ctx constructor in the EAL cipher surface.

## 2. `RC2_cfb64_encrypt`
- OpenSSL declaration/implementation: [rc2.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rc2.h#L51), [rc2cfb64.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rc2/rc2cfb64.c#L25)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L340)
- Verdict: keep `not_available`
- Why: RC2 OIDs exist, but there is no public RC2 CFB family.

## 3. `RC2_decrypt`
- OpenSSL declaration/implementation: [rc2.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rc2.h#L46), [rc2_cbc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rc2/rc2_cbc.c#L140)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L340)
- Verdict: keep `not_available`
- Why: RC2 OIDs exist, but there is no public RC2 primitive or key-schedule surface.

## 4. `RC2_ecb_encrypt`
- OpenSSL declaration/implementation: [rc2.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rc2.h#L42), [rc2_ecb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rc2/rc2_ecb.c#L28)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L340), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: RC2 OIDs exist, but there is no public RC2 ECB family.

## 5. `RC2_encrypt`
- OpenSSL declaration/implementation: [rc2.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rc2.h#L45), [rc2_cbc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rc2/rc2_cbc.c#L94)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L340)
- Verdict: keep `not_available`
- Why: RC2 OIDs exist, but there is no public RC2 primitive or key-schedule surface.

## 6. `RC2_ofb64_encrypt`
- OpenSSL declaration/implementation: [rc2.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rc2.h#L56), [rc2ofb64.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rc2/rc2ofb64.c#L24)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L340)
- Verdict: keep `not_available`
- Why: RC2 OIDs exist, but there is no public RC2 OFB family.

## 7. `RC2_set_key`
- OpenSSL declaration/implementation: [rc2.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rc2.h#L40), [rc2_skey.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rc2/rc2_skey.c#L55)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L340)
- Verdict: keep `not_available`
- Why: RC2 OIDs exist, but there is no public RC2 key-schedule surface.

## Batch 076 summary

Keep `not_available`:
- `RC2_cbc_encrypt`
- `RC2_cfb64_encrypt`
- `RC2_decrypt`
- `RC2_ecb_encrypt`
- `RC2_encrypt`
- `RC2_ofb64_encrypt`
- `RC2_set_key`

Main observation:
- RC2 is another “OID exists, public cipher surface absent” family.
- For truth-library purposes, object-ID presence is insufficient to classify these helpers as `partial`.
