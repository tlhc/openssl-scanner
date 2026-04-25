# openHiTLS Compatibility Validation Batch 078

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `CAST_cbc_encrypt`
- `CAST_cfb64_encrypt`
- `CAST_decrypt`
- `CAST_ecb_encrypt`
- `CAST_encrypt`
- `CAST_ofb64_encrypt`
- `CAST_set_key`

Status:
- completed

Initial evidence:
- openHiTLS exposes no public CAST cipher IDs in `CRYPT_CIPHER_AlgId`, no CAST entries in default provider dispatch, and no CAST entries in EAL cipher-method tables.
- The openHiTLS crypto tree also has no CAST implementation directory under [crypto](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto).

## 1. `CAST_cbc_encrypt`
- OpenSSL declaration/implementation: [cast.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/cast.h#L53), [c_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/cast/c_enc.c#L83)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L42)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public CAST CBC family.

## 2. `CAST_cfb64_encrypt`
- OpenSSL declaration/implementation: [cast.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/cast.h#L57), [c_cfb64.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/cast/c_cfb64.c#L25)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public CAST CFB family.

## 3. `CAST_decrypt`
- OpenSSL declaration/implementation: [cast.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/cast.h#L51), [c_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/cast/c_enc.c#L51)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public CAST primitive or key-schedule surface.

## 4. `CAST_ecb_encrypt`
- OpenSSL declaration/implementation: [cast.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/cast.h#L46), [c_ecb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/cast/c_ecb.c#L20)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public CAST ECB family.

## 5. `CAST_encrypt`
- OpenSSL declaration/implementation: [cast.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/cast.h#L49), [c_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/cast/c_enc.c#L19)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public CAST primitive or key-schedule surface.

## 6. `CAST_ofb64_encrypt`
- OpenSSL declaration/implementation: [cast.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/cast.h#L61), [c_ofb64.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/cast/c_ofb64.c#L24)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public CAST OFB family.

## 7. `CAST_set_key`
- OpenSSL declaration/implementation: [cast.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/cast.h#L44), [c_skey.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/cast/c_skey.c#L32)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public CAST key-schedule surface.

## Batch 078 summary

Keep `not_available`:
- `CAST_cbc_encrypt`
- `CAST_cfb64_encrypt`
- `CAST_decrypt`
- `CAST_ecb_encrypt`
- `CAST_encrypt`
- `CAST_ofb64_encrypt`
- `CAST_set_key`

Main observation:
- CAST is a fully absent legacy family in the public openHiTLS surface.
- There is no object-ID, cipher-dispatch, or implementation evidence strong enough to upgrade any entry beyond `not_available`.
