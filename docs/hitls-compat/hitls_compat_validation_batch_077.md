# openHiTLS Compatibility Validation Batch 077

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SEED_cbc_encrypt`
- `SEED_cfb128_encrypt`
- `SEED_decrypt`
- `SEED_ecb_encrypt`
- `SEED_encrypt`
- `SEED_ofb128_encrypt`
- `SEED_set_key`

Status:
- completed

Initial evidence:
- openHiTLS exposes no public SEED cipher IDs in `CRYPT_CIPHER_AlgId`, no SEED entries in default provider dispatch, and no SEED entries in EAL cipher-method tables.
- The openHiTLS crypto tree also has no SEED implementation directory under [crypto](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto).

## 1. `SEED_cbc_encrypt`
- OpenSSL declaration/implementation: [seed.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/seed.h#L92), [seed_cbc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/seed/seed_cbc.c#L19)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L42)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public SEED CBC family.

## 2. `SEED_cfb128_encrypt`
- OpenSSL declaration/implementation: [seed.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/seed.h#L97), [seed_cfb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/seed/seed_cfb.c#L19)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public SEED CFB family.

## 3. `SEED_decrypt`
- OpenSSL declaration/implementation: [seed.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/seed.h#L84), [seed.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/seed/seed.c#L550)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public SEED primitive or key-schedule surface.

## 4. `SEED_ecb_encrypt`
- OpenSSL declaration/implementation: [seed.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/seed.h#L88), [seed_ecb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/seed/seed_ecb.c#L18)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public SEED ECB family.

## 5. `SEED_encrypt`
- OpenSSL declaration/implementation: [seed.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/seed.h#L80), [seed.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/seed/seed.c#L505)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public SEED primitive or key-schedule surface.

## 6. `SEED_ofb128_encrypt`
- OpenSSL declaration/implementation: [seed.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/seed.h#L102), [seed_ofb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/seed/seed_ofb.c#L19)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public SEED OFB family.

## 7. `SEED_set_key`
- OpenSSL declaration/implementation: [seed.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/seed.h#L77), [seed.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/seed/seed.c#L446)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public SEED key-schedule surface.

## Batch 077 summary

Keep `not_available`:
- `SEED_cbc_encrypt`
- `SEED_cfb128_encrypt`
- `SEED_decrypt`
- `SEED_ecb_encrypt`
- `SEED_encrypt`
- `SEED_ofb128_encrypt`
- `SEED_set_key`

Main observation:
- SEED is a fully absent legacy family in the public openHiTLS surface.
- There is no OID, cipher-dispatch, or implementation evidence strong enough to upgrade any entry beyond `not_available`.
