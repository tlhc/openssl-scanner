# openHiTLS Compatibility Validation Batch 073

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BF_cbc_encrypt`
- `BF_cfb64_encrypt`
- `BF_decrypt`
- `BF_ecb_encrypt`
- `BF_encrypt`
- `BF_ofb64_encrypt`
- `BF_options`
- `BF_set_key`

Status:
- completed

Initial evidence:
- The openHiTLS public cipher surface still stops at AES, SM4, ChaCha20-Poly1305, and AES-WRAP families.
- `bsl_obj.h` contains Blowfish OID/CID constants such as [BSL_CID_BF_ECB](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L366), but those object identifiers do not make Blowfish available through the public `CRYPT_CIPHER_AlgId` or EAL cipher ctx APIs.
- The crypto tree also has no Blowfish implementation directory under [crypto](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto).

## 1. `BF_cbc_encrypt`
- OpenSSL declaration/implementation: [blowfish.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/blowfish.h#L57), [bf_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bf/bf_enc.c#L108)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L366), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L42)
- Verdict: keep `not_available`
- Why: Blowfish OIDs exist, but there is no public Blowfish cipher ID or CBC ctx constructor in the EAL cipher surface.

## 2. `BF_cfb64_encrypt`
- OpenSSL declaration/implementation: [blowfish.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/blowfish.h#L61), [bf_cfb64.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bf/bf_cfb64.c#L25)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L366)
- Verdict: keep `not_available`
- Why: Blowfish OIDs exist, but there is no public Blowfish CFB ctx constructor in the EAL cipher surface.

## 3. `BF_decrypt`
- OpenSSL declaration/implementation: [blowfish.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/blowfish.h#L53), [bf_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bf/bf_enc.c#L69)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L366)
- Verdict: keep `not_available`
- Why: Blowfish OIDs exist, but there is no public Blowfish primitive or key-schedule surface.

## 4. `BF_ecb_encrypt`
- OpenSSL declaration/implementation: [blowfish.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/blowfish.h#L54), [bf_ecb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bf/bf_ecb.c#L31)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L366), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: Blowfish OIDs exist, but there is no public Blowfish ECB family in the provider/EAL tables.

## 5. `BF_encrypt`
- OpenSSL declaration/implementation: [blowfish.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/blowfish.h#L52), [bf_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bf/bf_enc.c#L30)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L366)
- Verdict: keep `not_available`
- Why: Blowfish OIDs exist, but there is no public Blowfish primitive or key-schedule surface.

## 6. `BF_ofb64_encrypt`
- OpenSSL declaration/implementation: [blowfish.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/blowfish.h#L66), [bf_ofb64.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bf/bf_ofb64.c#L24)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L366)
- Verdict: keep `not_available`
- Why: Blowfish OIDs exist, but there is no public Blowfish OFB family in the EAL cipher surface.

## 7. `BF_options`
- OpenSSL declaration/implementation: [blowfish.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/blowfish.h#L70), [bf_ecb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bf/bf_ecb.c#L26)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L366)
- Verdict: keep `not_available`
- Why: Blowfish OIDs exist, but openHiTLS has no Blowfish implementation-options string because it has no public Blowfish surface.

## 8. `BF_set_key`
- OpenSSL declaration/implementation: [blowfish.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/blowfish.h#L50), [bf_skey.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bf/bf_skey.c#L22)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L366)
- Verdict: keep `not_available`
- Why: Blowfish OIDs exist, but there is no public Blowfish key-schedule surface.

## Batch 073 summary

Keep `not_available`:
- `BF_cbc_encrypt`
- `BF_cfb64_encrypt`
- `BF_decrypt`
- `BF_ecb_encrypt`
- `BF_encrypt`
- `BF_ofb64_encrypt`
- `BF_options`
- `BF_set_key`

Main observation:
- `bsl_obj.h` OIDs are not the same thing as public cipher APIs.
- For Blowfish, openHiTLS exposes identifiers at the object layer but no public `CRYPT_CIPHER_AlgId`, no provider cases, and no cipher ctx construction path.
