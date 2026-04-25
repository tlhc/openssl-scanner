# openHiTLS Compatibility Validation Batch 074

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `Camellia_cbc_encrypt`
- `Camellia_cfb128_encrypt`
- `Camellia_cfb1_encrypt`
- `Camellia_cfb8_encrypt`
- `Camellia_ctr128_encrypt`
- `Camellia_decrypt`
- `Camellia_ecb_encrypt`
- `Camellia_encrypt`
- `Camellia_ofb128_encrypt`
- `Camellia_set_key`

Status:
- completed

Initial evidence:
- Unlike Blowfish, openHiTLS does not even surface Camellia object identifiers in the searched public headers.
- `CRYPT_CIPHER_AlgId`, default provider dispatch, and EAL cipher-method tables all enumerate AES/SM4/ChaCha20/AES-WRAP families without any Camellia entries.
- The openHiTLS crypto tree also has no Camellia implementation directory under [crypto](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto).

## 1. `Camellia_cbc_encrypt`
- OpenSSL declaration/implementation: [camellia.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/camellia.h#L71), [cmll_cbc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/camellia/cmll_cbc.c#L19)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L42)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public Camellia CBC family or ctx constructor.

## 2. `Camellia_cfb128_encrypt`
- OpenSSL declaration/implementation: [camellia.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/camellia.h#L77), [cmll_cfb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/camellia/cmll_cfb.c#L25)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public Camellia CFB family.

## 3. `Camellia_cfb1_encrypt`
- OpenSSL declaration/implementation: [camellia.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/camellia.h#L84), [cmll_cfb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/camellia/cmll_cfb.c#L35)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public Camellia CFB-numbits family.

## 4. `Camellia_cfb8_encrypt`
- OpenSSL declaration/implementation: [camellia.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/camellia.h#L91), [cmll_cfb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/camellia/cmll_cfb.c#L43)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public Camellia CFB-numbits family.

## 5. `Camellia_ctr128_encrypt`
- OpenSSL declaration/implementation: [camellia.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/camellia.h#L105), [cmll_ctr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/camellia/cmll_ctr.c#L19)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public Camellia CTR family.

## 6. `Camellia_decrypt`
- OpenSSL declaration/implementation: [camellia.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/camellia.h#L64), [cmll_misc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/camellia/cmll_misc.c#L37)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public Camellia primitive or key-schedule surface.

## 7. `Camellia_ecb_encrypt`
- OpenSSL declaration/implementation: [camellia.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/camellia.h#L67), [cmll_ecb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/camellia/cmll_ecb.c#L19)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public Camellia ECB family.

## 8. `Camellia_encrypt`
- OpenSSL declaration/implementation: [camellia.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/camellia.h#L61), [cmll_misc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/camellia/cmll_misc.c#L31)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public Camellia primitive or key-schedule surface.

## 9. `Camellia_ofb128_encrypt`
- OpenSSL declaration/implementation: [camellia.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/camellia.h#L98), [cmll_ofb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/camellia/cmll_ofb.c#L24)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public Camellia OFB family.

## 10. `Camellia_set_key`
- OpenSSL declaration/implementation: [camellia.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/camellia.h#L58), [cmll_misc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/camellia/cmll_misc.c#L20)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public Camellia key-schedule surface.

## Batch 074 summary

Keep `not_available`:
- `Camellia_cbc_encrypt`
- `Camellia_cfb128_encrypt`
- `Camellia_cfb1_encrypt`
- `Camellia_cfb8_encrypt`
- `Camellia_ctr128_encrypt`
- `Camellia_decrypt`
- `Camellia_ecb_encrypt`
- `Camellia_encrypt`
- `Camellia_ofb128_encrypt`
- `Camellia_set_key`

Main observation:
- Camellia is a stronger “absent family” result than Blowfish.
- There is no public Camellia symbol family in the scanned openHiTLS headers or cipher-dispatch tables.
