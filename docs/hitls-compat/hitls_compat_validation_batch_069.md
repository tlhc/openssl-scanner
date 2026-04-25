# openHiTLS Compatibility Validation Batch 069

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `DES_cbc_encrypt`
- `DES_ecb_encrypt`
- `DES_cfb64_encrypt`
- `DES_ofb_encrypt`
- `DES_set_key_unchecked`
- `DES_set_odd_parity`

Status:
- completed

Initial evidence:
- This batch follows the AES legacy batch with the next coherent legacy low-level cipher surface.
- Unlike AES, the DES result is stronger: openHiTLS does not expose DES/3DES cipher IDs at all.

## 1. `DES_cbc_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L89), [ncbc_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/ncbc_enc.c#L19)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: DES/3DES cipher IDs do not appear in openHiTLS `CRYPT_CIPHER_AlgId`, and there is no DES crypto subtree.

## 2. `DES_ecb_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L105), [ecb_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/ecb_enc.c#L36)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: DES/3DES cipher IDs do not appear in openHiTLS `CRYPT_CIPHER_AlgId`, and there is no DES crypto subtree.

## 3. `DES_cfb64_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L197), [cfb64enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/cfb64enc.c#L24)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: DES/3DES cipher IDs do not appear in openHiTLS `CRYPT_CIPHER_AlgId`, and there is no DES crypto subtree.

## 4. `DES_ofb_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L166), [ofb_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/ofb_enc.c#L24)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: DES/3DES cipher IDs do not appear in openHiTLS `CRYPT_CIPHER_AlgId`, and there is no DES crypto subtree.

## 5. `DES_set_key_unchecked`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L192), [set_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/set_key.c#L325)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: DES/3DES key-schedule APIs are absent because DES/3DES itself is absent from openHiTLS cipher IDs.

## 6. `DES_set_odd_parity`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L176), [set_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/set_key.c#L59)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: DES parity helpers are absent because DES/3DES itself is absent from openHiTLS cipher IDs.

## Batch 069 summary

Keep `not_available`:
- `DES_cbc_encrypt`
- `DES_ecb_encrypt`
- `DES_cfb64_encrypt`
- `DES_ofb_encrypt`
- `DES_set_key_unchecked`
- `DES_set_odd_parity`

Main observation:
- This is a hard “unsupported” family, not just an object-model mismatch.
- openHiTLS does not expose DES/3DES cipher IDs at all.
