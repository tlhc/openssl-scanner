# openHiTLS Compatibility Validation Batch 071

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `DES_cbc_cksum`
- `DES_cfb_encrypt`
- `DES_check_key_parity`
- `DES_crypt`
- `DES_decrypt3`
- `DES_ecb3_encrypt`
- `DES_ede3_cbc_encrypt`
- `DES_ede3_cfb64_encrypt`
- `DES_ede3_cfb_encrypt`
- `DES_ede3_ofb64_encrypt`
- `DES_encrypt1`
- `DES_encrypt2`
- `DES_encrypt3`
- `DES_fcrypt`

Status:
- completed

Initial evidence:
- Batch 069 already established the public-surface conclusion: openHiTLS does not expose DES/3DES cipher IDs in `CRYPT_CIPHER_AlgId`.
- Re-checking the default provider and EAL method tables tightens that conclusion: the public cipher surface enumerates AES, SM4, ChaCha20-Poly1305, and AES-WRAP families, but not DES/3DES.
- `CRYPT_CTRL_DES_NOKEYCHECK` exists in [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L614), but that control constant alone does not create a public DES algorithm surface.
- The openHiTLS crypto tree also has no `crypto/des` directory: [crypto](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto)

## 1. `DES_cbc_cksum`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L82), [cbc_cksm.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/cbc_cksm.c#L18)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L614), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L42), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: DES checksum helpers depend on DES core and key-schedule APIs, and openHiTLS exposes no public DES/3DES cipher surface.

## 2. `DES_cfb_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L101), [cfb_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/cfb_enc.c#L30)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L614)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public DES/3DES cipher IDs or DES CFB contexts.

## 3. `DES_check_key_parity`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L177), [set_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/set_key.c#L71)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L614)
- Verdict: keep `not_available`
- Why: a DES-specific key-parity helper without a public DES key surface would still be unusable, and openHiTLS does not expose that surface.

## 4. `DES_crypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L164), [fcrypt.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/fcrypt.c#L64)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L42)
- Verdict: keep `not_available`
- Why: DES-based password hashing helpers have no public analogue because DES itself is absent from the public cipher surface.

## 5. `DES_decrypt3`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L139), [des_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/des_enc.c#L175)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: triple-DES block helpers have no public analogue because openHiTLS exposes no DES/3DES block-cipher family.

## 6. `DES_ecb3_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L78), [ecb3_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/ecb3_enc.c#L18)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: public EAL tables do not enumerate any DES/3DES ECB family.

## 7. `DES_ede3_cbc_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L142), [des_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/des_enc.c#L200)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: no public DES/3DES CBC family exists in openHiTLS.

## 8. `DES_ede3_cfb64_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L147), [cfb64ede.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/cfb64ede.c#L24)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: no public DES/3DES CFB family exists in openHiTLS.

## 9. `DES_ede3_cfb_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L152), [cfb64ede.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/cfb64ede.c#L91)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: public tables expose no DES/3DES CFB-numbits family.

## 10. `DES_ede3_ofb64_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L157), [ofb64ede.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/ofb64ede.c#L23)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: public tables expose no DES/3DES OFB family.

## 11. `DES_encrypt1`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L121), [des_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/des_enc.c#L20)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: there is no public DES primitive or DES key-schedule surface to anchor a low-level helper.

## 12. `DES_encrypt2`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L134), [des_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/des_enc.c#L91)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: there is no public DES primitive or DES key-schedule surface to anchor a low-level helper.

## 13. `DES_encrypt3`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L136), [des_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/des_enc.c#L155)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: there is no public 3DES primitive or 3DES key-schedule surface to anchor a low-level helper.

## 14. `DES_fcrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L162), [fcrypt.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/fcrypt.c#L97)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: the DES-based password-hash path has no public analogue because openHiTLS exposes no DES/3DES cipher family.

## Batch 071 summary

Keep `not_available`:
- `DES_cbc_cksum`
- `DES_cfb_encrypt`
- `DES_check_key_parity`
- `DES_crypt`
- `DES_decrypt3`
- `DES_ecb3_encrypt`
- `DES_ede3_cbc_encrypt`
- `DES_ede3_cfb64_encrypt`
- `DES_ede3_cfb_encrypt`
- `DES_ede3_ofb64_encrypt`
- `DES_encrypt1`
- `DES_encrypt2`
- `DES_encrypt3`
- `DES_fcrypt`

Main observation:
- DES is absent from the public openHiTLS cipher surface at a stronger level than mere object-model mismatch.
- Even the only DES-shaped public symbol, `CRYPT_CTRL_DES_NOKEYCHECK`, is just a control enum and does not expose a public DES algorithm family.
