# openHiTLS Compatibility Validation Batch 025

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `EVP_EncryptUpdate`
- `EVP_EncryptFinal_ex`
- `EVP_DecryptUpdate`
- `EVP_DecryptFinal_ex`
- `EVP_aes_128_gcm`
- `EVP_aes_256_gcm`
- `EVP_aes_128_cbc`
- `EVP_aes_128_ctr`
- `EVP_aes_256_cbc`

Status:
- completed

Initial evidence:
- OpenSSL update/final entrypoints are declared in [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L759) and implemented in [evp_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/evp_enc.c#L608), where provider-backed paths still preserve the `out/outl/in/inl` contract and boolean-style return semantics.
- openHiTLS exposes the same lifecycle through [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166) and [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L230), but with `in/inLen/out/outLen` ordering, `uint32_t` lengths, and explicit state checks.
- OpenSSL `EVP_aes_*` helpers return `const EVP_CIPHER *` descriptors, while openHiTLS represents algorithm choice with `CRYPT_CIPHER_AlgId` enums in [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150) that are consumed by [CRYPT_EAL_CipherNewCtx](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57).

## 1. `EVP_EncryptUpdate`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L759), [evp_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/evp_enc.c#L608)
- openHiTLS declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L230)
- Verdict: keep `partial`
- Why: the functional stage is the same, but caller adaptation is required for argument order, length type, and the fact that algorithm binding already happened during ctx creation/init on the openHiTLS side.

## 2. `EVP_EncryptFinal_ex`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L761), [evp_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/evp_enc.c#L670)
- openHiTLS declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L269)
- Verdict: keep `partial`
- Why: both finalize pending block-mode state, but openHiTLS returns status codes and `uint32_t *outLen`, while OpenSSL uses `int *outl` plus OpenSSL-specific padding/error reporting.

## 3. `EVP_DecryptUpdate`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L776), [evp_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/evp_enc.c#L756)
- openHiTLS declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L230)
- Verdict: keep `partial`
- Why: same update-stage functionality, but the contract mismatch is the same as `EVP_EncryptUpdate`, and OpenSSL preserves extra provider/legacy behavior around buffered final blocks.

## 4. `EVP_DecryptFinal_ex`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L780), [evp_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/evp_enc.c#L890)
- openHiTLS declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L269)
- Verdict: keep `partial`
- Why: openHiTLS finalization covers padding removal and state transition, but return/error semantics differ and OpenSSL's decrypt-final path carries its own final-block validation model.

## 5. `EVP_aes_128_gcm`
- OpenSSL declaration/legacy registration: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1021), [c_allc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/c_allc.c#L143)
- openHiTLS declaration/implementation: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L169), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [eal_cipher_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher_method.c#L303)
- Verdict: keep `partial`
- Why: openHiTLS supports the same algorithm, but as an enum ID fed into `CRYPT_EAL_CipherNewCtx`, not as an `EVP_CIPHER *` descriptor-returning helper.

## 6. `EVP_aes_256_gcm`
- OpenSSL declaration/legacy registration: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1052), [c_allc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/c_allc.c#L178)
- openHiTLS declaration/implementation: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L171), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [eal_cipher_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher_method.c#L305)
- Verdict: keep `partial`
- Why: same reason as `EVP_aes_128_gcm`.

## 7. `EVP_aes_128_cbc`
- OpenSSL declaration/legacy registration: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1013), [c_allc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/c_allc.c#L137)
- openHiTLS declaration/implementation: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [eal_cipher_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher_method.c#L283)
- Verdict: keep `partial`
- Why: same algorithm is present, but the API shape is enum-plus-ctx construction rather than function-pointer descriptor lookup.

## 8. `EVP_aes_128_ctr`
- OpenSSL declaration/legacy registration: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1019), [c_allc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/c_allc.c#L142)
- openHiTLS declaration/implementation: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L154), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [eal_cipher_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher_method.c#L293)
- Verdict: keep `partial`
- Why: same algorithm availability, but still an algorithm-ID selection model instead of OpenSSL's `EVP_CIPHER *`.

## 9. `EVP_aes_256_cbc`
- OpenSSL declaration/legacy registration: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1044), [c_allc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/c_allc.c#L172)
- openHiTLS declaration/implementation: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L152), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [eal_cipher_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher_method.c#L285)
- Verdict: keep `partial`
- Why: same reason as `EVP_aes_128_cbc`.

## Batch 025 summary

Keep `partial`:
- `EVP_EncryptUpdate`
- `EVP_EncryptFinal_ex`
- `EVP_DecryptUpdate`
- `EVP_DecryptFinal_ex`
- `EVP_aes_128_gcm`
- `EVP_aes_256_gcm`
- `EVP_aes_128_cbc`
- `EVP_aes_128_ctr`
- `EVP_aes_256_cbc`

Main observation:
- This family is functionally covered by openHiTLS public APIs.
- The reason it stays `partial` is API-shape mismatch, not missing cipher capability: OpenSSL uses descriptor-returning helpers and `int`-style EVP contracts, while openHiTLS uses typed algorithm IDs plus `CRYPT_EAL_*` status/outparam workflows.
