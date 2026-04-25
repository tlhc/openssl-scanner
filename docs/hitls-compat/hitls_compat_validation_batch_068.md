# openHiTLS Compatibility Validation Batch 068

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `AES_set_encrypt_key`
- `AES_set_decrypt_key`
- `AES_encrypt`
- `AES_decrypt`
- `AES_ecb_encrypt`
- `AES_cbc_encrypt`

Status:
- completed

Initial evidence:
- This batch moves past the fully documented BN family and starts the next coherent non-BN legacy API surface.
- The initial expectation is that openHiTLS will only provide higher-level cipher/EAL APIs rather than OpenSSL's low-level AES key schedule and block helpers.

## 1. `AES_set_encrypt_key`
- OpenSSL declaration: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L51)
- openHiTLS public declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L158), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L90), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L117)
- Verdict: change to `partial`
- Why: openHiTLS can initialize an AES cipher context with the raw key, but it does not expose a standalone `AES_KEY` schedule API.

## 2. `AES_set_decrypt_key`
- OpenSSL declaration: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L54)
- openHiTLS public declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L158), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L90), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L117)
- Verdict: change to `partial`
- Why: openHiTLS can initialize an AES cipher context for decryption, but it does not expose a standalone `AES_KEY` schedule API.

## 3. `AES_encrypt`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L57), [aes_core.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_core.c#L667)
- openHiTLS public declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L158), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L90), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L117), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L230), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L269)
- Verdict: change to `partial`
- Why: openHiTLS can perform the same ECB block encryption flow through the public EAL cipher API, but not through OpenSSL's low-level `AES_KEY`-based single-block helper.

## 4. `AES_decrypt`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L60), [aes_core.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_core.c#L682)
- openHiTLS public declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L158), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L90), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L117), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L230), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L269)
- Verdict: change to `partial`
- Why: openHiTLS can perform the same ECB block decryption flow through the public EAL cipher API, but not through OpenSSL's low-level `AES_KEY`-based single-block helper.

## 5. `AES_ecb_encrypt`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L63), [aes_ecb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_ecb.c#L21)
- openHiTLS public declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L158), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L90), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L117), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L230), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L269)
- Verdict: change to `partial`
- Why: openHiTLS can perform the ECB operation through the public EAL cipher API, but not through OpenSSL's low-level helper signature.

## 6. `AES_cbc_encrypt`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L66), [aes_cbc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_cbc.c#L20)
- openHiTLS public declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L90), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L117), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L230), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L269)
- Verdict: change to `partial`
- Why: openHiTLS can perform the CBC operation through the public EAL cipher API, but not through OpenSSL's low-level helper signature.

## Batch 068 summary

Change to `partial`:
- `AES_set_encrypt_key`
- `AES_set_decrypt_key`
- `AES_encrypt`
- `AES_decrypt`
- `AES_ecb_encrypt`
- `AES_cbc_encrypt`

Main observation:
- This is not a “no support” family.
- The functionality exists publicly in openHiTLS, but only through higher-level EAL cipher contexts, not OpenSSL's legacy low-level `AES_KEY` helpers.
