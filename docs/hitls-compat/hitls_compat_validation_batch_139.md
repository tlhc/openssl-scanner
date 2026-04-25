# openHiTLS Compatibility Validation Batch 139

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BIO_f_base64`
- `EVP_ENCODE_CTX_new`
- `EVP_ENCODE_CTX_free`
- `EVP_DecodeInit`
- `EVP_DecodeUpdate`
- `EVP_DecodeFinal`
- `OPENSSL_cleanse`
- `CRYPTO_memcmp`
- `EVP_aes_192_ctr`
- `EVP_aes_192_gcm`
- `EVP_get_cipherbyname`
- `EVP_CIPHER_CTX_set_key_length`
- `d2i_PUBKEY`
- `EVP_VerifyFinal`

Status:
- completed

Initial evidence:
- OpenSSL publishes Base64 ctx helpers and filter helpers in [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L852) and [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L890), utility helpers in [crypto.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/crypto.h.in#L344) and [crypto.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/crypto.h.in#L422), cipher helpers in [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L876), [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1035), [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1037), and [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1171), key decode in [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L513), and verify-final in [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L810).
- openHiTLS exposes direct public Base64 context APIs in [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L77), [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L86), [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L138), [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L151), and [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L162).
- openHiTLS exposes direct public memory-cleansing helpers in [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L274) and [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L283).
- openHiTLS exposes AES-192 CTR/GCM algorithm ids in [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L155) and [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L170), and public key decode in [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L184) and [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L217), implemented in [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L403).
- openHiTLS exposes public verify-by-hash composition in [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L420).
- No public constant-time compare helper and no public cipher-by-name lookup helper were found in openHiTLS.

Verdict:
- adjust to `available`:
  - `EVP_ENCODE_CTX_new`
  - `EVP_ENCODE_CTX_free`
  - `EVP_DecodeInit`
  - `EVP_DecodeUpdate`
  - `EVP_DecodeFinal`
  - `OPENSSL_cleanse`
  - `d2i_PUBKEY`
- keep `partial`:
  - `BIO_f_base64`
  - `EVP_aes_192_ctr`
  - `EVP_aes_192_gcm`
  - `EVP_VerifyFinal`
- keep `not_available`:
  - `CRYPTO_memcmp`
  - `EVP_get_cipherbyname`
  - `EVP_CIPHER_CTX_set_key_length`
