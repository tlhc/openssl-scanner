# openHiTLS Compatibility Validation Batch 265

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- report-side unknown mixed crypto utility tails:
  - `BIO_*` convenience helpers
  - `EVP_*` legacy descriptor/meta helpers
  - `ERR_*`
  - `CRYPTO_*` legacy thread-id callbacks
  - `ENGINE_*`
  - low-level error macros such as `RSAerr` and `SSLerr`

Status:
- completed

Initial evidence:
- OpenSSL exposes BIO helpers, legacy EVP descriptor helpers, engine hooks, and low-level error helpers in:
  - [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L631)
  - [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1172)
  - [crypto.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/crypto.h.in#L106)
  - [engine.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/engine.h#L336)
- openHiTLS public installed surface exposes adjacent UIO, SAL, ERR, EAL cipher/md/pkey, and bootstrap APIs in:
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L99)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L187)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L202)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L562)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L609)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L632)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L228)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L239)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L265)
  - [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L259)
  - [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L220)
  - [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L252)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L181)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L239)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L549)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L560)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L571)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L639)
  - [crypt_eal_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_init.h#L51)

Verdict:
- set `available = 1`
- set `partial = 52`
- set `not_available = 86`

Reasoning boundary:
- `available` is justified for:
  - `EVP_CIPHER_CTX_block_size`
    - direct public ctx-level block-size query exists through `CRYPT_EAL_CipherCtrl(CRYPT_CTRL_GET_BLOCKSIZE)`
- `partial` is justified where openHiTLS exposes a practical adjacent public path:
  - BIO fd/file/memory/pair/connect/accept/retry helpers through `BSL_UIO_Ctrl`, `BSL_UIO_SetFlags`, `BSL_UIO_TestFlags`, and `BSL_UIO_SetIsUnderlyingClosedByUio`
  - allocator/bootstrap helpers through `BSL_SAL_Dump`, `BSL_SAL_Realloc`, `BSL_SAL_Calloc`, `BSL_ERR_RemoveErrStringBatch`, and `CRYPT_EAL_Cleanup`
  - EVP cipher/md/pkey meta queries and key-generation helpers through `CRYPT_EAL_CipherGetInfo`, `CRYPT_EAL_MdGetDigestSize`, `CRYPT_EAL_PkeyGen`, `CRYPT_EAL_PkeyGetId`, `CRYPT_EAL_PkeyGetKeyBits`, `CRYPT_EAL_PkeyGetSecurityBits`, and `CRYPT_EAL_PkeyGetKeyLen`
  - installed CFB algorithm coverage for `AES-{128,192,256}-CFB` and `SM4-CFB`
- these stay `partial` because the public contract still differs in one or more of:
  - OpenSSL BIO helper macros/functions versus explicit openHiTLS UIO ctrl operations
  - OpenSSL descriptor objects (`EVP_CIPHER *`, `EVP_MD *`, `EVP_PKEY *`) versus openHiTLS algorithm ids or PkeyCtx objects
  - OpenSSL one-call helper APIs versus small composed public paths
- `not_available` remains correct for:
  - `ENGINE_*`
  - low-level error-construction helpers such as `ERR_put_error`, `RSAerr`, and `SSLerr`
  - `RSA_get_ex_new_index` / `DSA_get_ex_new_index`
  - legacy CFB helpers without installed public algorithm ids
  - EVP descriptor/provider metadata helpers with no public openHiTLS equivalent
  - CRYPTO thread-id callback registration helpers
  - advanced BIO helpers where the current openHiTLS UIO surface stops earlier

Representative evidence:
- OpenSSL declarations:
  - [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L631)
  - [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1172)
  - [crypto.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/crypto.h.in#L106)
  - [engine.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/engine.h#L336)
- openHiTLS public declarations:
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L99)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L187)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L202)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L562)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L609)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L632)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L228)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L239)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L265)
  - [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L259)
  - [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L220)
  - [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L252)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L181)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L239)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L549)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L560)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L571)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L639)
  - [crypt_eal_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_init.h#L51)

Batch 265 inventory:
- total interfaces: `139`
- `available = 1`
- `partial = 52`
- `not_available = 86`
