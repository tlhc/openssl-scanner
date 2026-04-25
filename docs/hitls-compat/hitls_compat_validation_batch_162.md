# openHiTLS Compatibility Validation Batch 162

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `EVP_PKEY_CTX_*` entries lacking `analysis_doc`
- this batch covers the ctrl/get/set family that remained after the core `EVP_PKEY_CTX` lifecycle batch

Status:
- completed

Initial evidence:
- OpenSSL exposes these helpers as a large ctrl-dispatch family in [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1519), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1661), [rsa.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/rsa.h#L122), and [kdf.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/kdf.h#L105).
- openHiTLS exposes a public generic pkey ctrl surface in [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L596), with the relevant ctrl namespace documented in [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L631).
- Public ctrl commands cover the main replacement surface needed by this batch:
  - generic parameter selection and generation: [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L631), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L645)
  - signature-md selection: [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L648)
  - RSA padding / OAEP / PSS getters and setters: [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L657), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L664), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L673)
  - ECC point format / cofactor / curve-name getters and setters: [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L649), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L688), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L702)
- The implementation evidence lines up with that public ctrl model in [rsa_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_ctrl.c#L591), [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L610), [dsa_core.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/dsa/src/dsa_core.c#L1611), and [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L279).
- No public string-driven or hex-driven helper surface was found corresponding to OpenSSL's `EVP_PKEY_CTX_ctrl_str`, `EVP_PKEY_CTX_hex2ctrl`, or `EVP_PKEY_CTX_md`.

Verdict:
- keep `partial`:
  - `88` interfaces in this batch
  - this covers the main ctrl/get/set helpers where openHiTLS has a practical public replacement path through `CRYPT_EAL_PkeyCtrl`
- keep `not_available`:
  - `6` interfaces
  - `EVP_PKEY_CTX_add1_tls1_prf_seed`
  - `EVP_PKEY_CTX_ctrl_str`
  - `EVP_PKEY_CTX_ctrl_uint64`
  - `EVP_PKEY_CTX_hex2ctrl`
  - `EVP_PKEY_CTX_md`
  - `EVP_PKEY_CTX_str2ctrl`

Reasoning boundary:
- The `partial` majority is still correct because openHiTLS does expose a practical public replacement path, but it is ctrl-dispatch based rather than OpenSSL's helper-by-helper `EVP_PKEY_CTX_*` API shape.
- The 6 `not_available` entries remain outside that boundary because openHiTLS does not expose:
  - string-based ctrl dispatch
  - hex-string ctrl dispatch
  - the generic md-name helper surface
  - a direct analogue for TLS1 PRF seed accumulation
