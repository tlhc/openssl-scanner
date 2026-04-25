# openHiTLS Compatibility Validation Batch 030

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `EVP_PKEY_set1_RSA`
- `RSA_set0_key`
- `EVP_PKEY_CTX_set_rsa_padding`
- `RSA_generate_key_ex`
- `RSA_size`

Status:
- completed

Initial evidence:
- This family is the next high-value coherent group among entries that lacked `analysis_doc`.
- Current scan aggregation shows:
  - `EVP_PKEY_set1_RSA`: 13 repos
  - `RSA_set0_key`: 10 repos
  - `EVP_PKEY_CTX_set_rsa_padding`: 10 repos
  - `RSA_generate_key_ex`: 9 repos
  - `RSA_size`: 9 repos
- All five map into the same openHiTLS abstraction boundary: generic `CRYPT_EAL_PkeyCtx` plus `SetPub/SetPrv/Ctrl/Gen/GetKeyLen`.

## 1. `EVP_PKEY_set1_RSA`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1344), [p_legacy.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/p_legacy.c#L25)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L251), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L278), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L321), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L338)
- Verdict: keep `partial`
- Why: openHiTLS can import RSA key material into a generic `CRYPT_EAL_PkeyCtx`, but not by attaching an `RSA *` object to an `EVP_PKEY`. Callers must translate into openHiTLS public/private key parameter structures first.

## 2. `RSA_set0_key`
- OpenSSL declaration/implementation: [rsa.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rsa.h#L207), [rsa_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rsa/rsa_lib.c#L392)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L251), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L278), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L321), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L338)
- Verdict: keep `partial`
- Why: openHiTLS can set RSA key components only through generic `PkeySetPub/PkeySetPrv` APIs. It does not expose OpenSSL's ownership-transfer semantics for `BIGNUM *n, *e, *d` on a raw `RSA *`.

## 3. `EVP_PKEY_CTX_set_rsa_padding`
- OpenSSL declaration/implementation: [rsa.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rsa.h#L119), [rsa_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rsa/rsa_lib.c#L957)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L596), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L664), [rsa_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_ctrl.c#L620)
- Verdict: keep `partial`
- Why: openHiTLS can control RSA padding through `CRYPT_EAL_PkeyCtrl(..., CRYPT_CTRL_SET_RSA_PADDING, ...)`, but the option model is generic ctrl-based and not OpenSSL's dedicated `EVP_PKEY_CTX_*` helper API.

## 4. `RSA_generate_key_ex`
- OpenSSL declaration/implementation: [rsa.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rsa.h#L260), [rsa_gen.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rsa/rsa_gen.c#L41)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L239), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L282)
- Verdict: keep `partial`
- Why: openHiTLS can generate RSA keys through generic pkey generation, but not on a raw `RSA *` object with explicit `BIGNUM *e` and callback parameters.

## 5. `RSA_size`
- OpenSSL declaration/implementation: [rsa.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rsa.h#L204), [rsa_crpt.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rsa/rsa_crpt.c#L28)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L549), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L455)
- Verdict: keep `partial`
- Why: openHiTLS can return RSA key length in bytes through `CRYPT_EAL_PkeyGetKeyLen`, but only on a generic `CRYPT_EAL_PkeyCtx`, not on a raw `RSA *`.

## Batch 030 summary

Keep `partial`:
- `EVP_PKEY_set1_RSA`
- `RSA_set0_key`
- `EVP_PKEY_CTX_set_rsa_padding`
- `RSA_generate_key_ex`
- `RSA_size`

Main observation:
- This batch is another generic-wrapper mismatch:
  - OpenSSL exposes RSA-specific object APIs
  - openHiTLS exposes generic pkey ctx APIs
- Functionality is present, but none of these five are API-identical enough to upgrade beyond `partial`.
