# openHiTLS Compatibility Validation Batch 003

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `EVP_PKEY_new`
- `EVP_PKEY_free`
- `EVP_PKEY_CTX_new`
- `EVP_PKEY_CTX_free`
- `EVP_PKEY_CTX_new_id`
- `EVP_PKEY_derive_init`
- `EVP_PKEY_derive`
- `EVP_PKEY_CTX_set_hkdf_md`
- `EVP_PKEY_CTX_set1_hkdf_key`
- `EVP_PKEY_CTX_set1_hkdf_salt`
- `EVP_PKEY_CTX_add1_hkdf_info`
- `EVP_PKEY_CTX_hkdf_mode`
- `RSA_new`
- `RSA_free`
- `DH_free`
- `EC_KEY_free`
- `EC_POINT_new`
- `EC_GROUP_free`
- `EC_KEY_get0_group`

Status:
- completed

Execution split:
- PKEY lifecycle:
  - `EVP_PKEY_new`
  - `EVP_PKEY_free`
  - `EVP_PKEY_CTX_new`
  - `EVP_PKEY_CTX_free`
  - `EVP_PKEY_CTX_new_id`
  - `RSA_new`
  - `RSA_free`
  - `DH_free`
  - `EC_KEY_free`
- Derive / HKDF / low-level EC:
  - `EVP_PKEY_derive_init`
  - `EVP_PKEY_derive`
  - `EVP_PKEY_CTX_set_hkdf_md`
  - `EVP_PKEY_CTX_set1_hkdf_key`
  - `EVP_PKEY_CTX_set1_hkdf_salt`
  - `EVP_PKEY_CTX_add1_hkdf_info`
  - `EVP_PKEY_CTX_hkdf_mode`
  - `EC_POINT_new`
  - `EC_GROUP_free`
  - `EC_KEY_get0_group`

Rule reminder:
- `available`: near-direct public replacement with thin adaptation only.
- `partial`: public openHiTLS API can realize the function, but signature, object model, or lifecycle differs materially.
- `not_available`: no direct public openHiTLS API for the OpenSSL symbol.
- Functional equivalence takes precedence over style equivalence, but direct-public-API absence still prevents `available`.

## 1. `EVP_PKEY_new`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyNewCtx`

Verified evidence:
- OpenSSL declaration: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1378)
- openHiTLS declaration: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132)
- openHiTLS algorithm enum: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L386)
- openHiTLS implementation entry: [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L74)

Verdict:
- Keep `partial`

Why:
- openHiTLS exposes public key-context creation, but requires algorithm identity at creation time.
- OpenSSL `EVP_PKEY_new()` creates an untyped generic container.
- Functionally replaceable, not API-shape equivalent.

## 2. `EVP_PKEY_free`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyFreeCtx`

Verified evidence:
- OpenSSL declaration: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1381)
- openHiTLS declaration: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L180)
- implementation: [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L167)

Verdict:
- Keep `partial`

Why:
- Public free exists, but for `CRYPT_EAL_PkeyCtx *`, not `EVP_PKEY *`.
- Same lifecycle role, different object model.

## 3. `EVP_PKEY_CTX_new`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyNewCtx`

Verified evidence:
- OpenSSL declaration: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1774)
- openHiTLS declaration: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132)
- implementation: [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L74)

Verdict:
- Keep `partial`

Why:
- OpenSSL constructs a context from an existing `EVP_PKEY`.
- openHiTLS constructs a generic pkey context from algorithm identity.

## 4. `EVP_PKEY_CTX_free`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyFreeCtx`

Verified evidence:
- OpenSSL declaration: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1782)
- openHiTLS declaration: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L180)
- implementation: [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L167)

Verdict:
- Keep `partial`

## 5. `EVP_PKEY_CTX_new_id`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyNewCtx`

Verified evidence:
- OpenSSL declaration: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1775)
- openHiTLS declaration: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132)
- openHiTLS algorithm enum domain: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L386)

Verdict:
- Keep `partial`

Why:
- Same high-level purpose, but OpenSSL uses NID + ENGINE, openHiTLS uses `CRYPT_PKEY_AlgId`.

## 6. `EVP_PKEY_derive_init`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyNewCtx`

Verified evidence:
- OpenSSL declaration: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1917)
- openHiTLS declarations: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L228)
- implementation entry: [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L74)

Verdict:
- Keep `partial`

Why:
- openHiTLS has no dedicated derive-init API.
- Equivalent setup is composed from public pkey context creation plus parameter setup.

## 7. `EVP_PKEY_derive`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyComputeShareKey`

Verified evidence:
- OpenSSL declaration: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1922)
- openHiTLS declaration: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L537)
- implementation entry: [eal_pkey_computesharekey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_computesharekey.c#L27)

Verdict:
- Keep `partial`

Why:
- Shared-secret derivation exists publicly.
- Signature differs: two key contexts plus output-length pointer vs OpenSSL context-centric derive API.

## 8. `EVP_PKEY_CTX_set_hkdf_md`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyCtrl`

Verified evidence:
- OpenSSL declaration: [kdf.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/kdf.h#L105)
- openHiTLS public KDF creation: [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L69)
- public KDF parameter API: [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L81)
- HKDF MAC param: [crypt_params_key.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_params_key.h#L47)
- implementation evidence: [eal_kdf.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_kdf.c#L110), [hkdf.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hkdf/src/hkdf.c#L290)

Verdict:
- Keep `partial`

Why:
- Supported through generic KDF parameterization, not dedicated PKEY_CTX helper.

## 9. `EVP_PKEY_CTX_set1_hkdf_key`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyCtrl`

Verified evidence:
- OpenSSL declaration: [kdf.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/kdf.h#L110)
- openHiTLS public KDF parameter API: [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L81)
- HKDF key param: [crypt_params_key.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_params_key.h#L51)
- implementation evidence: [hkdf.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hkdf/src/hkdf.c#L302)

Verdict:
- Keep `partial`

## 10. `EVP_PKEY_CTX_set1_hkdf_salt`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyCtrl`

Verified evidence:
- OpenSSL declaration: [kdf.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/kdf.h#L107)
- HKDF salt param: [crypt_params_key.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_params_key.h#L48)
- implementation evidence: [hkdf.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hkdf/src/hkdf.c#L305)

Verdict:
- Keep `partial`

## 11. `EVP_PKEY_CTX_add1_hkdf_info`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [kdf.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/kdf.h#L113)
- openHiTLS public KDF parameter API: [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L81)
- HKDF info param: [crypt_params_key.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_params_key.h#L53)
- implementation evidence: [hkdf.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hkdf/src/hkdf.c#L311)

Verdict:
- Change to `partial`

Why:
- Functionality exists through public generic KDF parameter API.
- No dedicated append-style helper exists, so still not `available`.

## 12. `EVP_PKEY_CTX_hkdf_mode`

Current JSON:
- missing

Verified evidence:
- OpenSSL declaration: [kdf.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/kdf.h#L124)
- openHiTLS HKDF mode enum: [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L911)
- openHiTLS KDF mode param: [crypt_params_key.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_params_key.h#L50)
- openHiTLS generic KDF setparam API: [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L81)
- implementation evidence: [hkdf.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hkdf/src/hkdf.c#L296)

Verdict:
- Add as `partial`

Why:
- HKDF mode is publicly controllable through generic parameterization, but not through a dedicated one-call OpenSSL-style helper.

## 13. `RSA_new`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA)`

Verified evidence:
- OpenSSL declaration: [rsa.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rsa.h#L201)
- openHiTLS public pkey constructor: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132)
- openHiTLS RSA alg id: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L125)
- implementation entry: [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L74)

Verdict:
- Keep `partial`

Why:
- No low-level `RSA *` API is exposed publicly, but public generic pkey creation provides the same high-level construction capability when caller adapts to the generic key model.

## 14. `RSA_free`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyFreeCtx`

Verified evidence:
- OpenSSL declaration: [rsa.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rsa.h#L293)
- openHiTLS public pkey free: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L180)
- implementation entry: [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L167)

Verdict:
- Keep `partial`

## 15. `DH_free`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyFreeCtx`

Verified evidence:
- OpenSSL declaration: [dh.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/dh.h#L200)
- openHiTLS public pkey free: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L180)
- openHiTLS generic pkey family applies to DH through alg id set

Verdict:
- Keep `partial`

## 16. `EC_KEY_free`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_PkeyFreeCtx`

Verified evidence:
- OpenSSL declaration: [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L1003)
- openHiTLS public pkey free: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L180)

Verdict:
- Keep `partial`

## 17. `EC_POINT_new`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L544)
- openHiTLS public ECC low-level point constructor: [crypt_ecc.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc.h#L101)
- implementation entry: [ecc.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc.c#L61)

Verdict:
- Change to `partial`

Why:
- A public low-level point constructor exists.
- Object model differs (`EC_POINT` vs `ECC_Point` with `ECC_Para`), so not `available`.

## 18. `EC_GROUP_free`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L194)
- openHiTLS public ECC parameter free: [crypt_ecc.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc.h#L70)
- implementation entry: [ecc_para.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_para.c#L697)

Verdict:
- Change to `partial`

## 19. `EC_KEY_get0_group`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L1034)
- openHiTLS public ECC parameter query: [crypt_ecc_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc_pkey.h#L91)
- implementation entry: [ecc_para.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_para.c#L631)

Verdict:
- Change to `partial`

Why:
- openHiTLS can expose curve parameters through a public query API, but not a zero-copy getter returning the same object type as OpenSSL.

## Batch 003 summary

Keep current status verdicts:
- `EVP_PKEY_new`
- `EVP_PKEY_free`
- `EVP_PKEY_CTX_new`
- `EVP_PKEY_CTX_free`
- `EVP_PKEY_CTX_new_id`
- `EVP_PKEY_derive_init`
- `EVP_PKEY_derive`
- `EVP_PKEY_CTX_set_hkdf_md`
- `EVP_PKEY_CTX_set1_hkdf_key`
- `EVP_PKEY_CTX_set1_hkdf_salt`
- `RSA_new`
- `RSA_free`
- `DH_free`
- `EC_KEY_free`

Change current status verdicts:
- `EVP_PKEY_CTX_add1_hkdf_info`: `not_available` -> `partial`
- `EVP_PKEY_CTX_hkdf_mode`: `missing` -> `partial`
- `EC_POINT_new`: `not_available` -> `partial`
- `EC_GROUP_free`: `not_available` -> `partial`
- `EC_KEY_get0_group`: `not_available` -> `partial`

Main observation:
- Batch 003 confirms the generic pkey / KDF / ECC public APIs are sufficient to keep most of this family in `partial`, not `not_available`, under the functional-equivalence-first rule.
