# openHiTLS Compatibility Validation Batch 036

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `EC_KEY_new_by_curve_name`
- `EC_GROUP_get_curve_name`
- `EC_KEY_generate_key`
- `EC_KEY_get0_private_key`
- `EC_KEY_get0_public_key`
- `EC_GROUP_new_by_curve_name`
- `EC_KEY_new`
- `EC_KEY_set_group`

Status:
- completed

Initial evidence:
- This is the next coherent EC-heavy cluster without `analysis_doc`.
- Current scan aggregation shows:
  - `EC_KEY_new_by_curve_name`: 10 repos
  - `EC_GROUP_get_curve_name`: 8 repos
  - `EC_KEY_generate_key`: 8 repos
  - `EC_KEY_get0_private_key`: 8 repos
  - `EC_KEY_get0_public_key`: 8 repos
  - `EC_GROUP_new_by_curve_name`: 7 repos
  - `EC_KEY_new`: 7 repos
  - `EC_KEY_set_group`: 7 repos
- The common pattern is the same one we already adopted for other low-level families:
  - OpenSSL exposes raw `EC_GROUP *` / `EC_KEY *` object APIs
  - openHiTLS exposes generic `CRYPT_EAL_PkeyCtx` plus `paraId`, `PkeyGetPrv/Pub`, and `PkeyCtrl` helpers

## 1. `EC_KEY_new_by_curve_name`
- OpenSSL declaration/implementation: [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L998), [ec_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/ec/ec_key.c#L64)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L228), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L100), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L276)
- Verdict: keep `partial`
- Why: the closest public path is composed:
  - `CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA)`
  - `CRYPT_EAL_PkeySetParaById(CRYPT_ECC_*)`
  Same purpose, different object model.

## 2. `EC_GROUP_get_curve_name`
- OpenSSL declaration/implementation: [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L278), [ec_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/ec/ec_lib.c#L489)
- openHiTLS declaration/implementation: [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L702), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L596), [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L524), [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L603)
- Verdict: change to `partial`
- Why: openHiTLS does not expose an `EC_GROUP *`, but callers can query the configured curve name through `CRYPT_EAL_PkeyCtrl(..., CRYPT_CTRL_GET_ECC_NAME, ...)`.

## 3. `EC_KEY_generate_key`
- OpenSSL declaration/implementation: [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L1101), [ec_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/ec/ec_key.c#L209)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L239), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L282)
- Verdict: keep `partial`
- Why: openHiTLS can generate EC keys through the generic pkey ctx, not on a raw `EC_KEY *`.

## 4. `EC_KEY_get0_private_key`
- OpenSSL declaration/implementation: [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L1048), [ec_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/ec/ec_key.c#L690)
- openHiTLS declaration/implementation: [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L275), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L332), [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L176), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L431)
- Verdict: change to `partial`
- Why: openHiTLS can export the EC private key scalar through `CRYPT_EAL_PkeyGetPrv(...).key.eccPrv`, but not as a zero-copy `BIGNUM *` getter.

## 5. `EC_KEY_get0_public_key`
- OpenSSL declaration/implementation: [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L1062), [ec_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/ec/ec_key.c#L790)
- openHiTLS declaration/implementation: [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L414), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L305), [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L191), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L414)
- Verdict: change to `partial`
- Why: openHiTLS can export the encoded EC public point through `CRYPT_EAL_PkeyGetPub(...).key.eccPub`, but not as a zero-copy `EC_POINT *` getter.

## 6. `EC_GROUP_new_by_curve_name`
- OpenSSL declaration/implementation: [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L480), [ec_curve.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/ec/ec_curve.c#L3301)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L228), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L100), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L276)
- Verdict: change to `partial`
- Why: openHiTLS has no standalone `EC_GROUP *`, but callers can create a pkey ctx and bind the same curve parameter ID, which is the public equivalent for downstream use.

## 7. `EC_KEY_new`
- OpenSSL declaration/implementation: [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L968), [ec_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/ec/ec_key.c#L33)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L100), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L127)
- Verdict: keep `partial`
- Why: `CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA)` is the closest public creation path, but it requires explicit algorithm selection.

## 8. `EC_KEY_set_group`
- OpenSSL declaration/implementation: [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L1042), [ec_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/ec/ec_key.c#L677)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L228), [eal_pkey_gen.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_gen.c#L276)
- Verdict: keep `partial`
- Why: curve binding on openHiTLS is done through `CRYPT_EAL_PkeySetParaById`, not by attaching an `EC_GROUP *` object to an `EC_KEY *`.

## Batch 036 summary

Change to `partial`:
- `EC_GROUP_get_curve_name`
- `EC_KEY_get0_private_key`
- `EC_KEY_get0_public_key`
- `EC_GROUP_new_by_curve_name`

Keep `partial`:
- `EC_KEY_new_by_curve_name`
- `EC_KEY_generate_key`
- `EC_KEY_new`
- `EC_KEY_set_group`

Main observation:
- This batch confirms the same rule we used elsewhere:
  - different object model is not the same as missing functionality
- openHiTLS does expose enough public ECC value-level APIs to count these as compatible at the function level, but never as raw `EC_GROUP *` / `EC_KEY *` drop-ins.
