# openHiTLS Compatibility Validation Batch 043

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_BLINDING_convert_ex`
- `BN_BLINDING_invert_ex`
- `BN_BLINDING_create_param`
- `BN_BLINDING_get_flags`
- `BN_BLINDING_is_current_thread`
- `BN_BLINDING_set_current_thread`
- `BN_BLINDING_lock`
- `BN_BLINDING_unlock`

Status:
- completed

Initial evidence:
- This batch stays inside the same BN blinding family but targets the remaining handle-centric helpers.
- Batch 042 already established the likely split:
  - public pkey-level blind/unblind may justify `partial` for workflow-level functions
  - handle lifecycle, threading, and flag helpers are likely to remain `not_available` unless a public control surface exists.

## 1. `BN_BLINDING_convert_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L423), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L134)
- openHiTLS public declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L596), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L612), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L677), [rsa_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_ctrl.c#L523), [eal_pkey_sign.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_sign.c#L142), [rsa_encdec.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_encdec.c#L641)
- Verdict: change to `partial`
- Why: openHiTLS can approximate explicit-factor blinding by setting RSA-BSSA factor `r` on the pkey context and then calling `CRYPT_EAL_PkeyBlind()`. That is still a pkey/byte-buffer workflow, not an OpenSSL `BN_BLINDING *` plus `BIGNUM *` contract.

## 2. `BN_BLINDING_invert_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L424), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L167)
- openHiTLS public declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L596), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L628), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L677), [rsa_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_ctrl.c#L523), [eal_pkey_sign.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_sign.c#L160), [rsa_encdec.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_encdec.c#L713)
- Verdict: change to `partial`
- Why: openHiTLS can approximate explicit-factor unblinding by installing RSA-BSSA factor `r` on the pkey context and then calling `CRYPT_EAL_PkeyUnBlind()`. It still does not expose a `BN_BLINDING` handle or explicit `BIGNUM *r` API.

## 3. `BN_BLINDING_create_param`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L434), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L234)
- openHiTLS public/internal declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L596), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L677), [rsa_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_ctrl.c#L523), [rsa_encdec.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_encdec.c#L570), [rsa_encdec.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_encdec.c#L577)
- Verdict: change to `partial`
- Why: openHiTLS can create blind parameters on a pkey context either explicitly with `CRYPT_CTRL_SET_RSA_BSSA_FACTOR_R` or implicitly on first `CRYPT_EAL_PkeyBlind()`. It does not expose a standalone `BN_BLINDING_create_param()` equivalent over a reusable blinding handle.

## 4. `BN_BLINDING_get_flags`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L432), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L224)
- openHiTLS public evidence: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L596), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L667), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L676), [rsa_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_ctrl.c#L304), [rsa_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_ctrl.c#L315), [rsa_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_ctrl.c#L487)
- Verdict: keep `not_available`
- Why: openHiTLS has public RSA flag set/clear on key contexts, but no getter for BN-blinding-handle flags and no equivalent to `BN_BLINDING_get_flags()`.

## 5. `BN_BLINDING_is_current_thread`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L427), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L204)
- openHiTLS internal evidence: [rsa_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_local.h#L36)
- Verdict: keep `not_available`
- Why: no matching public or internal thread-affinity helper exists. openHiTLS internal `RSA_Blind` stores only `r` and `rInv`.

## 6. `BN_BLINDING_set_current_thread`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L428), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L209)
- openHiTLS internal evidence: [rsa_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_local.h#L36)
- Verdict: keep `not_available`
- Why: openHiTLS has no matching thread-binding helper and no thread-id field on its internal `RSA_Blind`.

## 7. `BN_BLINDING_lock`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L429), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L214)
- openHiTLS internal evidence: [rsa_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_local.h#L36)
- Verdict: keep `not_available`
- Why: openHiTLS has no lock field or lock helper on RSA blinding handles.

## 8. `BN_BLINDING_unlock`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L430), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L219)
- openHiTLS internal evidence: [rsa_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_local.h#L36)
- Verdict: keep `not_available`
- Why: same object-model gap as `BN_BLINDING_lock`; there is no unlock helper on openHiTLS blinding state.

## Batch 043 summary

Change to `partial`:
- `BN_BLINDING_convert_ex`
- `BN_BLINDING_invert_ex`
- `BN_BLINDING_create_param`

Keep `not_available`:
- `BN_BLINDING_get_flags`
- `BN_BLINDING_is_current_thread`
- `BN_BLINDING_set_current_thread`
- `BN_BLINDING_lock`
- `BN_BLINDING_unlock`

Main observation:
- openHiTLS public blind/unblind remains workflow-level and RSA-BSSA-specific.
- That is enough for some `partial` verdicts on the `_ex` and `create_param` paths.
- Threading and handle-control helpers have no corresponding surface at all.
