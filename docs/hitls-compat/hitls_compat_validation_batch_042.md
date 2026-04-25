# openHiTLS Compatibility Validation Batch 042

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_BLINDING_new`
- `BN_BLINDING_free`
- `BN_BLINDING_update`
- `BN_BLINDING_convert`
- `BN_BLINDING_invert`
- `BN_BLINDING_set_flags`

Status:
- completed

Initial evidence:
- This is the next coherent BN blinding-management cluster without `analysis_doc`.
- OpenSSL uses a dedicated `BN_BLINDING *` object model for RSA-style blinding helpers.
- The next check is whether openHiTLS exposes any comparable public blinding object or whether this is another internal-only/no-surface family.

## 1. `BN_BLINDING_new`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L418), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L30)
- openHiTLS internal declaration/implementation: [rsa_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_local.h#L182), [rsa_blinding.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_blinding.c#L27), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `RSA_BlindNewCtx()` exists only as an internal RSA helper. openHiTLS does not expose a public `BN_BLINDING *`-style handle.

## 2. `BN_BLINDING_free`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L419), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L81)
- openHiTLS internal declaration/implementation: [rsa_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_local.h#L192), [rsa_blinding.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_blinding.c#L38), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `RSA_BlindFreeCtx()` is internal only, matching the same object-visibility gap as `BN_BLINDING_new`.

## 3. `BN_BLINDING_update`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L420), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L93)
- openHiTLS internal implementation: [rsa_blinding.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_blinding.c#L48), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS does have an internal `BlindUpdate()` helper over `RSA_Blind`, but it is not exposed publicly and there is no public refresh/update primitive.

## 4. `BN_BLINDING_convert`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L421), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L129)
- openHiTLS public declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L612), [eal_pkey_sign.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_sign.c#L142), [eal_pkey_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_method.c#L268), [rsa_encdec.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_encdec.c#L641)
- Verdict: change to `partial`
- Why: openHiTLS exposes public blinding through `CRYPT_EAL_PkeyBlind()`, but only for RSA-BSSA blind-signature workflows, on `CRYPT_EAL_PkeyCtx *` plus byte buffers. It is not a reusable low-level `BN_BLINDING *` + `BIGNUM *` API.

## 5. `BN_BLINDING_invert`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L422), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L162)
- openHiTLS public declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L628), [eal_pkey_sign.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_sign.c#L160), [eal_pkey_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_method.c#L275), [rsa_encdec.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_encdec.c#L713)
- Verdict: change to `partial`
- Why: `CRYPT_EAL_PkeyUnBlind()` gives a public unblind flow, but again only for RSA-BSSA byte-buffer workflows and not as low-level `BN_BLINDING` handle based inversion.

## 6. `BN_BLINDING_set_flags`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L433), [bn_blind.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_blind.c#L229)
- openHiTLS public/internal evidence: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L596), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L104), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L667), [rsa_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_ctrl.c#L304), [rsa_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_ctrl.c#L487)
- Verdict: keep `not_available`
- Why: openHiTLS does expose public RSA flag control, but those flags are `CRYPT_RSA_BLINDING` / `CRYPT_RSA_BSSA` on the RSA key context. They are not the same control surface as OpenSSL `BN_BLINDING_NO_UPDATE` / `BN_BLINDING_NO_RECREATE` on a blinding handle.

## Batch 042 summary

Change to `partial`:
- `BN_BLINDING_convert`
- `BN_BLINDING_invert`

Keep `not_available`:
- `BN_BLINDING_new`
- `BN_BLINDING_free`
- `BN_BLINDING_update`
- `BN_BLINDING_set_flags`

Main observation:
- openHiTLS has two distinct layers here:
  - internal RSA blinding handle APIs, which do not count because they are not public
  - public pkey-level blind/unblind APIs, which only cover RSA-BSSA workflows
- That is enough to upgrade `convert/invert` to `partial`, but not enough to expose an OpenSSL-compatible `BN_BLINDING` object model.
