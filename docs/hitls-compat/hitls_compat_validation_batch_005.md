# openHiTLS Compatibility Validation Batch 005

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_new`
- `BN_free`
- `BN_clear_free`
- `BN_bin2bn`
- `BN_bn2bin`
- `BN_num_bytes`
- `BN_set_word`
- `BN_CTX_new`
- `BN_CTX_free`

Status:
- completed

Initial evidence:
- OpenSSL public declarations are concentrated in [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L210) and [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L238).
- Current truth-library baseline marks most of this family as `not_available`, and `BN_num_bytes` is still missing from the JSON.
- openHiTLS source code uses internal `BN_*` helpers heavily in RSA implementation, for example [rsa_keyop.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_keyop.c#L31), [rsa_keyop.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_keyop.c#L259), and [rsa_blinding.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/rsa/src/rsa_blinding.c#L91).
- No corresponding `BN_*` public declarations were found under [`openhitls-upstream/include`](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include), which means this batch needs to distinguish internal big-number machinery from exported compatibility surface.

Key question for this batch:
- whether any of these OpenSSL low-level BigNum interfaces can be counted as function-level compatible through public openHiTLS APIs, or whether the correct verdict remains `not_available` because the BN layer is internal-only.

Rule applied in this batch:
- Internal source-level equivalents do not change the verdict to compatible when they are outside the installed public header set.
- `openHiTLS` installs only the top-level [include/](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include) tree through [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96).
- `crypt_bn.h` lives under [crypto/bn/include/](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h), so it is usable by in-tree modules but not part of the installed public compatibility surface.

## 1. `BN_new`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L238)
- openHiTLS internal analog: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L96)
- implementation: [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L26)
- install boundary: [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)

Verdict:
- Keep `not_available`

Why:
- `BN_Create(bits)` is an internal analog, but it is not part of the installed public header set.
- It also requires an explicit bit-size allocation contract that `BN_new()` does not.

## 2. `BN_free`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L299)
- openHiTLS internal analog: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L106)
- implementation: [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L50)

Verdict:
- Keep `not_available`

Why:
- `BN_Destroy()` is internal-only.
- The functionality is similar, including cleansing, but it is not exposed through installed public headers.

## 3. `BN_clear_free`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L240)
- openHiTLS internal analog: [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L55)

Verdict:
- Keep `not_available`

Why:
- `BN_Destroy()` internally cleanses before release, so the functional direction is clear.
- It still stays internal-only and therefore does not count as public compatibility.

## 4. `BN_bin2bn`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L243)
- openHiTLS internal analog: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L877)
- implementation: [bn_utils.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_utils.c#L26)

Verdict:
- Keep `not_available`

Why:
- `BN_Bin2Bn` exists internally, but requires a caller-supplied `BN_BigNum *`.
- OpenSSL `BN_bin2bn` returns a `BIGNUM *` and optionally reuses `ret`.
- The openHiTLS analog is not part of the installed public API.

## 5. `BN_bn2bin`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L244)
- openHiTLS internal analog: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L892)
- implementation: [bn_utils.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_utils.c#L76)

Verdict:
- Keep `not_available`

Why:
- `BN_Bn2Bin` exists internally and is functionally close.
- It uses a `uint32_t *binLen` in/out contract rather than OpenSSL's integer return count.
- It is not installed as part of the public header surface.

## 6. `BN_num_bytes`

Current JSON:
- missing

Verified evidence:
- OpenSSL macro: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L189)
- openHiTLS internal analog: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L423)
- implementation: [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L402)

Verdict:
- Add as `not_available`

Why:
- `BN_Bytes` is a direct internal analog for byte-length query.
- It is still outside the installed public API boundary.

## 7. `BN_set_word`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L295)
- openHiTLS internal analog: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L336)
- implementation: [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L283)

Verdict:
- Keep `not_available`

Why:
- `BN_SetLimb` is the internal analog.
- It is internal-only and typed on `BN_UINT`, not the OpenSSL public `BN_ULONG` surface.

## 8. `BN_CTX_new`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L210)
- openHiTLS closest internal analog: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1026)
- implementation: [bn_optimizer.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_optimizer.c#L27)

Verdict:
- Keep `not_available`

Why:
- `BN_OptimizerCreate` is a workspace allocator for internal large-number optimization, not a public `BN_CTX` equivalent.
- This is both a public-surface gap and a semantic mismatch.

## 9. `BN_CTX_free`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L213)
- openHiTLS closest internal analog: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1036)
- implementation: [bn_optimizer.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_optimizer.c#L51)

Verdict:
- Keep `not_available`

Why:
- `BN_OptimizerDestroy` tears down an internal optimizer/workspace, not a public `BN_CTX` object model.
- The semantic mismatch remains material even before public-surface considerations.

## Batch 005 summary

Add:
- `BN_num_bytes`: `missing` -> `not_available`

Keep:
- `BN_new`
- `BN_free`
- `BN_clear_free`
- `BN_bin2bn`
- `BN_bn2bin`
- `BN_set_word`
- `BN_CTX_new`
- `BN_CTX_free`

Main observation:
- openHiTLS has a substantial internal big-number subsystem.
- That subsystem is intentionally outside the installed top-level public headers, so low-level OpenSSL `BN_*` APIs still count as `not_available` in the scanner truth library.
