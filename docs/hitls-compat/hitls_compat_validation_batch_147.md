# openHiTLS Compatibility Validation Batch 147

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `CRYPTO_memcmp`
- `OSSL_PROVIDER_try_load`
- `EC_KEY_dup`
- `EC_POINT_point2oct`
- `EC_KEY_key2buf`
- `OSSL_PARAM_construct_uint`
- `OSSL_PARAM_construct_uint32`
- `OSSL_PARAM_construct_uint64`
- `OSSL_PARAM_uint32`
- `OSSL_PARAM_uint64`

Status:
- completed

Initial evidence:
- OpenSSL exposes these interfaces in [crypto.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crypto.h.in#L476), [provider.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/provider.h#L28), and [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L760), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1035), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1146).
- openHiTLS exposes public provider loading in [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L71), [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L102), and [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L151).
- openHiTLS exposes public generic pkey duplication and ECC public-key export in [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L172), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L305), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L320), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L596), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L688), [crypt_ecc_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc_pkey.h#L60), [crypt_ecc_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc_pkey.h#L175), and [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L203), [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L247), [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L615).
- OpenSSL exposes runtime unsigned-parameter constructors in [params.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/params.h#L75), [params.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/params.h#L80), [params.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/params.h#L82), with the concrete constructors implemented in [params.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/params.c#L324), [params.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/params.c#L699), and [params.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/params.c#L1014).
- OpenSSL also exposes unsigned parameter-definition macros in [params.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/params.h#L33), [params.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/params.h#L43), and [params.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/params.h#L49).
- openHiTLS exposes the corresponding public parameter value types and constructor helper in [bsl_params.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_params.h#L34), [bsl_params.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_params.h#L41), [bsl_params.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_params.h#L48), [bsl_params.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_params.h#L75), and [bsl_params.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/params/src/bsl_params.c#L26), with public UINT64 and UINT32 usage visible in [eal_pkey_params.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_params.c#L324), [eal_pkey_params.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_params.c#L578), [xmss.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/xmss/src/xmss.c#L394), and [xmss.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/xmss/src/xmss.c#L460).
- No public constant-time compare helper matching `CRYPTO_memcmp` was found in openHiTLS public headers; only internal/plain `memcmp` usage was observed.

Verdict:
- keep `not_available`:
  - `CRYPTO_memcmp`
- adjust to `partial`:
  - `OSSL_PROVIDER_try_load`
  - `EC_KEY_dup`
  - `EC_POINT_point2oct`
  - `EC_KEY_key2buf`
  - `OSSL_PARAM_construct_uint`
  - `OSSL_PARAM_construct_uint32`
  - `OSSL_PARAM_construct_uint64`
  - `OSSL_PARAM_uint32`
  - `OSSL_PARAM_uint64`

Reasoning boundary:
- `CRYPTO_memcmp` remains `not_available` because the required constant-time comparison helper is still absent from the public openHiTLS surface.
- `OSSL_PROVIDER_try_load` reached `partial` because openHiTLS does expose public runtime provider load/is-loaded/unload APIs, but not OpenSSL's exact try-load handle-returning surface or its fallback-retention semantics.
- The low-level EC family reached `partial` because openHiTLS does expose public pkey duplication and encoded public-key export through the EAL and ECC pkey APIs, but only through the higher-level key-context model, not through OpenSSL's `EC_KEY` / `EC_POINT` object model.
- The unsigned `OSSL_PARAM_construct_*` family reached `partial` because openHiTLS publicly exposes equivalent unsigned parameter construction through `BSL_PARAM_InitValue`, but it uses integer parameter IDs plus explicit `BSL_PARAM_TYPE_UINT32` and `BSL_PARAM_TYPE_UINT64` tags instead of OpenSSL's string-keyed `OSSL_PARAM` constructor helpers.
- `OSSL_PARAM_uint32` and `OSSL_PARAM_uint64` reached `partial` because openHiTLS publicly exposes the same unsigned parameter definition capability through `BSL_PARAM_InitValue`, while the API shape stays different at both the key type and macro/function layer.

Verification notes:
- Re-checked the adjacent `BN_mod` and `OSSL_PARAM_uint` conclusions from Batch 146 against the same source family. Their current `partial` status still matches the public surfaces, so no JSON status change was required in this batch.
- Expanded the truth-library keyset with `OSSL_PARAM_uint32` and `OSSL_PARAM_uint64` because both are public OpenSSL macros with direct public openHiTLS replacement paths and they fit the same verified parameter family.
