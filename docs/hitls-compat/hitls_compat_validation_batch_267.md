# openHiTLS Compatibility Validation Batch 267

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- remaining report-side unknown provider/internal/global utility tails:
  - `OPENSSL_*` helpers still absent from the truth library
  - `OSSL_*` provider/internal macros
  - dynamic-bind macros
  - the remaining small global utility/error tails

Status:
- completed

Initial evidence:
- openHiTLS public installed surface exposes adjacent SAL/bootstrap primitives in:
  - [bsl_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_init.h#L42)
  - [crypt_eal_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_init.h#L51)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L228)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L239)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L265)
  - [hitls_crypt_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_crypt_init.h#L36)
  - [hitls_cert_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert_init.h#L36)
- openHiTLS also exposes a generic parameter-builder surface in:
  - [bsl_params.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_params.h#L178)
  - [bsl_params.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_params.h#L204)
- the public boundary still stops before:
  - OpenSSL provider/internal macro families such as `OSSL_PARAM_*`, `OSSL_TRACE*`, `OSSL_CORE_MAKE_FUNC`, and `IMPLEMENT_DYNAMIC_*`
  - OpenSSL secure-heap helpers
  - low-level `PKCS12err` style error-construction helpers

Verdict:
- keep `available = 0`
- set `partial = 8`
- set `not_available = 36`

Reasoning boundary:
- `partial` is justified where openHiTLS exposes a practical adjacent public path:
  - `OPENSSL_zalloc`, `OPENSSL_memdup`, `OPENSSL_realloc`, `OPENSSL_clear_realloc`, `OPENSSL_strndup`
    - SAL allocator primitives exist through `BSL_SAL_Calloc`, `BSL_SAL_Dump`, and `BSL_SAL_Realloc`
  - `OPENSSL_add_all_algorithms_noconf`, `OpenSSL_add_all_digests`
    - public bootstrap exists through `BSL_GLOBAL_Init` and `CRYPT_EAL_Init`
  - `SSLeay_add_ssl_algorithms`
    - public TLS bootstrap exists through `HITLS_CryptMethodInit` and `HITLS_CertMethodInit`
- these stay `partial` because the contract differs in helper naming, initialization scope, or wrapper work required around the raw SAL primitives.
- `not_available` remains correct for:
  - `OPENSSL_secure_*`
  - `OSSL_PARAM_*`
  - `OSSL_TRACE*`
  - `OSSL_CMP_*`
  - `OSSL_CORE_MAKE_FUNC`
  - `IMPLEMENT_DYNAMIC_*`
  - `OPENSSL_assert`
  - `OPENSSL_MALLOC_MAX_NELEMS`
  - `PKCS12err`

Representative evidence:
- openHiTLS public declarations:
  - [bsl_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_init.h#L42)
  - [crypt_eal_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_init.h#L51)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L228)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L239)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L265)
  - [hitls_crypt_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_crypt_init.h#L36)
  - [hitls_cert_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert_init.h#L36)
  - [bsl_params.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_params.h#L178)
  - [bsl_params.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_params.h#L204)

Batch 267 inventory:
- total interfaces: `44`
- `available = 0`
- `partial = 8`
- `not_available = 36`
