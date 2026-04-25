# openHiTLS Compatibility Validation Batch 248

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `OSSL_*` family lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a mixed `OSSL_*` surface across:
  - OpenSSL library-context management:
    - `OSSL_LIB_CTX_*`
  - trace and indicator helpers:
    - `OSSL_trace_*`
    - `OSSL_INDICATOR_*`
  - self-test helpers:
    - `OSSL_SELF_TEST_*`
  - default cipher / thread helper utilities:
    - `OSSL_default_cipher_list`
    - `OSSL_default_ciphersuites`
    - `OSSL_sleep`
    - `OSSL_get_max_threads`
    - `OSSL_set_max_threads`
  - QUIC method helpers:
    - `OSSL_QUIC_client_method`
    - `OSSL_QUIC_client_thread_method`
  - ASN.1 wrapper / object families:
    - `OSSL_ATTRIBUTES_SYNTAX_*`
    - `OSSL_IETF_ATTR_SYNTAX_*`
    - `OSSL_ISSUER_SERIAL_*`
    - `OSSL_OBJECT_DIGEST_INFO_*`
    - `OSSL_TARGET*`
    - `OSSL_USER_NOTICE_SYNTAX_*`
- openHiTLS public installed surface exposes only one real adjacent family here:
  - provider library-context management:
    - `CRYPT_EAL_LibCtxNew`
    - `CRYPT_EAL_LibCtxFree`
    - provider load/register/unload helpers
- openHiTLS public installed tree does not expose:
  - default-context / child-context / libctx-data APIs
  - FIPS indicator callback APIs
  - OpenSSL-style trace category APIs
  - QUIC method selection APIs
  - standalone `OSSL_*` ASN.1 wrapper-object families

Verdict:
- keep `available = 0`
- adjust to `partial = 2`
- adjust to `not_available = 89`

Reasoning boundary:
- `partial` is justified only for:
  - `OSSL_LIB_CTX_new`
  - `OSSL_LIB_CTX_free`
- openHiTLS has a practical public create/free path for provider library contexts:
  - `CRYPT_EAL_LibCtxNew`
  - `CRYPT_EAL_LibCtxFree`
- These still remain `partial` because OpenSSL `OSSL_LIB_CTX` includes a much broader contract:
  - `new_from_dispatch`
  - `new_child`
  - `load_config`
  - `get0_global_default`
  - `set0_default`
  - `get_data`
  - `get_conf_diagnostics`
- openHiTLS public `CRYPT_EAL_LibCtx` only covers provider-side library-context creation and provider management, so it does not preserve the OpenSSL default-context and data-attachment semantics.
- `not_available` remains correct for the rest because openHiTLS public APIs do not provide a practical public replacement path for:
  - `OSSL_LIB_CTX_new_from_dispatch`
  - `OSSL_LIB_CTX_new_child`
  - `OSSL_LIB_CTX_load_config`
  - `OSSL_LIB_CTX_get0_global_default`
  - `OSSL_LIB_CTX_set0_default`
  - `OSSL_LIB_CTX_get_data`
  - `OSSL_LIB_CTX_get_conf_diagnostics`
  - `OSSL_INDICATOR_get_callback`
  - `OSSL_INDICATOR_set_callback`
  - `OSSL_SELF_TEST_*`
  - `OSSL_trace_*`
  - `OSSL_default_cipher_list`
  - `OSSL_default_ciphersuites`
  - `OSSL_get_max_threads`
  - `OSSL_get_thread_support_flags`
  - `OSSL_set_max_threads`
  - `OSSL_parse_url`
  - `OSSL_sleep`
  - `OSSL_QUIC_client_method`
  - `OSSL_QUIC_client_thread_method`
  - all remaining standalone `OSSL_*` ASN.1 wrapper/object families

Important boundary calls:
- `OSSL_sleep` stays `not_available`
  - OpenSSL contract is millisecond sleep
  - openHiTLS public `BSL_SAL_Sleep` uses seconds and eventually calls `sleep(time)`
  - that loses the timing contract, so practical replacement does not hold
- `OSSL_INDICATOR_*` stays `not_available`
  - OpenSSL exposes libctx-bound FIPS indicator callbacks
  - openHiTLS has internal `indicator.h` use in TLS internals, but no installed public indicator callback API
- `OSSL_SELF_TEST_*` stays `not_available`
  - openHiTLS public `CRYPT_CMVP_SelftestNewCtx / Selftest / SelftestFreeCtx` is a whole self-test runner
  - it does not match the OpenSSL `OSSL_SELF_TEST` event-object lifecycle and callback contract

Representative evidence:
- OpenSSL declarations and manpages:
  - [OSSL_LIB_CTX.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/OSSL_LIB_CTX.pod#L17)
  - [OSSL_LIB_CTX.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/OSSL_LIB_CTX.pod#L22)
  - [OSSL_LIB_CTX.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/OSSL_LIB_CTX.pod#L24)
  - [crypto.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crypto.h.in#L593)
  - [OSSL_sleep.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/OSSL_sleep.pod#L11)
  - [indicator.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/indicator.h#L23)
  - [self_test.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/self_test.h#L108)
  - [self_test.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/self_test.h#L113)
  - [quic.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/quic.h#L26)
  - [ssl.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ssl.h.in#L2849)
  - [trace.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/trace.h#L63)
  - [OSSL_trace_set_channel.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/OSSL_trace_set_channel.pod#L17)
- openHiTLS public declarations:
  - [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L41)
  - [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L49)
  - [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L63)
  - [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L79)
  - [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L151)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L30)
  - [hitls_crypt_type.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_crypt_type.h#L33)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L718)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L1513)
  - [crypt_eal_cmvp.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cmvp.h#L61)
  - [crypt_eal_cmvp.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cmvp.h#L84)
- openHiTLS implementation evidence:
  - [crypt_provider.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/mgr/crypt_provider.c#L40)
  - [crypt_provider.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/mgr/crypt_provider.c#L46)
  - [sal_time.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/sal/src/sal_time.c#L407)
  - [posix_time.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/sal/src/posix/posix_time.c#L86)

Batch 248 inventory:
- total interfaces: `91`
- `partial = 2`
- `not_available = 89`
