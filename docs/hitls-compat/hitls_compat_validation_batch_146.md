# openHiTLS Compatibility Validation Batch 146

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `CRYPTO_cleanup_all_ex_data`
- `CRYPTO_num_locks`
- `CRYPTO_THREADID_set_numeric`
- `CRYPTO_set_locking_callback`
- `CRYPTO_get_locking_callback`
- `sk_PKCS7_SIGNER_INFO_num`
- `sk_SSL_CIPHER_num`
- `sk_X509_CRL_pop_free`
- `OPENSSL_sk_value`
- `OSSL_PARAM_uint`
- `BN_mod`

Status:
- completed

Initial evidence:
- OpenSSL exposes the legacy thread/ex_data compatibility macros in [crypto.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crypto.h.in#L291) and [crypto.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crypto.h.in#L305), the generic stack helpers in [stack.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/stack.h#L30), the parameter-construction macro in [params.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/params.h#L33), and the BN modulo macro in [bn.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bn.h#L276).
- openHiTLS exposes public generic list helpers in [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L124), [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L149), and [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L263).
- openHiTLS publicly aliases `HITLS_X509_List` to `BslList` in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L32) and exposes `HITLS_X509_CrlFree` in [hitls_pki_crl.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_crl.h#L46).
- openHiTLS exposes public parameter construction and BN modulo helpers in [bsl_params.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_params.h#L75) and [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L723).
- openHiTLS exposes public cipher-suite enumeration in [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L682), but no public signer-info list getter on the CMS surface.

Verdict:
- adjust to `available`:
  - `sk_X509_CRL_pop_free`
  - `OPENSSL_sk_value`
- adjust to `partial`:
  - `CRYPTO_cleanup_all_ex_data`
  - `CRYPTO_num_locks`
  - `CRYPTO_THREADID_set_numeric`
  - `CRYPTO_set_locking_callback`
  - `CRYPTO_get_locking_callback`
  - `sk_SSL_CIPHER_num`
  - `OSSL_PARAM_uint`
  - `BN_mod`
- keep `not_available`:
  - `sk_PKCS7_SIGNER_INFO_num`

Reasoning boundary:
- The `CRYPTO_*locks*` and `THREADID*` entries only reached `partial` because OpenSSL 1.1+ already reduced them to compatibility no-ops or fixed constants. They are practically removable in migration, but openHiTLS does not expose corresponding public APIs.
- `OPENSSL_sk_value` and `sk_X509_CRL_pop_free` crossed into `available` because openHiTLS publicly exposes the list container and the required index/free primitives directly.
- `sk_SSL_CIPHER_num` stayed `partial` because openHiTLS exposes public cipher-suite enumeration and count, but not an `OPENSSL_STACK`-based `SSL_CIPHER` list object.
- `OSSL_PARAM_uint` and `BN_mod` stayed `partial` because openHiTLS exposes public equivalents for the underlying operation, but through different type systems and object models.
