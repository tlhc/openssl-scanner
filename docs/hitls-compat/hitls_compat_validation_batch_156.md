# openHiTLS Compatibility Validation Batch 156

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `EVP_KEYMGMT_*` entries lacking `analysis_doc`
- all remaining `EVP_KEYEXCH_*` entries lacking `analysis_doc`
- all remaining `EVP_KEM_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes fetched/refcounted descriptor surfaces for key management, key exchange, and KEM in [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1605), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1905), and [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1752), with descriptor/provider/name/metadata APIs such as `fetch`, `up_ref`, `free`, `get0_name`, `get0_provider`, `is_a`, and `*_gettable_ctx_params`.
- openHiTLS does expose provider-aware operation creation and provider management in [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L146), [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L71), [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L102), and [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L151).
- But openHiTLS does not expose public installed descriptor objects corresponding to `EVP_KEYMGMT`, `EVP_KEYEXCH`, or `EVP_KEM`, and does not expose the fetched-descriptor metadata/refcount/enumeration APIs that OpenSSL provides for those families.

Verdict:
- all `35` interfaces in this batch remain `not_available`

Reasoning boundary:
- The existence of provider-aware operation creation in openHiTLS is not enough to classify these OpenSSL provider-style descriptor families as `partial`.
- Under the current rule, `partial` requires a public practical replacement path for the interface itself, not just an adjacent lower-level capability.
- For these families, openHiTLS lacks the public descriptor object model entirely, so the correct verdict for the whole batch is `not_available`.
