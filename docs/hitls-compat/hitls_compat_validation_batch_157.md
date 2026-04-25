# openHiTLS Compatibility Validation Batch 157

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `EVP_SIGNATURE_*` entries lacking `analysis_doc`
- all remaining `EVP_ASYM_CIPHER_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes fetched/refcounted descriptor surfaces for signature and asymmetric-cipher algorithms in [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1715) and [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1734), including `fetch`, `up_ref`, `free`, `get0_provider`, `get0_name`, `get0_description`, `do_all_provided`, `names_do_all`, and gettable/settable ctx param metadata.
- openHiTLS does expose the underlying sign/verify and asymmetric-cipher operations through the generic pkey/EAL and provider layers, for example [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L351), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L370), and provider algorithm tables under [crypt_default_provider.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_provider.c#L339).
- But openHiTLS does not expose public installed descriptor objects corresponding to `EVP_SIGNATURE` or `EVP_ASYM_CIPHER`, and does not expose the fetched-descriptor/provider/name/metadata/refcount family that OpenSSL provides.

Verdict:
- all `22` interfaces in this batch remain `not_available`

Reasoning boundary:
- The existence of generic sign/verify and asymmetric cipher operations is not enough to classify these OpenSSL descriptor families as `partial`.
- Under the current rule, `partial` requires a public practical replacement path for the interface itself.
- For these families, openHiTLS lacks the public descriptor object model entirely, so the whole batch correctly remains `not_available`.
