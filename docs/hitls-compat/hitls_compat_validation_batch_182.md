# openHiTLS Compatibility Validation Batch 182

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `EVP_RAND_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a provider-era fetched `EVP_RAND` descriptor and `EVP_RAND_CTX` context surface in [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1204).
- openHiTLS public installed headers expose a direct random/DRBG surface in [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L124), [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L273), [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L297), [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L327), [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L339), [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L376), and [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L390).
- That public surface gives practical replacement paths for DRBG construction, generation, reseed, instantiate, deinit, and status/ctrl operations, but not the exact OpenSSL fetched descriptor/provider/name/param-table object model.

Verdict:
- all `30` interfaces in this batch remain `partial`

Reasoning boundary:
- openHiTLS has real public RAND/DRBG functionality, so this family is not `not_available`.
- But because OpenSSL's `EVP_RAND` descriptor/fetch/provider object model is absent, the correct classification stays `partial`.
