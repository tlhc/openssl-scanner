# openHiTLS Compatibility Validation Batch 164

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `OSSL_STORE_INFO_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes typed `OSSL_STORE_INFO` constructors, getters, and destructors in [store.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/store.h#L172), [store.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/store.h#L185), and [store.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/store.h#L209).
- openHiTLS public installed headers expose key/cert/crl decode and encode helpers, but no public `OSSL_STORE_INFO` wrapper object family.

Verdict:
- all `26` interfaces in this batch remain `not_available`

Reasoning boundary:
- Public codec capability is not enough to classify OpenSSL `OSSL_STORE_INFO` object helpers as `partial`.
- openHiTLS does not expose a practical public wrapper object analogous to `OSSL_STORE_INFO`.
