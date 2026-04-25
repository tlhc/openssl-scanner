# openHiTLS Compatibility Validation Batch 166

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `OSSL_STORE_SEARCH_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes typed search-criterion builders and getters in [store.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/store.h#L230), [store.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/store.h#L241), and [store.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/store.h#L244).
- openHiTLS public installed headers expose no store-search criterion object family.

Verdict:
- all `11` interfaces in this batch remain `not_available`

Reasoning boundary:
- openHiTLS has no public search criterion objects, so there is no practical replacement path.
