# openHiTLS Compatibility Validation Batch 168

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining loader-registry `OSSL_STORE_*` helpers lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes loader-registry helpers such as `OSSL_STORE_do_all_loaders`, `OSSL_STORE_register_loader`, and `OSSL_STORE_unregister_loader` in [store.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/store.h#L354) and [store.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/store.h#L365).
- openHiTLS public installed headers expose no store-loader registry.

Verdict:
- all `3` interfaces in this batch remain `not_available`

Reasoning boundary:
- No public store-loader registry exists in openHiTLS.
