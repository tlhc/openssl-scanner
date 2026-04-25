# openHiTLS Compatibility Validation Batch 165

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `OSSL_STORE_LOADER_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes fetched loader descriptors, registration hooks, and loader callback setters in [store.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/store.h#L266), [store.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/store.h#L319), and [store.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/store.h#L354).
- openHiTLS public installed headers expose provider load/unload and provider-aware codecs, but no public loader descriptor or loader registration object family.

Verdict:
- all `22` interfaces in this batch remain `not_available`

Reasoning boundary:
- Provider and codec entry points do not create a practical public replacement path for OpenSSL loader-descriptor APIs.
