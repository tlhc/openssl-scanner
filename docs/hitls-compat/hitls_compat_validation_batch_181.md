# openHiTLS Compatibility Validation Batch 181

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `DSA_meth_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes legacy `DSA_METHOD` object APIs in [dsa.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/dsa.h#L221).
- openHiTLS public installed headers expose DSA algorithm operation APIs, but no public method-object construction/customization surface.

Verdict:
- all `27` interfaces in this batch remain `not_available`

Reasoning boundary:
- Algorithm capability is not a practical public replacement path for legacy `DSA_METHOD` object APIs.
