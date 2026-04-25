# openHiTLS Compatibility Validation Batch 180

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `RSA_meth_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes legacy `RSA_METHOD` object APIs in [rsa.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/rsa.h#L482).
- openHiTLS public installed headers expose RSA algorithm operation APIs, but no public method-object construction/customization surface.

Verdict:
- all `33` interfaces in this batch remain `not_available`

Reasoning boundary:
- Algorithm capability is not a practical public replacement path for legacy `RSA_METHOD` object APIs.
