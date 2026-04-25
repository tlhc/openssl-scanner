# openHiTLS Compatibility Validation Batch 192

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `X509_LOOKUP_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes `X509_LOOKUP` / `X509_LOOKUP_METHOD` object and callback families in `x509_vfy.h.in`.
- openHiTLS public installed headers expose no `X509_LOOKUP` object or lookup-method surface.

Verdict:
- all `37` interfaces in this batch remain `not_available`

Reasoning boundary:
- File/path/store loading helpers elsewhere in openHiTLS do not create a practical public analogue for `X509_LOOKUP` object APIs.
