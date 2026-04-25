# openHiTLS Compatibility Validation Batch 190

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `OSSL_HTTP_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a full HTTP request-context/client helper family in `http.h`.
- openHiTLS public installed headers expose no comparable HTTP client/request-context surface.

Verdict:
- all `23` interfaces in this batch remain `not_available`

Reasoning boundary:
- No practical public HTTP client/request-context analogue exists in openHiTLS.
