# openHiTLS Compatibility Validation Batch 178

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `ENGINE_get_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes legacy ENGINE getter APIs in [engine.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/engine.h#L392), [engine.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/engine.h#L757), and [engine.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/engine.h#L981).
- openHiTLS public installed headers expose provider-based crypto dispatch, not an ENGINE subsystem.

Verdict:
- all `41` interfaces in this batch remain `not_available`

Reasoning boundary:
- Provider load/register APIs do not create a practical public analogue for legacy ENGINE getter surfaces.
