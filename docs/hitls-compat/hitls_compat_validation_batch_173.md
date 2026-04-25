# openHiTLS Compatibility Validation Batch 173

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `OSSL_CRMF_MSG_*` helpers not covered by batches 171-172

Status:
- completed

Initial evidence:
- OpenSSL exposes CRMF message construction and mutation helpers in [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L117), [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L153), and [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L165).
- openHiTLS public installed headers expose no CRMF message construction surface.

Verdict:
- all `13` interfaces in this batch remain `not_available`

Reasoning boundary:
- No public CRMF message construction or mutation API exists in openHiTLS.
