# openHiTLS Compatibility Validation Batch 172

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `OSSL_CRMF_MSG_get0_*`
- remaining `OSSL_CRMF_MSG_set1_*`

Status:
- completed

Initial evidence:
- OpenSSL exposes these CRMF message field getters and setters in [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L109), [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L141), and [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L171).
- openHiTLS public installed headers expose no CRMF message object model.

Verdict:
- all `15` interfaces in this batch remain `not_available`

Reasoning boundary:
- No public CRMF message surface exists in openHiTLS.
