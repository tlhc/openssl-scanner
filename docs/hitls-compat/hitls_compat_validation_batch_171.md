# openHiTLS Compatibility Validation Batch 171

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `OSSL_CRMF_MSGS_*`
- `OSSL_CRMF_pbm_new`
- `OSSL_CRMF_pbmp_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes CRMF message-stack and PBM helpers in [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L93), [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L99), and [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L102).
- openHiTLS public installed headers expose no CRMF message-stack or PBM helper surface.

Verdict:
- all `6` interfaces in this batch remain `not_available`

Reasoning boundary:
- openHiTLS does not expose CRMF message or PBM helper objects publicly.
