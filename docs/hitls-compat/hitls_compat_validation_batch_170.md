# openHiTLS Compatibility Validation Batch 170

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `OSSL_CRMF_ENCRYPTEDVALUE_*`
- remaining `OSSL_CRMF_PBMPARAMETER_*`
- remaining `OSSL_CRMF_PKIPUBLICATIONINFO_*`
- remaining `OSSL_CRMF_SINGLEPUBINFO_*`

Status:
- completed

Initial evidence:
- OpenSSL exposes these CRMF typed ASN.1 helpers in [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L50), [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L73), [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L86), and [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L88).
- openHiTLS public installed headers expose no CRMF typed helper family.

Verdict:
- all `13` interfaces in this batch remain `not_available`

Reasoning boundary:
- No public CRMF object surface exists in openHiTLS.
