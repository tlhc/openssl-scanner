# openHiTLS Compatibility Validation Batch 169

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `OSSL_CRMF_ATTRIBUTETYPEANDVALUE_*`
- remaining `OSSL_CRMF_CERTID_*`
- remaining `OSSL_CRMF_CERTTEMPLATE_*`

Status:
- completed

Initial evidence:
- OpenSSL exposes CRMF ASN.1 typed objects and helpers in [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L64), [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L77), and [crmf.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/crmf.h.in#L90).
- openHiTLS public installed headers do not expose a CRMF object family; the only visible trace is a CRMF OID section in [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L283).

Verdict:
- all `19` interfaces in this batch remain `not_available`

Reasoning boundary:
- An OID table is not a practical public replacement path for CRMF typed object APIs.
