# openHiTLS Compatibility Validation Batch 160

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `OSSL_CMP_*` entries lacking `analysis_doc`
- includes CMP utility, ASN.1 helper, context, message, HTTP, validation, and server-side families

Status:
- completed

Initial evidence:
- OpenSSL exposes a full CMP surface in [cmp_util.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cmp_util.h#L26), [cmp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cmp.h.in#L221), [cmp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cmp.h.in#L349), [cmp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cmp.h.in#L481), [cmp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cmp.h.in#L494), [cmp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cmp.h.in#L500), [cmp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cmp.h.in#L510), and [cmp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cmp.h.in#L562).
- The OpenSSL implementation spans dedicated CMP client/server/util/ASN.1 modules such as [cmp_server.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/cmp/cmp_server.c#L48), [cmp_util.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/cmp/cmp_util.c#L23), [cmp_msg.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/cmp/cmp_msg.c#L18), [cmp_asn.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/cmp/cmp_asn.c#L131), and [cmp_vfy.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/cmp/cmp_vfy.c#L579).
- openHiTLS public installed headers expose PKI surfaces for certificates, CMS, CSR, CRL, and generic utilities, but no CMP client/server/message/context API family. The nearest public evidence is limited to generic PKI/CMS coverage in [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L49), [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L54), [hitls_pki_csr.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_csr.h#L41), and CRMF/CMP-related OID constants in [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L283).
- A direct search of the openHiTLS installed `include/`, `pki/`, `crypto/`, and `apps/` trees found no public `CMP` or `OSSL_CMP` interface family, only unrelated `cmp` substrings such as compare-result constants and internal OID references.

Verdict:
- all `151` interfaces in this batch remain `not_available`

Reasoning boundary:
- Generic ASN.1, X.509, CMS, or HTTP-adjacent building blocks are not enough to classify OpenSSL CMP interfaces as `partial`.
- The current rule requires a public practical migration surface for the interface family itself.
- openHiTLS does not expose a public CMP object model, CMP context, CMP message flow, CMP validation helper, or CMP server surface, so the whole `OSSL_CMP_*` batch stays `not_available`.
