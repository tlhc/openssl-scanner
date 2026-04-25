# openHiTLS Compatibility Validation Batch 206

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `d2i_OSSL_*` family lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes dedicated typed object families for CMP, CRMF, targeting, and attribute-syntax objects, including:
  - `OSSL_CMP_*`
  - `OSSL_CRMF_*`
  - `OSSL_TARGET*`
  - `OSSL_IETF_ATTR_SYNTAX`
  - `OSSL_ATTRIBUTES_SYNTAX`
  - `OSSL_USER_NOTICE_SYNTAX`
- The matching `d2i_OSSL_*` helpers decode DER into those public wrapper objects.
- openHiTLS public installed headers expose no public CMP or CRMF object family.
- In openHiTLS public trees, the only relevant signals are:
  - OID constants in `bsl_obj.h`
  - internal CMS/X509 usage of those OIDs
  - no public `CMP`, `CRMF`, `TARGET`, or related decode handles

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 20`

Reasoning boundary:
- These interfaces are blocked by missing public object families, not by missing ASN.1 mechanics alone.
- openHiTLS has no practical public replacement path for:
  - `d2i_OSSL_CMP_*`
  - `d2i_OSSL_CRMF_*`
  - `d2i_OSSL_TARGET*`
  - `d2i_OSSL_IETF_ATTR_SYNTAX`
  - `d2i_OSSL_ATTRIBUTES_SYNTAX`
  - `d2i_OSSL_USER_NOTICE_SYNTAX`
- The whole batch therefore remains `not_available`.
