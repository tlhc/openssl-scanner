# openHiTLS Compatibility Validation Batch 198

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `X509_REVOKED_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a public `X509_REVOKED` object family through:
  - `DECLARE_ASN1_FUNCTIONS(X509_REVOKED)`
  - `X509_REVOKED_get0_serialNumber`
  - `X509_REVOKED_set_serialNumber`
  - `X509_REVOKED_get0_revocationDate`
  - `X509_REVOKED_set_revocationDate`
  - `X509_REVOKED_get0_extensions`
  - `X509_REVOKED_get_ext*`
  - `X509_REVOKED_add_ext`
  - `X509_REVOKED_add1_ext_i2d`
- openHiTLS public installed headers expose a narrower revoked-entry surface through:
  - `HITLS_X509_CrlEntryNew`
  - `HITLS_X509_CrlEntryFree`
  - `HITLS_X509_CrlEntryCtrl`
  - `HITLS_X509_CRL_SET_REVOKED_SERIALNUM`
  - `HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME`
  - `HITLS_X509_CRL_SET_REVOKED_INVALID_TIME`
  - `HITLS_X509_CRL_SET_REVOKED_REASON`
  - `HITLS_X509_CRL_SET_REVOKED_CERTISSUER`
  - matching `GET_*` commands for those typed fields

Verdict:
- adjust to `available = 2`
- adjust to `partial = 5`
- adjust to `not_available = 11`

Reasoning boundary:
- `available` is limited to the direct revoked-entry lifecycle that openHiTLS exposes one-for-one: `X509_REVOKED_new` and `X509_REVOKED_free`.
- `partial` covers practical typed field access through `HITLS_X509_CrlEntryCtrl`, where public replacement exists but the contract differs:
  - serial number and revocation date use openHiTLS buffer or `BSL_TIME` representations instead of `ASN1_INTEGER *` and `ASN1_TIME *`
  - `X509_REVOKED_dup` can be compositionally approximated for common typed fields, but openHiTLS has no dedicated dup helper and does not preserve generic extension semantics one-to-one
- `not_available` covers the OpenSSL-only generic revoked-extension-stack surface:
  - `X509_REVOKED_get0_extensions`
  - `X509_REVOKED_get_ext*`
  - `X509_REVOKED_add_ext`
  - `X509_REVOKED_add1_ext_i2d`
  - `X509_REVOKED_delete_ext`
  - `X509_REVOKED_it`
