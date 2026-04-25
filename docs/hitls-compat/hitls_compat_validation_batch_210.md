# openHiTLS Compatibility Validation Batch 210

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `d2i_*` long-tail typed wrapper objects:
  - RFC3779-style wrappers
  - DH/DSA/EC parameter wrappers
  - CMS receipt wrapper
  - SCT / SXNET wrappers

Status:
- completed

Initial evidence:
- OpenSSL exposes standalone typed decode helpers for:
  - `ASIdOrRange`, `ASIdentifierChoice`, `ASIdentifiers`, `IPAddressChoice`, `IPAddressFamily`, `IPAddressOrRange`, `IPAddressRange`
  - `DHparams`, `DHxparams`, `DSAparams`, `ECPKParameters`, `ECParameters`
  - `CMS_ReceiptRequest`
  - `SCT_LIST`
  - `SXNET`, `SXNETID`
- openHiTLS public installed headers expose only adjacent capabilities:
  - DH / DSA / ECDSA parameter contexts and key-management controls
  - CMS SignedData handle operations
  - OID constants and extension-processing helpers
- No public installed header exposes a standalone decode API for any of these wrapper objects.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 18`

Reasoning boundary:
- These interfaces are blocked by the same public-surface gap:
  - OpenSSL returns standalone typed wrapper objects
  - openHiTLS has neighboring functionality, but no standalone decode path for the wrapper object itself
- The whole batch therefore remains `not_available`.
