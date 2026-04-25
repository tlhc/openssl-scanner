# openHiTLS Compatibility Validation Batch 208

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `PKCS12/PKCS8` residue from the remaining `d2i_*` long tail:
  - `d2i_PKCS12_BAGS`
  - `d2i_PKCS12_MAC_DATA`
  - `d2i_PKCS12_SAFEBAG`
  - `d2i_PKCS8PrivateKey_bio`
  - `d2i_PKCS8PrivateKey_fp`
  - `d2i_PKCS8_bio`
  - `d2i_PKCS8_fp`

Status:
- completed

Initial evidence:
- OpenSSL exposes standalone typed decode helpers for PKCS12 bag wrappers and encrypted PKCS8 wrappers.
- openHiTLS public installed headers expose:
  - `HITLS_PKCS12_BagNew`
  - `HITLS_PKCS12_BagCtrl`
  - `HITLS_PKCS12_ParseBuff`
  - `HITLS_PKCS12_ParseFile`
  - `CRYPT_EAL_DecodeBuffKey`
  - `CRYPT_EAL_DecodeFileKey`
- The openHiTLS PKCS12 public surface is whole-container oriented.
- The openHiTLS PKCS8 public surface is key-decode oriented.

Verdict:
- keep `available = 0`
- adjust to `partial = 4`
- adjust to `not_available = 3`

Reasoning boundary:
- `partial`:
  - `d2i_PKCS8PrivateKey_bio`
  - `d2i_PKCS8PrivateKey_fp`
  - `d2i_PKCS8_bio`
  - `d2i_PKCS8_fp`
  - Public encrypted PKCS8 decode exists, but the contract differs:
    - no BIO / FILE helper
    - no OpenSSL callback contract
    - no `X509_SIG` wrapper-object result
    - return type is an openHiTLS key context
- `not_available`:
  - `d2i_PKCS12_BAGS`
  - `d2i_PKCS12_MAC_DATA`
  - `d2i_PKCS12_SAFEBAG`
  - openHiTLS has PKCS12 bag objects and whole-PKCS12 parse, but no public standalone decode surface for these wrapper objects
