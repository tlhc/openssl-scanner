# openHiTLS Compatibility Validation Batch 201

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `CMS_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a very broad CMS family across `include/openssl/cms.h.in` and `crypto/cms/*`, including:
  - `CMS_ContentInfo_*`
  - `CMS_sign` / `CMS_verify`
  - `CMS_add*cert*` / `CMS_add*crl*`
  - `CMS_SignerInfo_*`
  - `CMS_RecipientInfo_*`
  - `CMS_EnvelopedData_*`
  - `CMS_EncryptedData_*`
  - `CMS_signed_*` / `CMS_unsigned_*`
- openHiTLS public installed headers expose a much narrower CMS surface through:
  - `HITLS_CMS_ProviderNew`
  - `HITLS_CMS_Free`
  - `HITLS_CMS_ProviderParseBuff`
  - `HITLS_CMS_ProviderParseFile`
  - `HITLS_CMS_DataSign`
  - `HITLS_CMS_DataVerify`
  - `HITLS_CMS_DataInit`
  - `HITLS_CMS_DataUpdate`
  - `HITLS_CMS_DataFinal`
  - `HITLS_CMS_Ctrl`
  - `HITLS_CMS_ADD_CERT`
  - `HITLS_CMS_ADD_CRL`
  - `HITLS_CMS_SET_MSG_MD`
- The public openHiTLS CMS surface is explicitly centered on `SignedData`; the header states parse support is currently limited to SignedData.

Verdict:
- keep `available = 0`
- adjust to `partial = 15`
- adjust to `not_available = 116`

Reasoning boundary:
- `partial` is limited to the CMS operations that have a practical public replacement path through the openHiTLS `HITLS_CMS` handle:
  - `CMS_ContentInfo_new/new_ex/free`
  - `CMS_sign/sign_ex`
  - `CMS_verify`
  - `CMS_add0/add1_cert`
  - `CMS_add0/add1_crl`
  - `CMS_add1_signer`
  - `CMS_dataInit`
  - `CMS_dataFinal`
  - `CMS_final`
  - `CMS_SignedData_verify`
- `not_available` covers the rest of the family because openHiTLS does not expose public subobject surfaces such as:
  - `CMS_SignerInfo_*`
  - `CMS_RecipientInfo_*`
  - `CMS_ReceiptRequest_*`
  - `CMS_signed_*` / `CMS_unsigned_*`
  - `CMS_get0_*` / `CMS_get1_*` getters
  - `CMS_EnvelopedData_*` / `CMS_EncryptedData_*`
  - `CMS_AuthEnvelopedData_*`
  - `CMS_compress` / `CMS_uncompress`
  - generic `CMS_ContentInfo_print_ctx`
- The practical boundary is public `HITLS_CMS` SignedData handling. OpenSSL CMS subobject manipulation and non-SignedData content families still have no practical public replacement path.
