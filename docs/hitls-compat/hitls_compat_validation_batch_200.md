# openHiTLS Compatibility Validation Batch 200

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `X509_ACERT_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a full attribute-certificate surface across:
  - `include/openssl/x509_acert.h.in`
  - `crypto/x509/x509_acert.c`
  - `crypto/x509/x509aset.c`
  - `crypto/x509/t_acert.c`
  - `crypto/x509/x_all.c`
- openHiTLS public installed headers expose no attribute-certificate object family.
- The only openHiTLS hit in public-facing trees is a CMS comment acknowledging that attribute certificates may be present in SignedData version logic.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 47`

Reasoning boundary:
- OpenSSL's `X509_ACERT_*` family depends on a dedicated public object model for attribute certificates, including holder/issuer setters, attribute accessors, extension helpers, sign/verify helpers, print helpers, and ASN.1 alloc/item helpers.
- openHiTLS does not expose any public `ACERT` object, parser, generator, signer, verifier, accessor, or print API.
- Since there is no practical public replacement path, the whole batch remains `not_available`.
