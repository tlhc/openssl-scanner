# openHiTLS Compatibility Validation Batch 174

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `PEM_write_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a broad `PEM_write_*` family in [pem.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pem.h#L390), [pem.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pem.h#L487), [pem.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pem.h#L493), [cms.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cms.h.in#L127), [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L252), and [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L894).
- openHiTLS public installed headers expose practical PEM/file/buffer generation paths for certs, CRLs, CSRs, and keys via [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L283), [hitls_pki_crl.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_crl.h#L150), [hitls_pki_csr.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_csr.h#L85), and [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L281).
- PEM transport itself is present through [bsl_pem.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/pem/src/bsl_pem.c#L101) and [bsl_pem.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/pem/src/bsl_pem.c#L147).

Verdict:
- keep the current split:
  - `partial = 38`
  - `not_available = 27`

Reasoning boundary:
- `partial` remains correct for entries where openHiTLS has public practical write/generate paths for the same object class, but not the exact OpenSSL `PEM_write_*` helper shape.
- `not_available` remains correct for CMS/PKCS7/SSL_SESSION, generic low-level PEM stream helpers, and object classes with no matching public PEM writer surface.
