# openHiTLS Compatibility Validation Batch 175

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `PEM_read_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a broad `PEM_read_*` family in [pem.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pem.h#L380), [pem.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pem.h#L526), and [pem_pkey.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pem/pem_pkey.c#L264).
- openHiTLS public installed headers expose practical PEM/file/buffer parse paths for certs, CRLs, CSRs, and keys via [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L128), [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L210), [hitls_pki_crl.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_crl.h#L81), [hitls_pki_crl.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_crl.h#L116), [hitls_pki_csr.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_csr.h#L130), [hitls_pki_csr.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_csr.h#L145), and [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L184).
- PEM transport decode is present through [bsl_pem.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/pem/src/bsl_pem.c#L147).

Verdict:
- keep the current split:
  - `partial = 30`
  - `not_available = 24`

Reasoning boundary:
- `partial` remains correct for entries where openHiTLS has public practical parse paths for the same object class, but not the exact OpenSSL `PEM_read_*` helper shape.
- `not_available` remains correct for CMS/PKCS7/SSL_SESSION, generic PEM read helpers, and object classes with no matching public reader surface.
