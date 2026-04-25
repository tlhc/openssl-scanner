# openHiTLS Compatibility Validation Batch 191

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `OSSL_HPKE_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a public HPKE API in `crypto/hpke` and [`openssl/hpke.h`](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/hpke.h).
- openHiTLS has internal HPKE implementation code under `crypto/hpke`, but no public installed HPKE header surface.

Verdict:
- all `20` interfaces in this batch remain `not_available`

Reasoning boundary:
- Internal HPKE capability does not count as a public practical replacement path.
