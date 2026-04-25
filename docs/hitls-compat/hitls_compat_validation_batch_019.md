# openHiTLS Compatibility Validation Batch 019

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_CTX_get0_CA_list`
- `SSL_CTX_get_client_CA_list`
- `SSL_CTX_set0_CA_list`
- `SSL_CTX_set_client_CA_list`
- `SSL_get0_peer_CA_list`
- `SSL_get_peer_cert_chain`
- `SSL_get0_verified_chain`

Status:
- completed

## 1. `SSL_CTX_get0_CA_list`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2016), [ssl_cert.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_cert.c#L512)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L914), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L840)
- Verdict: keep `partial`
- Why: direct getter exists, but the returned type is `HITLS_TrustedCAList` rather than `STACK_OF(X509_NAME)`.

## 2. `SSL_CTX_get_client_CA_list`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2024), [ssl_cert.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_cert.c#L527)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L852), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L763)
- Verdict: keep `partial`
- Why: same type mismatch as `SSL_CTX_get0_CA_list`.

## 3. `SSL_CTX_set0_CA_list`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2014), [ssl_cert.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_cert.c#L507)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L925), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L848)
- Verdict: keep `partial`
- Why: same setter role, but the list representation differs.

## 4. `SSL_CTX_set_client_CA_list`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2022), [ssl_cert.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_cert.c#L522)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L925), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L848)
- Verdict: keep `partial`
- Why: same as current mapping; type mismatch remains material.

## 5. `SSL_get0_peer_CA_list`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2019), [ssl_cert.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_cert.c#L537)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L843), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L752)
- Verdict: change to `partial`
- Why: direct getter exists, but the returned type is `HITLS_TrustedCAList`, not `STACK_OF(X509_NAME)`.

## 6. `SSL_get_peer_cert_chain`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1724), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1597)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L834), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L732)
- Verdict: change to `partial`
- Why: direct getter exists, but it returns `HITLS_CERT_Chain` (`BslList`) rather than OpenSSL’s `STACK_OF(X509)`.

## 7. `SSL_get0_verified_chain`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2082), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4960)
- openHiTLS closest evidence: verification store-context internal getter path [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L109), [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L603)
- Verdict: keep `not_available`
- Why: there is no TLS-level public getter on `HITLS_Ctx` for the verified chain.

## Batch 019 summary

Change to `partial`:
- `SSL_get0_peer_CA_list`
- `SSL_get_peer_cert_chain`

Keep `partial`:
- `SSL_CTX_get0_CA_list`
- `SSL_CTX_get_client_CA_list`
- `SSL_CTX_set0_CA_list`
- `SSL_CTX_set_client_CA_list`

Keep `not_available`:
- `SSL_get0_verified_chain`

Main observation:
- openHiTLS has better public CA-list and peer-chain getters than the current JSON suggested.
- The main compatibility limit in this family is container-type mismatch, not missing capability.
