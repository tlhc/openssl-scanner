# openHiTLS Compatibility Validation Batch 016

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_use_certificate`
- `SSL_use_certificate_ASN1`
- `SSL_use_certificate_file`
- `SSL_use_certificate_chain_file`
- `SSL_use_PrivateKey`
- `SSL_use_PrivateKey_ASN1`
- `SSL_use_PrivateKey_file`
- `SSL_CTX_use_certificate`
- `SSL_CTX_use_certificate_file`
- `SSL_CTX_use_certificate_chain_file`

Status:
- completed

Initial evidence:
- OpenSSL declarations/implementations are concentrated in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1594), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1597), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1620), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1630), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1633), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1746), plus [ssl_rsa.c](openssl-3.0.9/ssl/ssl_rsa.c).
- openHiTLS public cert/key setters and parsers are concentrated in [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L350), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L398), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L461), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L552), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L668), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L685), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1343), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1354), plus implementations in [conn_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_cert.c) and [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c).
- Current mapping baseline is mostly `partial`; the main question is which operations already have direct public setters (`SetCertificate`, `SetPrivateKey`, `UseCertificateChainFile`) and which ones still require parse-then-set choreography or callback-based loading.

## 1. `SSL_use_certificate`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1597), [ssl_rsa.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_rsa.c#L28)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L398), [conn_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_cert.c#L115)
- Verdict: `available`

## 2. `SSL_use_certificate_ASN1`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1598), [ssl_rsa.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_rsa.c#L96)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L425), [conn_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_cert.c#L135)
- Verdict: `available`

## 3. `SSL_use_certificate_file`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1621), [ssl_rsa.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_rsa.c#L45)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L410), [conn_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_cert.c#L125)
- Verdict: `available`

## 4. `SSL_use_certificate_chain_file`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1634), [ssl_rsa.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_rsa.c#L537)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1343), [conn_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_cert.c#L249)
- Verdict: `available`

## 5. `SSL_use_PrivateKey`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1594), [ssl_rsa.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_rsa.c#L138)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L552), [conn_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_cert.c#L153)
- Verdict: `available`

## 6. `SSL_use_PrivateKey_ASN1`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1595), [ssl_rsa.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_rsa.c#L192)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L592), [conn_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_cert.c#L192)
- Verdict: `available`

## 7. `SSL_use_PrivateKey_file`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1620), [ssl_rsa.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_rsa.c#L150)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L564), [conn_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_cert.c#L172)
- Verdict: `available`

## 8. `SSL_CTX_use_certificate`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1746), [ssl_rsa.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_rsa.c#L211)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L350), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L252)
- Verdict: `available`

## 9. `SSL_CTX_use_certificate_file`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1630), [ssl_rsa.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_rsa.c#L277)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L362), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L266)
- Verdict: `available`

## 10. `SSL_CTX_use_certificate_chain_file`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1633), [ssl_rsa.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_rsa.c#L532)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1354), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L1335)
- Verdict: `available`

## Batch 016 summary

Change to `available`:
- `SSL_use_certificate`
- `SSL_use_certificate_ASN1`
- `SSL_use_certificate_file`
- `SSL_use_certificate_chain_file`
- `SSL_use_PrivateKey`
- `SSL_use_PrivateKey_ASN1`
- `SSL_use_PrivateKey_file`
- `SSL_CTX_use_certificate`
- `SSL_CTX_use_certificate_file`
- `SSL_CTX_use_certificate_chain_file`

Main observation:
- This family was previously too pessimistic. openHiTLS already exposes direct object setters and direct file/buffer loading APIs, so these interfaces count as public compatible operations rather than “callback-based loading only”.
