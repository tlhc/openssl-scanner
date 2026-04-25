# openHiTLS Compatibility Validation Batch 240

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)
- OpenSSL docs:
  - https://docs.openssl.org/1.1.1/man3/X509_check_host/
  - https://docs.openssl.org/3.0/man3/X509_check_issued/
  - https://docs.openssl.org/3.5/man3/X509_check_ca/

Scope:
- remaining X509 accessor / checker / setter family lacking `analysis_doc`:
  - `X509_get_*`
  - `X509_get0_*`
  - `X509_set_*`
  - `X509_check_*`

Status:
- completed

Initial evidence:
- OpenSSL exposes a wide X509 accessor/checker/setter surface, including:
  - version / serial / pubkey getters and setters
  - extension introspection helpers
  - AKI / SKI / key-usage / pathlen helpers
  - host / IP / CA / issuer / trust / key consistency checks
- openHiTLS public installed tree exposes adjacent public surfaces through:
  - `HITLS_X509_CertCtrl`
  - extension getters:
    - `HITLS_X509_EXT_GET_SKI`
    - `HITLS_X509_EXT_GET_AKI`
    - `HITLS_X509_EXT_GET_KUSAGE`
    - `HITLS_X509_EXT_GET_BCONS`
    - `HITLS_X509_EXT_GET_SAN`
  - identity match helpers:
    - `HITLS_X509_VerifyHostname`
    - `HITLS_X509_VerifyIp`
  - key-pair consistency helper:
    - `HITLS_X509_CheckKey`
- openHiTLS public installed tree still does not expose:
  - generic `ex_data`
  - generic extension index / object / count access
  - authority issuer/serial getters as supported public semantics
  - proxy / trust / purpose checks
  - full `X509_check_issued` semantics

Verdict:
- keep `available = 0`
- adjust to `partial = 18`
- adjust to `not_available = 36`

Reasoning boundary:
- `partial` is justified where openHiTLS has a practical public replacement path:
  - `X509_get_ext_by_NID`
  - `X509_get_key_usage`
  - `X509_get_pathlen`
  - `X509_get_signature_nid`
  - `X509_get_version`
  - `X509_get0_authority_key_id`
  - `X509_get0_serialNumber`
  - `X509_get0_subject_key_id`
  - `X509_set_issuer_name`
  - `X509_set_pubkey`
  - `X509_set_serialNumber`
  - `X509_set_subject_name`
  - `X509_set_version`
  - `X509_check_ca`
  - `X509_check_host`
  - `X509_check_ip`
  - `X509_check_ip_asc`
  - `X509_check_private_key`
- These remain `partial` because the public replacement path is narrower or contract-incompatible:
  - `HITLS_X509_CertCtrl` uses `BslList`, `BSL_Buffer`, `int32_t`, or `CRYPT_EAL_PkeyCtx *`, not OpenSSL wrapper objects
  - `X509_get_ext_by_NID` only has specific extension getter commands, not generic NID/index lookup
  - `X509_get_pathlen` is reachable only via `HITLS_X509_EXT_GET_BCONS.maxPathLen`
  - `X509_check_ip` / `X509_check_ip_asc` use string IP matching and no OpenSSL flag contract
  - `X509_check_private_key` uses a public sign/verify consistency helper instead of the OpenSSL direct compare contract
- `not_available` remains correct for the rest of the family because openHiTLS has no public replacement path for:
  - `X509_get_default_*`
  - `X509_get_ex_data` / `X509_set_ex_data`
  - generic extension object/index/count access
  - `X509_get_extended_key_usage`
  - `X509_get_extension_flags`
  - `X509_get_signature_info`
  - `X509_get_signature_type`
  - `X509_get0_authority_issuer`
  - `X509_get0_authority_serial`
  - `X509_get0_extensions`
  - `X509_get0_pubkey_bitstr`
  - `X509_get0_signature`
  - `X509_get0_tbs_sigalg`
  - proxy setters/getters
  - `X509_check_email`
  - `X509_check_issued`
  - `X509_check_purpose`
  - `X509_check_trust`
- `X509_check_issued` specifically stays `not_available` because `HITLS_X509_IS_SELF_SIGNED` only covers the self-issued/self-signed case, while OpenSSL also checks issuer/subject, AKID, and key-usage consistency.
- `X509_get0_authority_issuer` and `X509_get0_authority_serial` stay `not_available` because the public `HITLS_X509_ExtAki` type marks these fields as not supported.

Representative evidence:
- OpenSSL declarations:
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L533)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L591)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L596)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L660)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L664)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L783)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L911)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L760)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L817)
- OpenSSL implementation evidence:
  - [x509_ext.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_ext.c#L75)
  - [x_x509.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_x509.c#L296)
  - [v3_purp.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/v3_purp.c#L1117)
  - [v3_purp.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/v3_purp.c#L1287)
  - [x509_cmp.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_cmp.c#L127)
  - [x509_cmp.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_cmp.c#L395)
  - [v3_utl.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/v3_utl.c#L1004)
  - [v3_utl.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/v3_utl.c#L1063)
  - [v3_utl.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/v3_utl.c#L1071)
- openHiTLS public declarations:
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L54)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L65)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L67)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L72)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L75)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L96)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L164)
  - [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L176)
  - [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L190)
  - [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L226)
- openHiTLS implementation boundary:
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L591)
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L600)
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L624)
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L634)
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L707)
  - [hitls_x509_util.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_util.c#L160)
  - [hitls_x509_util.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_util.c#L208)
  - [hitls_x509_util.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_util.c#L237)
  - [hitls_x509_util.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_util.c#L285)

Batch 240 inventory:
- total interfaces: `54`
- `partial = 18`
- `not_available = 36`
