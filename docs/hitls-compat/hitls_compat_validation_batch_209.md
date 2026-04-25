# openHiTLS Compatibility Validation Batch 209

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- standalone params/signature/session decode residue from the remaining `d2i_*` long tail:
  - `d2i_DSA_SIG`
  - `d2i_ECDSA_SIG`
  - `d2i_KeyParams`
  - `d2i_KeyParams_bio`
  - `d2i_PBE2PARAM`
  - `d2i_PBEPARAM`
  - `d2i_PBKDF2PARAM`
  - `d2i_PBMAC1PARAM`
  - `d2i_RSA_OAEP_PARAMS`
  - `d2i_RSA_PSS_PARAMS`
  - `d2i_SCRYPT_PARAMS`
  - `d2i_SSL_SESSION`
  - `d2i_SSL_SESSION_ex`

Status:
- completed

Initial evidence:
- OpenSSL exposes standalone typed decode helpers for:
  - DSA/ECDSA signature wrapper objects
  - key-parameter wrapper objects
  - PBES/PBKDF/PBMAC/scrypt parameter wrappers
  - RSA OAEP/PSS parameter wrappers
  - `SSL_SESSION` decode
- openHiTLS public installed headers expose only adjacent primitive or context-level surfaces:
  - DSA/ECDSA sign/verify and key-management APIs
  - PBKDF2 and scrypt KDF contexts
  - RSA OAEP/PSS control and algorithm support
  - TLS session getters, ticket management, and session-manager internals
- No public installed header exposes a standalone decode API for any of these wrapper objects.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 13`

Reasoning boundary:
- This batch is blocked by missing public standalone decode surfaces.
- openHiTLS has related functionality in neighboring layers, but not the wrapper-object decode path itself.
- The whole batch therefore remains `not_available`.
