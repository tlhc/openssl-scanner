"""
OpenSSL library patterns and symbol categorization.
"""

from typing import Dict, List

OPENSSL_LIBRARY_PATTERNS: List[str] = [
    "libcrypto",
    "libssl",
    "libcrypto_openssl",
    "libssl_openssl",
]

SYMBOL_CATEGORIES: Dict[str, List[str]] = {
    "ssl_core": ["SSL_"],
    "ssl_tls": ["TLS_", "DTLS_"],
    "crypto_evp": ["EVP_"],
    "crypto_rsa": ["RSA_"],
    "crypto_dsa": ["DSA_"],
    "crypto_dh": ["DH_"],
    "crypto_ec": ["EC_", "ECDSA_", "ECDH_", "ED25519_", "ED448_", "X25519_", "X448_"],
    "crypto_aes": ["AES_"],
    "crypto_des": ["DES_"],
    "crypto_chacha": ["CHACHA_", "POLY1305_"],
    "crypto_hash": ["SHA1_", "SHA224_", "SHA256_", "SHA384_", "SHA512_", "SHA3_",
                   "MD4_", "MD5_", "RIPEMD160_", "BLAKE2_"],
    "crypto_hmac": ["HMAC_", "CMAC_", "GMAC_", "SIPHASH_"],
    "crypto_bn": ["BN_"],
    "crypto_bio": ["BIO_"],
    "crypto_pem": ["PEM_"],
    "crypto_asn1": ["ASN1_", "d2i_", "i2d_"],
    "crypto_x509": ["X509_", "X509V3_"],
    "crypto_pkcs": ["PKCS7_", "PKCS12_", "PKCS5_", "PKCS8_"],
    "crypto_cms": ["CMS_"],
    "crypto_ocsp": ["OCSP_"],
    "crypto_ts": ["TS_"],
    "crypto_rand": ["RAND_"],
    "crypto_err": ["ERR_"],
    "crypto_obj": ["OBJ_"],
    "crypto_engine": ["ENGINE_"],
    "crypto_provider": ["OSSL_PROVIDER_", "OSSL_PARAM_", "OSSL_STORE_"],
    "crypto_kdf": ["HKDF_", "PBKDF2_", "SCRYPT_", "KDF_"],
    "crypto_sm": ["SM2_", "SM3_", "SM4_"],
    "openssl_util": ["OPENSSL_", "OSSL_", "CRYPTO_"],
}

DEFAULT_SEARCH_PATHS: List[str] = [
    # OpenHarmony system paths
    "/system/lib64",
    "/system/lib",
    "/system/lib64/ndk",
    "/system/lib64/chipset-pub-sdk",
    "/system/lib64/module",
    "/system/lib64/module/security",

    # Vendor paths
    "/vendor/lib64",
    "/vendor/lib",

    # Chip SDK paths
    "/chipset/lib64",
    "/chipset/lib",

    # Standard Linux paths (for host analysis)
    "/lib64",
    "/lib",
    "/usr/lib64",
    "/usr/lib",
    "/usr/local/lib64",
    "/usr/local/lib",

    # Debian/Ubuntu multiarch paths
    "/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/lib/arm-linux-gnueabihf",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/usr/lib/arm-linux-gnueabihf",
]

CATEGORY_DISPLAY_ORDER: List[str] = [
    "ssl_core",
    "ssl_tls",
    "crypto_evp",
    "crypto_rsa",
    "crypto_ec",
    "crypto_aes",
    "crypto_hash",
    "crypto_hmac",
    "crypto_x509",
    "crypto_pkcs",
    "crypto_bio",
    "crypto_asn1",
    "crypto_bn",
    "crypto_rand",
    "crypto_err",
    "crypto_sm",
    "openssl_util",
]
