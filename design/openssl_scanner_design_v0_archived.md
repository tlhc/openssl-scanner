# OpenSSL 符号依赖扫描工具设计方案

## 一、工具概述

### 1.1 目标

开发一个针对 OpenHarmony 系统的 OpenSSL 符号依赖扫描工具，能够：
- 从可执行文件出发，递归扫描所有依赖的共享库
- 识别对 OpenSSL 库的符号引用
- 生成结构化的依赖报告

### 1.2 技术选型

| 方面 | 选择 | 理由 |
|------|------|------|
| 语言 | Python 3.8+ | 跨平台、丰富的 ELF 解析库 |
| ELF 解析 | pyelftools | 成熟稳定，支持完整 ELF 格式 |
| 并发 | concurrent.futures | 标准库，线程池管理 |
| 输出 | JSON + 控制台 | 结构化 + 人性化 |

### 1.3 OpenHarmony 文件格式

OpenHarmony 使用标准 ELF 格式：
- 架构: ARM64 (aarch64), ARM32 (armv7)
- 共享库后缀: `.so`, `.z.so` (压缩)
- 可执行文件: 无固定后缀

---

## 二、架构设计

### 2.1 模块架构

```
+------------------------------------------------------------------+
|                     openssl_scanner.py                            |
+------------------------------------------------------------------+
|                                                                  |
|  +------------------+    +------------------+    +-------------+ |
|  |   CLI Module     |    |   Scanner Core   |    |   Reporter  | |
|  |  (argparse)      |--->|   (ELF Parser)   |--->|   (JSON)    | |
|  +------------------+    +------------------+    +-------------+ |
|                                |                                 |
|                    +-----------+-----------+                     |
|                    |           |           |                     |
|                    v           v           v                     |
|             +----------+ +----------+ +----------+               |
|             | Symbol   | | Deps     | | OpenSSL  |               |
|             | Extractor| | Resolver | | Matcher  |               |
|             +----------+ +----------+ +----------+               |
|                                                                  |
|  +------------------+    +------------------+                    |
|  |   Thread Pool    |    |   Logger         |                    |
|  |   (Workers)      |    |   (logging)      |                    |
|  +------------------+    +------------------+                    |
+------------------------------------------------------------------+
```

### 2.2 核心类设计

```python
class ELFAnalyzer:
    """ELF 文件分析器"""
    def get_needed_libs(self, path: str) -> List[str]
    def get_undefined_symbols(self, path: str) -> List[Symbol]
    def get_defined_symbols(self, path: str) -> List[Symbol]
    def is_elf_file(self, path: str) -> bool

class DependencyResolver:
    """依赖解析器"""
    def resolve_library(self, name: str, search_paths: List[str]) -> Optional[str]
    def build_dependency_tree(self, root: str) -> DependencyNode

class OpenSSLMatcher:
    """OpenSSL 符号匹配器"""
    def is_openssl_symbol(self, symbol: str) -> bool
    def categorize_symbol(self, symbol: str) -> str  # crypto/ssl/etc

class Scanner:
    """主扫描器"""
    def scan_directory(self, path: str) -> ScanResult
    def scan_file(self, path: str) -> FileResult

class Reporter:
    """报告生成器"""
    def generate_json(self, result: ScanResult) -> str
    def generate_summary(self, result: ScanResult) -> str
```

---

## 三、OpenSSL 符号识别策略

### 3.1 符号前缀匹配

OpenSSL 导出的符号有明确的命名规范：

```python
OPENSSL_SYMBOL_PREFIXES = [
    # libcrypto 符号
    "EVP_",           # 高级加密接口
    "RSA_",           # RSA 算法
    "EC_",            # 椭圆曲线
    "ECDSA_",         # ECDSA 签名
    "ECDH_",          # ECDH 密钥交换
    "AES_",           # AES 算法
    "SHA1_", "SHA256_", "SHA512_",  # 哈希
    "MD5_",           # MD5
    "HMAC_",          # HMAC
    "BN_",            # 大数运算
    "BIO_",           # I/O 抽象
    "PEM_",           # PEM 格式
    "X509_",          # X.509 证书
    "ASN1_",          # ASN.1 编解码
    "PKCS_", "PKCS7_", "PKCS12_",  # PKCS 标准
    "CRYPTO_",        # 底层加密
    "OPENSSL_",       # OpenSSL 工具函数
    "ERR_",           # 错误处理
    "OBJ_",           # OID 对象
    "RAND_",          # 随机数
    "ENGINE_",        # 引擎
    "OSSL_",          # OpenSSL 3.0 新接口

    # libssl 符号
    "SSL_",           # SSL/TLS 接口
    "TLS_",           # TLS 方法
    "DTLS_",          # DTLS 方法

    # SM 国密 (OpenSSL 3.0+)
    "SM2_", "SM3_", "SM4_",
]

# 特殊完整匹配符号
OPENSSL_EXACT_SYMBOLS = [
    "OPENSSL_init_crypto",
    "OPENSSL_init_ssl",
    "OpenSSL_version",
    "OpenSSL_version_num",
]
```

### 3.2 符号分类

```python
def categorize_openssl_symbol(symbol: str) -> str:
    """将符号分类到 OpenSSL 模块"""
    categories = {
        "crypto_evp": ["EVP_"],
        "crypto_rsa": ["RSA_"],
        "crypto_ec": ["EC_", "ECDSA_", "ECDH_"],
        "crypto_aes": ["AES_"],
        "crypto_hash": ["SHA1_", "SHA256_", "SHA512_", "MD5_"],
        "crypto_hmac": ["HMAC_"],
        "crypto_bn": ["BN_"],
        "crypto_bio": ["BIO_"],
        "crypto_x509": ["X509_", "PEM_"],
        "crypto_asn1": ["ASN1_"],
        "crypto_rand": ["RAND_"],
        "crypto_err": ["ERR_"],
        "crypto_engine": ["ENGINE_"],
        "crypto_sm": ["SM2_", "SM3_", "SM4_"],
        "ssl_core": ["SSL_"],
        "ssl_tls": ["TLS_", "DTLS_"],
        "openssl_util": ["OPENSSL_", "OSSL_", "CRYPTO_"],
    }
    for cat, prefixes in categories.items():
        if any(symbol.startswith(p) for p in prefixes):
            return cat
    return "other"
```

---

## 四、依赖解析流程

### 4.1 流程图

```
+-------------------+
| 输入: 可执行文件   |
+--------+----------+
         |
         v
+--------+----------+
| 解析 ELF 头部      |
| 检查是否有效 ELF   |
+--------+----------+
         |
         v
+--------+----------+
| 提取 DT_NEEDED    |
| (直接依赖库列表)   |
+--------+----------+
         |
         v
+--------+----------+
| 解析库路径         |
| (DT_RPATH/RUNPATH)|
+--------+----------+
         |
         v
+--------+----------+
| 递归解析每个依赖库 |
| 构建依赖树        |
+--------+----------+
         |
         v
+--------+----------+
| 提取未定义符号     |
| (UND in .dynsym)  |
+--------+----------+
         |
         v
+--------+----------+
| 匹配 OpenSSL 符号 |
| 分类统计          |
+--------+----------+
         |
         v
+--------+----------+
| 生成报告          |
+-------------------+
```

### 4.2 库搜索路径

```python
DEFAULT_SEARCH_PATHS = [
    # OpenHarmony 系统库路径
    "/system/lib64",
    "/system/lib",
    "/vendor/lib64",
    "/vendor/lib",
    "/system/lib64/ndk",
    "/system/lib64/chipset-pub-sdk",

    # 用户指定的额外路径
    # (通过命令行参数添加)
]
```

---

## 五、输出格式设计

### 5.1 JSON 报告结构

```json
{
  "meta": {
    "tool_version": "1.0.0",
    "scan_time": "2026-01-31T18:30:00+08:00",
    "scan_root": "/system/bin/example_app",
    "target_arch": "aarch64",
    "openssl_version_detected": "3.0.12"
  },

  "summary": {
    "total_files_scanned": 156,
    "total_elf_files": 89,
    "files_with_openssl_deps": 23,
    "total_openssl_symbols": 487,
    "unique_openssl_symbols": 156,
    "openssl_libs_found": [
      "/system/lib64/libcrypto_openssl.so",
      "/system/lib64/libssl_openssl.so"
    ]
  },

  "dependency_tree": {
    "root": "/system/bin/example_app",
    "children": [
      {
        "name": "libnetstack.z.so",
        "path": "/system/lib64/libnetstack.z.so",
        "openssl_symbols": ["SSL_connect", "SSL_read", "SSL_write"],
        "children": [
          {
            "name": "libcurl.z.so",
            "path": "/system/lib64/libcurl.z.so",
            "openssl_symbols": ["EVP_MD_CTX_new", "EVP_DigestInit_ex"],
            "children": [
              {
                "name": "libcrypto_openssl.so",
                "path": "/system/lib64/libcrypto_openssl.so",
                "is_openssl_lib": true,
                "openssl_symbols": []
              },
              {
                "name": "libssl_openssl.so",
                "path": "/system/lib64/libssl_openssl.so",
                "is_openssl_lib": true,
                "openssl_symbols": []
              }
            ]
          }
        ]
      }
    ]
  },

  "openssl_symbols": {
    "by_file": {
      "/system/lib64/libnetstack.z.so": {
        "count": 45,
        "symbols": [
          {"name": "SSL_connect", "category": "ssl_core"},
          {"name": "SSL_read", "category": "ssl_core"},
          {"name": "SSL_write", "category": "ssl_core"},
          {"name": "SSL_CTX_new", "category": "ssl_core"},
          {"name": "EVP_sha256", "category": "crypto_evp"}
        ]
      },
      "/system/lib64/libcurl.z.so": {
        "count": 78,
        "symbols": [
          {"name": "EVP_MD_CTX_new", "category": "crypto_evp"},
          {"name": "EVP_DigestInit_ex", "category": "crypto_evp"},
          {"name": "RSA_public_encrypt", "category": "crypto_rsa"}
        ]
      }
    },

    "by_category": {
      "ssl_core": {
        "count": 45,
        "symbols": ["SSL_connect", "SSL_read", "SSL_write", "SSL_CTX_new"]
      },
      "crypto_evp": {
        "count": 67,
        "symbols": ["EVP_MD_CTX_new", "EVP_DigestInit_ex", "EVP_sha256"]
      },
      "crypto_rsa": {
        "count": 12,
        "symbols": ["RSA_public_encrypt", "RSA_private_decrypt"]
      },
      "crypto_x509": {
        "count": 34,
        "symbols": ["X509_new", "X509_verify_cert"]
      }
    },

    "all_unique": [
      "SSL_connect",
      "SSL_read",
      "SSL_write",
      "EVP_MD_CTX_new",
      "EVP_DigestInit_ex",
      "RSA_public_encrypt"
    ]
  },

  "files_detail": [
    {
      "path": "/system/bin/example_app",
      "type": "executable",
      "arch": "aarch64",
      "direct_deps": ["libnetstack.z.so", "libc++.so"],
      "openssl_deps": {
        "direct": false,
        "transitive": true,
        "via": ["libnetstack.z.so"]
      },
      "openssl_symbols_used": []
    },
    {
      "path": "/system/lib64/libnetstack.z.so",
      "type": "shared_library",
      "arch": "aarch64",
      "direct_deps": ["libcurl.z.so", "libssl_openssl.so"],
      "openssl_deps": {
        "direct": true,
        "libs": ["libssl_openssl.so", "libcrypto_openssl.so"]
      },
      "openssl_symbols_used": [
        "SSL_connect",
        "SSL_read",
        "SSL_write"
      ]
    }
  ],

  "errors": [
    {
      "file": "/system/lib64/broken.so",
      "error": "Invalid ELF header",
      "severity": "warning"
    }
  ]
}
```

### 5.2 控制台输出示例

```
================================================================================
                    OpenSSL Symbol Dependency Scanner v1.0.0
================================================================================

Scan Target: /system/bin/example_app
Scan Time:   2026-01-31 18:30:00
Architecture: aarch64

--------------------------------------------------------------------------------
                              SCAN SUMMARY
--------------------------------------------------------------------------------

Total Files Scanned:       156
ELF Files Found:           89
Files with OpenSSL Deps:   23

OpenSSL Libraries Found:
  - /system/lib64/libcrypto_openssl.so (v3.0.12)
  - /system/lib64/libssl_openssl.so (v3.0.12)

--------------------------------------------------------------------------------
                           DEPENDENCY TREE
--------------------------------------------------------------------------------

/system/bin/example_app
├── libnetstack.z.so [OpenSSL: 45 symbols]
│   ├── libcurl.z.so [OpenSSL: 78 symbols]
│   │   ├── libcrypto_openssl.so ★
│   │   └── libssl_openssl.so ★
│   └── libssl_openssl.so ★
├── libhuks_client.z.so [OpenSSL: 23 symbols]
│   └── libcrypto_openssl.so ★
└── libc++.so

(★ = OpenSSL library)

--------------------------------------------------------------------------------
                         OPENSSL SYMBOLS SUMMARY
--------------------------------------------------------------------------------

Total OpenSSL Symbols Referenced: 487
Unique Symbols: 156

By Category:
  ssl_core      ████████████████████  45 (29%)
  crypto_evp    ██████████████████████████████  67 (43%)
  crypto_rsa    ██████  12 (8%)
  crypto_x509   ████████████████  34 (22%)
  crypto_hash   ████████  18 (12%)
  crypto_bn     ████  8 (5%)
  other         ██  6 (4%)

Top 10 Most Used Symbols:
  1. SSL_read           (15 files)
  2. SSL_write          (15 files)
  3. EVP_MD_CTX_new     (12 files)
  4. EVP_DigestInit_ex  (12 files)
  5. SSL_connect        (10 files)
  6. X509_verify_cert   (8 files)
  7. RSA_public_encrypt (7 files)
  8. EVP_sha256         (6 files)
  9. BIO_new            (6 files)
  10. RAND_bytes        (5 files)

--------------------------------------------------------------------------------
                              WARNINGS
--------------------------------------------------------------------------------

[WARN] /system/lib64/broken.so: Invalid ELF header (skipped)
[WARN] libmissing.so: Library not found in search paths

--------------------------------------------------------------------------------

Report saved to: openssl_deps_report.json

Scan completed in 2.34 seconds.
```

---

## 六、命令行接口设计

### 6.1 使用方式

```bash
# 基本用法
openssl_scanner /system/bin/my_app

# 指定输出文件
openssl_scanner /system/bin/my_app -o report.json

# 扫描整个目录
openssl_scanner /system/lib64 --scan-dir

# 添加库搜索路径
openssl_scanner /system/bin/my_app -L /vendor/lib64 -L /data/app/libs

# 详细日志
openssl_scanner /system/bin/my_app -v

# 多线程
openssl_scanner /system/bin/my_app -j 8

# 只输出 JSON
openssl_scanner /system/bin/my_app --json-only

# 过滤特定符号类别
openssl_scanner /system/bin/my_app --category ssl_core,crypto_evp
```

### 6.2 完整参数

```
usage: openssl_scanner [-h] [-o OUTPUT] [-L LIB_PATH] [-v] [-j JOBS]
                       [--scan-dir] [--json-only] [--category CATEGORY]
                       [--log-file LOG_FILE] [--version]
                       target

OpenSSL Symbol Dependency Scanner for OpenHarmony

positional arguments:
  target                Target executable or directory to scan

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output JSON report file (default: openssl_deps_report.json)
  -L LIB_PATH, --lib-path LIB_PATH
                        Additional library search path (can be used multiple times)
  -v, --verbose         Enable verbose logging
  -j JOBS, --jobs JOBS  Number of parallel workers (default: CPU count)
  --scan-dir            Scan all ELF files in directory instead of dependency tree
  --json-only           Output JSON only, no console summary
  --category CATEGORY   Filter symbols by category (comma-separated)
  --log-file LOG_FILE   Write logs to file
  --version             Show version information
```

---

## 七、实现计划

### 7.1 文件结构

```
openssl_scanner/
├── openssl_scanner.py      # 主入口 (单文件版本)
├── requirements.txt        # 依赖: pyelftools
└── README.md               # 使用说明

# 或模块化版本:
openssl_scanner/
├── __init__.py
├── __main__.py             # CLI 入口
├── scanner.py              # 核心扫描逻辑
├── elf_analyzer.py         # ELF 解析
├── openssl_matcher.py      # OpenSSL 符号匹配
├── dependency_resolver.py  # 依赖解析
├── reporter.py             # 报告生成
├── logger.py               # 日志配置
└── constants.py            # 常量定义
```

### 7.2 开发阶段

| 阶段 | 内容 | 预估时间 |
|------|------|----------|
| Phase 1 | ELF 解析 + 符号提取 | - |
| Phase 2 | 依赖树构建 | - |
| Phase 3 | OpenSSL 符号匹配 | - |
| Phase 4 | 报告生成 | - |
| Phase 5 | CLI + 多线程 | - |
| Phase 6 | 测试 + 优化 | - |

---

## 八、待讨论问题

### 8.1 功能范围

1. **是否需要支持静态库 (.a) 扫描?**
   - 当前设计只支持动态库和可执行文件
   - 静态库需要额外的 ar 解析

2. **是否需要符号版本信息?**
   - OpenSSL 3.0 引入了符号版本
   - 例如: `OPENSSL_3.0.0` 版本标签

3. **是否需要交叉编译支持?**
   - 在 x86 主机上分析 ARM ELF 文件
   - pyelftools 支持，但需要测试

### 8.2 输出格式

1. **JSON 结构是否合适?**
   - 是否需要其他格式 (CSV, HTML)?
   - 依赖树的展示深度是否需要限制?

2. **符号分类是否完整?**
   - 是否需要添加更多 OpenSSL 符号前缀?
   - 是否需要区分 OpenSSL 1.x 和 3.x 符号?

### 8.3 性能考量

1. **大目录扫描的内存占用**
   - 是否需要流式处理?
   - 是否需要增量扫描?

2. **循环依赖处理**
   - A -> B -> C -> A 的情况
   - 当前设计使用访问集合避免重复

---

## 九、替代方案对比

| 方案 | 优点 | 缺点 |
|------|------|------|
| **Python + pyelftools** | 跨平台、易开发 | 性能一般 |
| C + libelf | 高性能 | 开发复杂 |
| Rust + goblin | 高性能、安全 | 学习曲线 |
| Shell + readelf | 简单快速 | 功能有限 |

**推荐**: Python + pyelftools (开发效率优先)

---

请确认以上设计方案，或提出修改意见，我将开始实现。
