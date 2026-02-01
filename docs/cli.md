# OpenSSL Scanner CLI 使用文档

## 概述

`openssl-scanner` 是一个 ELF 二进制文件的 OpenSSL 符号依赖扫描工具，专为 OpenHarmony 系统设计。通过解析 ELF 文件的动态符号表，精确识别对 OpenSSL 库的依赖关系。

**主要功能：**
- **扫描** (`scan`) - 分析单个二进制或目录，生成 JSON 报告
- **聚合** (`aggregate`) - 合并多个扫描报告，按组件统计
- **导出** (`export`) - 将 JSON 报告转换为 HTML 或 Excel 格式

## 安装

```bash
# 从源码安装（基础功能）
cd scanner
pip install -e .

# 安装 Excel 导出支持
pip install -e ".[export]"

# 安装开发依赖（测试、类型检查等）
pip install -e ".[dev]"

# 验证安装
openssl-scanner --version
```

---

## 命令概览

```bash
openssl-scanner <command> [options]

Commands:
  scan        扫描二进制或目录，分析 OpenSSL 依赖
  aggregate   聚合多个扫描报告，生成汇总分析
  export      将 JSON 报告导出为 HTML 或 Excel
```

> **提示：** 直接运行 `openssl-scanner <target>` 等同于 `openssl-scanner scan <target>`

---

## 命令详解

### 1. scan - 扫描命令

分析 ELF 二进制文件或目录中的 OpenSSL 符号依赖。

#### 语法

```bash
openssl-scanner scan <target> [options]
```

#### 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `target` | (必需) | 扫描目标：可执行文件路径或目录路径 |
| `--openssl-lib PATH` | 自动检测 | libcrypto.so 的路径 |
| `--openssl-ssl PATH` | 自动检测 | libssl.so 的路径 |
| `-o, --output FILE` | `openssl_deps_report.json` | 输出 JSON 报告路径 |
| `-L, --lib-path PATH` | - | 额外库搜索路径（可多次使用） |
| `-v, --verbose` | false | 启用详细日志 |
| `-j, --jobs N` | CPU 核心数 | 并行工作线程数 |
| `--scan-dir` | false | 目录扫描模式（扫描所有 ELF 文件） |
| `--json-only` | false | 仅输出 JSON，不显示控制台摘要 |
| `--no-recursive` | false | 不递归子目录（配合 `--scan-dir`） |
| `--log-file FILE` | - | 日志写入文件 |

#### 示例

```bash
# 场景 1: 扫描单个可执行文件
# - 自动检测 OpenSSL 库
# - 递归分析依赖树
openssl-scanner scan /system/bin/netd -o netd_report.json

# 场景 2: 扫描整个系统库目录
# - 扫描 /system/lib64 下所有 ELF 文件
# - 使用 8 线程并行分析
openssl-scanner scan /system/lib64 \
    --scan-dir \
    -j 8 \
    -o system_libs_report.json

# 场景 3: 交叉分析（设备 A 的二进制 + 设备 B 的 OpenSSL）
# - 手动指定 OpenSSL 库路径
# - 添加多个库搜索路径
openssl-scanner scan /extracted/system/bin/wpa_supplicant \
    --openssl-lib /extracted/system/lib64/libcrypto.so.3 \
    --openssl-ssl /extracted/system/lib64/libssl.so.3 \
    -L /extracted/system/lib64 \
    -L /extracted/vendor/lib64 \
    -o wpa_supplicant_report.json

# 场景 4: CI/CD 集成
# - JSON-only 模式，适合管道处理
# - 详细日志写入文件
openssl-scanner scan /build/out/system \
    --scan-dir \
    --json-only \
    -v \
    --log-file scan.log \
    -o build_report.json
```

---

### 2. aggregate - 聚合命令

将多个扫描报告合并，按组件分组统计 OpenSSL 符号使用情况。

#### 语法

```bash
openssl-scanner aggregate <reports_dir> [options]
```

#### 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `reports_dir` | (必需) | 包含 JSON 报告的目录 |
| `-m, --mapping FILE` | - | 组件映射文件（JSON 格式） |
| `-o, --output FILE` | `aggregated_report.json` | 输出聚合报告路径 |
| `--top N` | 20 | 显示前 N 个组件 |
| `--json-only` | false | 仅输出 JSON |
| `-v, --verbose` | false | 详细日志 |
| `--log-file FILE` | - | 日志文件 |

#### 映射文件格式

```json
{
  "network_stack": [
    "/system/bin/netd",
    "/system/lib64/libnetstack.so"
  ],
  "crypto_service": [
    "/system/bin/huks_service",
    "/system/lib64/libhuks_client.so"
  ]
}
```

#### 示例

```bash
# 场景 1: 聚合目录中所有报告
# - 自动按二进制名称分组
openssl-scanner aggregate /reports/ -o aggregated.json

# 场景 2: 使用组件映射文件
# - 将多个二进制归类到逻辑组件
# - 显示前 30 个组件
openssl-scanner aggregate /reports/ \
    -m component_mapping.json \
    --top 30 \
    -o aggregated.json

# 场景 3: 批量扫描后聚合
# 步骤 1: 扫描多个二进制
for bin in /system/bin/*; do
    name=$(basename "$bin")
    openssl-scanner scan "$bin" \
        --json-only \
        -o "/reports/${name}_report.json" 2>/dev/null || true
done

# 步骤 2: 聚合所有报告
openssl-scanner aggregate /reports/ -o aggregated.json
```

---

### 3. export - 导出命令

将 JSON 报告转换为可视化格式（HTML 或 Excel）。

#### 语法

```bash
openssl-scanner export <report.json> -o <output> [options]
```

#### 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `report` | (必需) | 输入 JSON 报告文件 |
| `-o, --output FILE` | (必需) | 输出文件路径（.html 或 .xlsx） |
| `-f, --format FORMAT` | 自动检测 | 输出格式：`html` 或 `xlsx` |
| `-v, --verbose` | false | 详细日志 |
| `--log-file FILE` | - | 日志文件 |

#### 示例

```bash
# 场景 1: 导出为交互式 HTML 报告
# - 自包含（无需网络）
# - 包含交互式图表
openssl-scanner export aggregated.json -o report.html

# 场景 2: 导出为 Excel 工作簿
# - 多个工作表（Overview, Ranking, Symbols 等）
# - 适合数据分析和报表
openssl-scanner export aggregated.json -o report.xlsx

# 场景 3: 完整工作流（扫描 -> 聚合 -> 导出）
openssl-scanner scan /system/lib64 --scan-dir -o scan.json
openssl-scanner aggregate /reports/ -o aggregated.json
openssl-scanner export aggregated.json -o report.html
openssl-scanner export aggregated.json -o report.xlsx
```

---

## 输出格式详解

### JSON 报告结构（单次扫描）

```json
{
  "meta": {
    "tool_version": "1.0.0",
    "scan_time": "2026-01-31T12:00:00.000000",
    "scan_root": "/system/bin/example_app",
    "target_arch": "aarch64",
    "report_type": "single"
  },

  "summary": {
    "total_files_scanned": 33,
    "total_elf_files": 33,
    "files_with_openssl_deps": 4,
    "total_openssl_symbols": 487,
    "unique_openssl_symbols": 156,
    "openssl_libs_found": [
      "/system/lib64/libcrypto.so.3",
      "/system/lib64/libssl.so.3"
    ]
  },

  "openssl_symbols": {
    "by_file": {
      "/system/lib64/libnetstack.so": {
        "count": 45,
        "symbols": ["SSL_connect", "SSL_read", "SSL_write"]
      }
    },
    "by_category": {
      "ssl_core": { "count": 54, "symbols": ["SSL_connect", ...] },
      "crypto_evp": { "count": 89, "symbols": ["EVP_DigestInit", ...] }
    },
    "by_depth": {
      "0": { "count": 0, "symbols": [] },
      "1": { "count": 45, "symbols": ["SSL_connect", ...] },
      "2": { "count": 111, "symbols": ["EVP_DigestInit", ...] }
    },
    "import_chains": {
      "SSL_connect": ["example_app -> libnetstack.so -> libssl.so.3"],
      "EVP_sha256": [
        "example_app -> libnetstack.so -> libcrypto.so.3",
        "example_app -> libnetstack.so -> libssl.so.3 -> libcrypto.so.3"
      ]
    },
    "all_unique": ["EVP_DigestInit", "SSL_connect", ...]
  },

  "dependency_tree": {
    "name": "example_app",
    "path": "/system/bin/example_app",
    "is_openssl_lib": false,
    "openssl_symbols_count": 0,
    "children": [...]
  },

  "files_detail": [...],
  "errors": []
}
```

### JSON 报告结构（聚合报告）

```json
{
  "meta": {
    "tool_version": "1.0.0",
    "aggregation_time": "2026-01-31T15:30:00.000000",
    "report_type": "aggregated",
    "source_reports_count": 74,
    "mapping_file": "component_mapping.json"
  },

  "summary": {
    "total_components": 45,
    "total_executables": 74,
    "global_unique_symbols": 312
  },

  "ranking": [
    { "rank": 1, "component": "curl", "unique_symbols_count": 156 },
    { "rank": 2, "component": "wpa_supplicant", "unique_symbols_count": 89 },
    { "rank": 3, "component": "netstack", "unique_symbols_count": 67 }
  ],

  "components": {
    "curl": {
      "executables": ["/system/bin/curl"],
      "unique_symbols_count": 156,
      "symbols": ["SSL_connect", "EVP_sha256", ...],
      "by_category": {
        "ssl_core": { "count": 45, "symbols": [...] },
        "crypto_evp": { "count": 67, "symbols": [...] }
      }
    }
  },

  "global_by_category": {
    "ssl_core": { "count": 89, "symbols": [...] },
    "crypto_evp": { "count": 134, "symbols": [...] }
  }
}
```

### HTML 报告特性

HTML 报告为**完全自包含**的单文件，包含：

| 功能 | 说明 |
|------|------|
| **概览卡片** | 组件数、符号数、扫描时间等关键指标 |
| **组件排名表** | 按 OpenSSL 符号使用量排序，支持点击查看详情 |
| **分类分布图** | SVG 条形图展示各 API 类别使用占比 |
| **符号统计图** | SVG 饼图展示符号分类分布 |
| **组件详情弹窗** | 点击组件名查看其使用的具体符号列表 |
| **Excel 导出** | 浏览器内直接导出 Excel（使用嵌入的 SheetJS） |

```
+---------------------------------------------------------------+
|  OpenSSL Dependency Report                                     |
+---------------------------------------------------------------+
|  Components: 45    Symbols: 312    Scan Time: 2026-01-31      |
+---------------------------------------------------------------+
|                                                                 |
|  COMPONENT RANKING                      CATEGORY DISTRIBUTION   |
|  +-----------------------------+        +-----------------+     |
|  | # | Component    | Symbols |        | ssl_core    ███ 28%|  |
|  |---|--------------|---------|        | crypto_evp ████ 43%|  |
|  | 1 | curl         |     156 |        | crypto_x509 ██  11%|  |
|  | 2 | wpa_supplicant|     89 |        | crypto_rsa  █   8% |  |
|  | 3 | netstack     |      67 |        | ...              ...|  |
|  +-----------------------------+        +-----------------+     |
|                                                                 |
|  [Export to Excel]                                             |
+---------------------------------------------------------------+
```

### Excel 工作表结构

| 工作表 | 内容 |
|--------|------|
| **Overview** | 元数据、扫描摘要、关键指标 |
| **Ranking** | 组件排名（#、组件名、符号数、占比） |
| **Category Pivot** | 组件-分类矩阵（透视表） |
| **Symbols** | 所有符号列表（符号名、使用组件、分类） |
| **By File** | 按文件统计（文件路径、符号数、符号列表） |
| **By Component** | 按组件统计（组件、符号数、分类、符号列表） |

---

## 控制台输出示例

### 单次扫描输出

```
================================================================================
                    OpenSSL Symbol Dependency Scanner v1.0.0
================================================================================

Scan Target: /system/bin/example_app
Scan Time:   2026-01-31T12:00:00.000000
Architecture: aarch64

--------------------------------------------------------------------------------
                                  SCAN SUMMARY
--------------------------------------------------------------------------------

Total Files Scanned:       33
ELF Files Found:           33
Files with OpenSSL Deps:   4

OpenSSL Libraries Found:
  - /system/lib64/libcrypto.so.3
  - /system/lib64/libssl.so.3

--------------------------------------------------------------------------------
                                DEPENDENCY TREE
--------------------------------------------------------------------------------

+-- example_app
    +-- libnetstack.so [OpenSSL: 45 symbols]
    |   +-- libssl.so.3*
    |   |   +-- libcrypto.so.3*
    |   +-- libcrypto.so.3* (circular dependency)
    +-- libc.so.6

(* = OpenSSL library)

--------------------------------------------------------------------------------
                            OPENSSL SYMBOLS SUMMARY
--------------------------------------------------------------------------------

Total OpenSSL Symbols Referenced: 487
Unique Symbols: 156

By Dependency Depth:
  depth 1     : 45 unique symbols
  depth 2     : 111 unique symbols

By Category:
  ssl_core             ##################             54
  crypto_evp           ############################## 89
  crypto_x509          ##########                     34
  crypto_rsa           #####                          12
  crypto_hash          ########                       18

Top 10 Most Common Symbols:
   1. EVP_MD_CTX_new                           (4 files)
   2. SSL_read                                 (3 files)
   3. SSL_write                                (3 files)
   4. EVP_DigestInit_ex                        (3 files)
   5. SSL_connect                              (2 files)

--------------------------------------------------------------------------------

OpenSSL symbols loaded: 5882
Report saved to: openssl_deps_report.json
Scan completed in 1.23 seconds.
```

### 聚合报告输出

```
================================================================================
              OpenSSL Symbol Dependency Aggregated Report v1.0.0
================================================================================

Aggregation Time: 2026-01-31T15:30:00.000000
Source Reports:   74
Mapping File:     component_mapping.json

--------------------------------------------------------------------------------
                                  SUMMARY
--------------------------------------------------------------------------------

Total Components:          45
Total Executables:         74
Global Unique Symbols:     312

--------------------------------------------------------------------------------
                            COMPONENT RANKING
--------------------------------------------------------------------------------

 Rank  Component                         Unique Symbols    Percentage
--------------------------------------------------------------------------------
    1  curl                                        156        50.0%
    2  wpa_supplicant                               89        28.5%
    3  netstack                                     67        21.5%
    4  huks_service                                 45        14.4%
    5  certificate_manager                          34        10.9%
    ...

--------------------------------------------------------------------------------
                          CATEGORY DISTRIBUTION
--------------------------------------------------------------------------------

  ssl_core             ##################             89 (28.5%)
  crypto_evp           ##########################    134 (42.9%)
  crypto_x509          ##########                     45 (14.4%)
  crypto_rsa           #####                          23 ( 7.4%)
  crypto_hash          ####                           18 ( 5.8%)
  crypto_sm            ##                              8 ( 2.6%)

--------------------------------------------------------------------------------

Report saved to: aggregated_report.json
Aggregation completed in 0.45 seconds.
```

---

## 符号分类说明

| 分类 | 前缀 | 说明 |
|------|------|------|
| `ssl_core` | SSL_ | SSL/TLS 核心功能（连接、读写等） |
| `ssl_tls` | TLS_, DTLS_ | TLS/DTLS 协议方法 |
| `crypto_evp` | EVP_ | 高级加密接口（通用加解密） |
| `crypto_rsa` | RSA_ | RSA 非对称加密 |
| `crypto_ec` | EC_, ECDSA_, ECDH_ | 椭圆曲线加密 |
| `crypto_aes` | AES_ | AES 对称加密 |
| `crypto_hash` | SHA*, MD5_ | 哈希函数 |
| `crypto_hmac` | HMAC_ | HMAC 消息认证码 |
| `crypto_bn` | BN_ | 大数运算 |
| `crypto_bio` | BIO_ | I/O 抽象层 |
| `crypto_x509` | X509_ | X.509 证书处理 |
| `crypto_pkcs` | PKCS* | PKCS 标准实现 |
| `crypto_rand` | RAND_ | 随机数生成 |
| `crypto_err` | ERR_ | 错误处理 |
| `crypto_sm` | SM2_, SM3_, SM4_ | 国密算法（中国标准） |
| `openssl_util` | OPENSSL_, OSSL_ | OpenSSL 工具函数 |

---

## 实际应用场景

### 场景 1: 安全审计 - 识别 OpenSSL 依赖组件

```bash
# 1. 扫描整个系统分区
openssl-scanner scan /system \
    --scan-dir \
    -j 16 \
    -o system_scan.json

# 2. 导出为 Excel 用于审计报告
openssl-scanner export system_scan.json -o security_audit.xlsx
```

### 场景 2: 版本升级影响分析

```bash
# 对比分析：用新版 OpenSSL 的符号表分析现有二进制
# 找出哪些符号在新版本中被移除

openssl-scanner scan /current/system/lib64 \
    --scan-dir \
    --openssl-lib /openssl-3.2/lib/libcrypto.so \
    -o upgrade_impact.json
```

### 场景 3: CI/CD 集成 - 构建时依赖检查

```bash
#!/bin/bash
# build_check.sh - 检查构建产物的 OpenSSL 依赖

BUILD_DIR=$1
REPORT_DIR=/artifacts/reports

# 扫描构建输出
openssl-scanner scan "$BUILD_DIR" \
    --scan-dir \
    --json-only \
    -o "$REPORT_DIR/build_scan.json"

# 生成可视化报告
openssl-scanner export "$REPORT_DIR/build_scan.json" \
    -o "$REPORT_DIR/openssl_deps.html"

# 检查是否使用了禁用的符号（如 MD5）
if grep -q '"MD5_' "$REPORT_DIR/build_scan.json"; then
    echo "WARNING: Build uses deprecated MD5 functions"
    exit 1
fi
```

### 场景 4: 多版本对比分析

```bash
# 分析 OpenHarmony 不同版本的 OpenSSL 使用变化

# 扫描 v4.0
openssl-scanner scan /oh-4.0/system --scan-dir -o reports/v4.0.json

# 扫描 v5.0
openssl-scanner scan /oh-5.0/system --scan-dir -o reports/v5.0.json

# 聚合对比
openssl-scanner aggregate reports/ -o version_comparison.json
openssl-scanner export version_comparison.json -o version_comparison.html
```

---

## 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 成功完成 |
| 1 | 失败（参数错误、文件不存在、解析失败等） |
| 130 | 用户中断 (Ctrl+C) |

---

## 常见问题

### Q: 什么时候需要手动指定 --openssl-lib？

大多数情况下**不需要**。工具会自动检测：
- 二进制扫描：从依赖树中发现
- 目录扫描：先在目标目录查找，再回退系统路径

需要手动指定的场景：
- 交叉分析：分析设备 A 的二进制，使用设备 B 的 OpenSSL 符号表
- 自动检测失败时
- 测试特定版本 OpenSSL 的兼容性

### Q: by_depth 中的深度是什么意思？

```
depth 0: 根二进制自身引用的 OpenSSL 符号
depth 1: 直接依赖库引用的符号
depth 2: 间接依赖（依赖的依赖）引用的符号
...以此类推
```

### Q: HTML 报告需要网络连接吗？

**不需要**。HTML 报告完全自包含，所有 JavaScript、CSS、图表库（SheetJS）都已嵌入文件中。可在离线环境使用。

### Q: Excel 导出需要安装额外依赖吗？

**服务端导出需要**：
```bash
pip install openpyxl  # 或 pip install -e ".[export]"
```

**浏览器导出不需要**：HTML 报告中已嵌入 SheetJS 库，可直接在浏览器中点击导出。

### Q: 如何找到 OpenSSL 库的路径？

```bash
# Linux 系统
find /usr -name "libcrypto.so*" 2>/dev/null
ldconfig -p | grep crypto

# OpenHarmony 设备
ls /system/lib64/libcrypto*
ls /system/lib64/libssl*
```

### Q: 为什么使用严格匹配模式？

工具从实际的 OpenSSL 库提取导出符号，与目标文件的未定义符号做**集合交集**：

```
OpenSSL deps = exports(libcrypto) ∩ imports(target)
```

这确保 100% 匹配准确率，**没有误报**（不会把恰好以 `EVP_` 开头但非 OpenSSL 的符号误判）。

---

## 工作原理

```
+-------------------+     +-------------------+
| libcrypto.so      |     | Target Binary     |
| (--openssl-lib)   |     | (target)          |
+--------+----------+     +--------+----------+
         |                         |
         v                         v
+--------+----------+     +--------+----------+
| Extract DEFINED   |     | Extract UNDEFINED |
| symbols (exports) |     | symbols (imports) |
+--------+----------+     +--------+----------+
         |                         |
         +-----------+-------------+
                     |
                     v
             +-------+-------+
             | Set           |
             | Intersection  |
             +-------+-------+
                     |
                     v
             +-------+-------+
             | OpenSSL Deps  |
             +---------------+
```

---

## 版本信息

```bash
openssl-scanner --version
# openssl-scanner 1.0.0
```

## 许可证

Apache-2.0
