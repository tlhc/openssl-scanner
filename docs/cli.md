# OpenSSL Scanner CLI 文档

## 快速开始（免安装）

所有依赖已内置，仅需 Python 3.8+，克隆后直接运行：

```bash
git clone https://github.com/anthropics/openssl-scanner.git
cd openssl-scanner

# 扫描
./scan scan /path/to/binary -o report.json

# 聚合
./scan aggregate /reports/ -o aggregated.json

# 导出
./scan export report.json -o report.xlsx
```

### 在任意位置运行

```bash
# 使用绝对路径
/path/to/openssl-scanner/scan scan /path/to/binary -o report.json

# 或创建符号链接
ln -s /path/to/openssl-scanner/scan /usr/local/bin/openssl-scanner
openssl-scanner scan /path/to/binary -o report.json
```

### 内置依赖

| 依赖 | 用途 |
|------|------|
| elftools (pyelftools) | ELF 解析 |
| openpyxl + et_xmlfile | Excel 导出 |

---

## 命令概览

```bash
./scan <command> [options]

Commands:
  scan        扫描二进制或目录
  aggregate   聚合多个扫描报告
  export      导出为 HTML 或 Excel
```

> 直接运行 `./scan <target>` 等同于 `./scan scan <target>`

---

## scan - 扫描命令

### 语法

```bash
./scan scan <target> [options]
```

### 参数

| 参数 | 说明 |
|------|------|
| `target` | 扫描目标（文件或目录） |
| `--openssl-lib PATH` | 指定 libcrypto.so 路径（默认自动检测） |
| `--openssl-ssl PATH` | 指定 libssl.so 路径 |
| `-o, --output FILE` | 输出文件（默认: openssl_deps_report.json） |
| `-L, --lib-path PATH` | 额外库搜索路径（可多次使用） |
| `-j, --jobs N` | 并行线程数（默认: CPU 核心数） |
| `--scan-dir` | 目录扫描模式 |
| `--no-recursive` | 不递归子目录 |
| `--json-only` | 仅输出 JSON |
| `-v, --verbose` | 详细日志 |

### 示例

```bash
# 单二进制扫描（Tree Scan）
./scan scan /usr/bin/curl -o curl.json

# 目录扫描（Directory Scan）
./scan scan /usr/bin --scan-dir -j 8 -o usrbin.json

# 指定 OpenSSL 库路径
./scan scan /path/to/app \
    --openssl-lib /lib/libcrypto.so.3 \
    -L /custom/lib64 \
    -o report.json
```

### 两种扫描模式

| 模式 | 触发方式 | 特点 |
|------|----------|------|
| **Tree Scan** | 目标是文件 | 递归分析依赖树，生成 `dependency_tree`，多层 `by_depth` |
| **Directory Scan** | `--scan-dir` | 扫描所有 ELF，使用 `DependencyGraph` 计算 import chains |

---

## aggregate - 聚合命令

### 语法

```bash
./scan aggregate <reports_dir> [options]
```

### 参数

| 参数 | 说明 |
|------|------|
| `reports_dir` | 包含 JSON 报告的目录 |
| `-m, --mapping FILE` | 组件映射文件 |
| `-o, --output FILE` | 输出文件（默认: aggregated_report.json） |
| `--top N` | 显示前 N 个组件（默认: 20） |
| `--json-only` | 仅输出 JSON |

### 映射文件格式

```json
{
  "openssh": ["/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/sftp"],
  "curl": ["/usr/bin/curl"]
}
```

### 示例

```bash
# 不使用映射（每个二进制作为独立组件）
./scan aggregate /reports/ -o aggregated.json

# 使用组件映射
./scan aggregate /reports/ -m mapping.json -o aggregated.json
```

---

## export - 导出命令

### 语法

```bash
./scan export <report.json> -o <output> [options]
```

### 参数

| 参数 | 说明 |
|------|------|
| `report` | 输入 JSON 报告 |
| `-o, --output FILE` | 输出文件（.xlsx 或 .html） |
| `-f, --format` | 输出格式（自动根据扩展名检测） |

### 示例

```bash
./scan export report.json -o report.xlsx
./scan export report.json -o report.html
```

---

## 输出格式

### JSON 结构（单次扫描）

```json
{
  "meta": {
    "tool_version": "1.0.0",
    "report_type": "single",
    "scan_time": "2026-02-01T12:00:00",
    "scan_root": "/usr/bin/curl",
    "target_arch": "aarch64"
  },
  "summary": {
    "total_files_scanned": 33,
    "total_elf_files": 33,
    "files_with_openssl_deps": 4,
    "total_openssl_symbols": 881,
    "unique_openssl_symbols": 722,
    "openssl_libs_found": ["/lib/libcrypto.so.3", "/lib/libssl.so.3"]
  },
  "openssl_symbols": {
    "by_file": {
      "/lib/libcurl.so.4": {
        "count": 218,
        "symbols": ["SSL_connect", "SSL_read", "..."]
      }
    },
    "by_category": {
      "ssl_core": {"count": 54, "symbols": ["SSL_connect", "..."]},
      "crypto_evp": {"count": 172, "symbols": ["EVP_DigestInit", "..."]}
    },
    "by_depth": {
      "depth_1": {"count": 218, "symbols": ["..."], "files": ["/lib/libcurl.so.4"]},
      "depth_2": {"count": 577, "symbols": ["..."], "files": ["..."]}
    },
    "import_chains": {
      "SSL_connect": [
        {"source_file": "/lib/libcurl.so.4", "chain": "curl -> libcurl.so.4", "depth": 1}
      ]
    },
    "all_unique": ["SSL_connect", "EVP_DigestInit", "..."]
  },
  "dependency_tree": {
    "name": "curl",
    "path": "/usr/bin/curl",
    "is_openssl_lib": false,
    "openssl_symbols_count": 0,
    "children": [...]
  },
  "files_detail": [...],
  "errors": []
}
```

### JSON 结构（聚合报告）

```json
{
  "meta": {
    "tool_version": "1.0.0",
    "report_type": "aggregated",
    "aggregation_time": "2026-02-01T15:00:00",
    "source_reports_count": 18,
    "mapping_file": "mapping.json"
  },
  "summary": {
    "total_components": 6,
    "total_executables": 18,
    "global_unique_symbols": 1969
  },
  "ranking": [
    {"rank": 1, "component": "openssl-cli", "unique_symbols_count": 1565}
  ],
  "components": {
    "openssl-cli": {
      "executables": ["/usr/bin/openssl"],
      "unique_symbols_count": 1565,
      "symbols": ["..."],
      "by_category": {...},
      "executables_detail": {
        "openssl": {
          "name": "openssl",
          "path": "/usr/bin/openssl",
          "unique_symbols": ["..."],
          "by_category": {...}
        }
      }
    }
  },
  "openssl_symbols": {
    "import_chains": {
      "SSL_connect": [
        {"component": "openssh", "binary": "ssh", "chain": "ssh -> libssl.so.3", "depth": 1}
      ]
    },
    "by_depth": {
      "depth_0": {"count": 1764, "symbols": ["..."], "files": ["..."]},
      "depth_1": {"count": 495, "symbols": ["..."], "files": ["..."]}
    },
    "by_category": {...}
  }
}
```

### Excel 工作表（8 个）

| Sheet | 列 | 说明 |
|-------|-----|------|
| **Overview** | Key, Value | 元数据和统计摘要 |
| **Files** | Path, Name, Type, Arch, ... | 所有扫描文件 |
| **File-Symbol** | Component, Binary, Symbol, Category | 透视分析用 |
| **Import Chains** | Source File, File Name, Symbol, Category, Chain, Depth | 符号导入路径 |
| **By Category** | Category, Count, Percentage, Symbols | 分类统计 |
| **By Depth** | Depth, Description, Symbol Count, File Count, Symbols | 深度统计 |
| **Dep Tree** | Parent, Child, Depth, Is OpenSSL, Symbol Count, Path | 依赖树 |
| **Errors** | Severity, File, Message | 错误日志 |

### HTML 报告

自包含单文件，无需网络：

- **Summary Cards** - 关键指标卡片
- **Component Ranking** - 组件排名表（可点击查看详情）
- **Category Distribution** - SVG 条形图
- **Component Modal** - 三级展开（组件 → 二进制 → 符号分类）
- **Export Excel** - 浏览器内导出（使用嵌入的 SheetJS）

---

## 符号分类

| 类别 | 前缀 | 说明 |
|------|------|------|
| ssl_core | SSL_ | SSL/TLS 连接管理 |
| ssl_tls | TLS_, DTLS_ | TLS/DTLS 方法 |
| crypto_evp | EVP_ | 高级加密接口 |
| crypto_rsa | RSA_ | RSA 算法 |
| crypto_ec | EC_, ECDSA_, ECDH_ | 椭圆曲线 |
| crypto_aes | AES_ | AES 对称加密 |
| crypto_hash | SHA*, MD5_ | 哈希函数 |
| crypto_hmac | HMAC_ | HMAC 认证码 |
| crypto_bn | BN_ | 大数运算 |
| crypto_bio | BIO_ | I/O 抽象层 |
| crypto_x509 | X509_ | 证书处理 |
| crypto_pem | PEM_ | PEM 格式 |
| crypto_asn1 | ASN1_ | ASN.1 编解码 |
| crypto_pkcs | PKCS* | PKCS 标准 |
| crypto_rand | RAND_ | 随机数生成 |
| crypto_err | ERR_ | 错误处理 |
| crypto_engine | ENGINE_ | 硬件引擎 |
| crypto_provider | OSSL_PROVIDER_ | Provider 接口 |
| crypto_sm | SM2_, SM3_, SM4_ | 国密算法 |
| openssl_util | OPENSSL_, OSSL_ | 工具函数 |

---

## 应用场景

### 安全审计

```bash
# 扫描系统目录
./scan scan /system --scan-dir -o system.json

# 导出审计报告
./scan export system.json -o audit.xlsx
```

### CI/CD 集成

```bash
#!/bin/bash
SCANNER=/path/to/openssl-scanner
$SCANNER/scan scan "$BUILD_OUTPUT" --scan-dir --json-only -o scan.json

# 检查是否使用了废弃的 MD5
if grep -q '"MD5_' scan.json; then
    echo "ERROR: Using deprecated MD5 functions"
    exit 1
fi
```

### 版本升级分析

```bash
# 用新版 OpenSSL 符号表分析现有二进制
./scan scan /current/app \
    --openssl-lib /openssl-3.2/lib/libcrypto.so \
    -o upgrade_impact.json
```

---

## 常见问题

**Q: 什么时候需要 --openssl-lib?**

通常不需要，工具会自动检测。需要手动指定的场景：
- 交叉分析（不同环境的二进制和 OpenSSL）
- 自动检测失败时
- 测试特定 OpenSSL 版本的兼容性

**Q: by_depth 中的深度含义?**

```
depth 0: 目标直接引用的 OpenSSL 符号
depth 1: 一级依赖（直接库）引用的符号
depth 2: 二级依赖引用的符号
...
```

**Q: Tree Scan 和 Directory Scan 的区别?**

| | Tree Scan | Directory Scan |
|--|-----------|----------------|
| 触发 | 目标是文件 | `--scan-dir` |
| 分析方式 | 递归依赖树 | 遍历所有 ELF |
| dependency_tree | ✓ 完整树结构 | ✗ 无 |
| by_depth | 多层（0,1,2...） | 通常只有 depth_1 |
| import_chains | 完整路径 | 文件到 OpenSSL 的直接路径 |

**Q: HTML 报告需要网络吗?**

不需要。完全自包含，所有 JS/CSS/图表库都已嵌入。

---

## 退出码

| 码 | 含义 |
|---|------|
| 0 | 成功 |
| 1 | 失败 |
| 130 | 用户中断 (Ctrl+C) |
