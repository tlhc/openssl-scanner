# OpenSSL Symbol Dependency Scanner

OpenHarmony 系统的 OpenSSL 符号依赖扫描工具。

## 功能

- **扫描** - 分析 ELF 可执行文件和共享库的 OpenSSL 依赖
- **聚合** - 合并多个扫描报告，按组件统计
- **导出** - 生成交互式 HTML 报告和 Excel 工作簿
- **严格匹配** - 从 OpenSSL 库提取导出符号，100% 精确匹配

## 安装

```bash
# 基础安装
pip install -e .

# 包含 Excel 导出支持
pip install -e ".[export]"

# 包含开发依赖
pip install -e ".[dev]"
```

## 快速开始

```bash
# 扫描单个二进制（自动检测 OpenSSL 库）
openssl-scanner scan /system/bin/my_app -o report.json

# 扫描整个目录
openssl-scanner scan /system/lib64 --scan-dir -o scan.json

# 聚合多个报告
openssl-scanner aggregate /reports/ -o aggregated.json

# 导出为 HTML（交互式报告）
openssl-scanner export aggregated.json -o report.html

# 导出为 Excel（多工作表）
openssl-scanner export aggregated.json -o report.xlsx
```

## 命令概览

| 命令 | 说明 |
|------|------|
| `scan` | 扫描二进制或目录，生成 JSON 报告 |
| `aggregate` | 合并多个扫描报告，按组件分组统计 |
| `export` | 将 JSON 报告转换为 HTML 或 Excel |

> 直接运行 `openssl-scanner <target>` 等同于 `openssl-scanner scan <target>`

## 工作原理

```
+-------------------+     +-------------------+     +------------------+
| libcrypto.so      |     | Target Binary     |     | Match Result     |
| (Reference)       |     | (Scan Target)     |     |                  |
+--------+----------+     +--------+----------+     +--------+---------+
         |                         |                         ^
         v                         v                         |
+--------+----------+     +--------+----------+              |
| Extract defined   |     | Extract undefined |              |
| symbols (exports) |     | symbols (imports) |              |
+--------+----------+     +--------+----------+              |
         |                         |                         |
         +------------+------------+                         |
                      |                                      |
                      v                                      |
              +-------+-------+                              |
              | Set           |                              |
              | Intersection  +------------------------------+
              +---------------+

              exports(libcrypto) ∩ imports(target) = OpenSSL dependencies
```

## 输出格式

| 格式 | 用途 |
|------|------|
| **JSON** | 机器可读，CI/CD 集成，程序化分析 |
| **HTML** | 交互式可视化，组件排名，分类图表，浏览器内 Excel 导出 |
| **Excel** | 多工作表（Overview, Ranking, Category Pivot, Symbols, By File, By Component） |

## 符号分类

| 类别 | 前缀 | 说明 |
|------|------|------|
| ssl_core | SSL_ | SSL/TLS 核心功能 |
| ssl_tls | TLS_, DTLS_ | TLS/DTLS 方法 |
| crypto_evp | EVP_ | 高级加密接口 |
| crypto_rsa | RSA_ | RSA 算法 |
| crypto_ec | EC_, ECDSA_, ECDH_ | 椭圆曲线 |
| crypto_hash | SHA*, MD5_ | 哈希函数 |
| crypto_x509 | X509_ | X.509 证书 |
| crypto_sm | SM2_, SM3_, SM4_ | 国密算法 |

## 文档

- [CLI 完整使用文档](docs/cli.md) - 命令行参数、输出格式、场景示例

## 开发

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest -v

# 类型检查
mypy src/openssl_scanner

# 代码检查
ruff check src/openssl_scanner
```

## 许可证

Apache-2.0
