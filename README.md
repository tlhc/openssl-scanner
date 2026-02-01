# OpenSSL Symbol Dependency Scanner

分析 ELF 二进制的 OpenSSL API 依赖关系。

## 功能

- **扫描** - 分析 ELF 文件的 OpenSSL 符号依赖
- **聚合** - 合并多个扫描报告，按组件统计
- **导出** - 生成 Excel（8 个工作表）和交互式 HTML 报告
- **严格匹配** - 从 OpenSSL 库提取导出符号，100% 精确匹配

## 快速开始（免安装）

所有依赖已内置，仅需 Python 3.8+，克隆后直接运行：

```bash
git clone https://github.com/anthropics/openssl-scanner.git
cd openssl-scanner

# 扫描单个二进制
./scan scan /path/to/binary -o report.json

# 扫描目录
./scan scan /path/to/dir --scan-dir -o report.json

# 聚合多个报告
./scan aggregate /path/to/reports/ -o aggregated.json

# 导出 HTML
./scan export report.json -o report.html

# 导出 Excel
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

## 扫描模式

| 模式 | 命令 | 特点 |
|------|------|------|
| **Tree Scan** | `./scan scan /path/to/binary` | 递归分析依赖树，生成完整依赖图 |
| **Directory Scan** | `./scan scan /path/to/dir --scan-dir` | 扫描目录内所有 ELF，计算 import chains |

## 输出格式

### Excel 工作表（8 个）

| Sheet | 内容 |
|-------|------|
| Overview | 元数据、扫描摘要 |
| Files | 所有扫描文件的详细信息 |
| File-Symbol | 文件-符号关联表（透视分析用） |
| Import Chains | 符号导入路径（含源文件、深度） |
| By Category | 按 API 类别统计 |
| By Depth | 按依赖深度统计（含文件分布） |
| Dep Tree | 依赖树结构（仅 Tree Scan） |
| Errors | 扫描错误和警告 |

### HTML 报告

- 完全自包含（离线可用）
- 交互式组件排名表
- API 类别分布图表
- 组件详情弹窗（支持三级展开：组件→二进制→符号）
- 浏览器内 Excel 导出

## 符号分类

| 类别 | 前缀 | 说明 |
|------|------|------|
| ssl_core | SSL_ | SSL/TLS 核心功能 |
| crypto_evp | EVP_ | 高级加密接口 |
| crypto_x509 | X509_ | 证书处理 |
| crypto_ec | EC_, ECDSA_ | 椭圆曲线 |
| crypto_hash | SHA*, MD5_ | 哈希函数 |
| crypto_sm | SM2_, SM3_, SM4_ | 国密算法 |

完整分类见 [CLI 文档](docs/cli.md)。

## 可选：pip 安装

如需全局安装 `openssl-scanner` 命令：

```bash
pip install -e .
openssl-scanner scan /path/to/binary -o report.json
```

## 文档

- [CLI 完整文档](docs/cli.md) - 命令参数、输出格式、使用示例

## 许可证

Apache-2.0
