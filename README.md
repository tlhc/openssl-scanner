# OpenSSL Symbol Dependency Scanner

分析 ELF 二进制和源代码的 OpenSSL API 依赖关系。

## 功能

- **ELF 扫描** - 分析 ELF 文件的 OpenSSL 符号依赖（从 .dynsym 提取）
- **源码扫描** - 基于 tree-sitter AST 分析 C/C++/Rust 源码中的 OpenSSL API 调用点
- **进程扫描** - 分析运行中进程加载的共享库（Linux）
- **包扫描** - 分析 OpenHarmony HAP/HAR/HSP/APP/ZIP 包内的 OpenSSL 依赖
- **组合扫描** - 一键完成探测、扫描、合并流水线（probe + scan + merge）
- **差异比较** - 比较两次源码扫描报告，追踪 OpenSSL API 调用变更
- **聚合** - 合并多个扫描报告，按组件统计
- **导出** - 生成 Excel（8 个工作表）和交互式 HTML 报告
- **严格匹配** - 从 OpenSSL 库/头文件提取符号和宏，100% 精确匹配

## 快速开始

核心依赖已内置（pyelftools、openpyxl），仅需 Python 3.8+，克隆后直接运行：

```bash
git clone https://github.com/anthropics/openssl-scanner.git
cd openssl-scanner

# 扫描单个二进制
./scan scan /path/to/binary -o report.json

# 扫描目录
./scan scan /path/to/dir --scan-dir -o report.json

# 扫描 OpenHarmony 应用包（支持 HAP/HAR/HSP/APP/ZIP）
./scan hap MyApp.hap -o report.xlsx

# 扫描 ZIP 包（自动处理嵌套 HAP/ZIP）
./scan hap MyBundle.zip -o report.xlsx

# 批量扫描目录（逐包独立报告）
./scan hap /path/to/packages/ -o /tmp/reports/

# 增量扫描（跳过已有报告的包，--force 强制重扫）
./scan hap /path/to/packages/ -o /tmp/reports/ --force

# 从已有报告生成汇总（无需重新扫描）
./scan hap-summary /tmp/reports/ -o summary.xlsx

# 扫描源代码（tree-sitter）
./scan source /path/to/src -o report.xlsx

# 聚合多个报告
./scan aggregate /path/to/reports/ -o aggregated.json

# 导出 HTML / Excel
./scan export report.json -o report.html
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

## 命令概览

| 命令 | 功能 | 输入 | 输出 |
|------|------|------|------|
| `scan` | ELF 二进制符号分析 | ELF 文件/目录 | JSON/HTML/Excel |
| `source` | 源码 API 调用点分析 | C/C++/Rust 源文件/目录 | XLSX/JSON |
| `source-probe` | 快速探测目录中的 OpenSSL 使用 | 根目录 | 项目列表 |
| `source-merge` | 合并多个源码扫描报告 | 多个 XLSX | 合并 XLSX |
| `combo-scan` | 一键探测+扫描+合并 | 根目录 | 合并 XLSX/JSON |
| `source-diff` | 比较两次源码扫描报告 | 两个 JSON 报告 | 控制台/JSON/XLSX |
| `proc` | 运行中进程分析 | PID 或进程名 | JSON |
| `hap` | OpenHarmony 包分析 | HAP/HAR/HSP/APP/ZIP | XLSX/HTML/JSON |
| `hap-summary` | 从已有报告生成汇总 | JSON 报告目录/文件 | XLSX |
| `update-data` | 更新内置符号数据 | libcrypto.so / 头文件目录 | data/*.json |
| `aggregate` | 聚合多个报告 | JSON 报告目录 | JSON |
| `export` | 导出为 HTML/Excel | JSON 报告 | HTML/XLSX |

## 扫描模式

| 模式 | 命令 | 特点 |
|------|------|------|
| **Tree Scan** | `./scan scan /path/to/binary` | 递归分析依赖树，生成完整依赖图 |
| **Directory Scan** | `./scan scan /path/to/dir --scan-dir` | 扫描目录内所有 ELF，计算 import chains |
| **Source Scan** | `./scan source /path/to/src -o r.xlsx` | AST 分析源码，提取每个 OpenSSL 调用的位置和参数 |
| **Combo Scan** | `./scan combo-scan /root -o r.xlsx` | 一键完成 probe+scan+merge 流水线 |
| **Source Diff** | `./scan source-diff old.json new.json` | 比较两次扫描结果，追踪 API 变更 |
| **Process Scan** | `./scan proc --pid 1234` | 分析运行进程的已加载库 |
| **Package Scan** | `./scan hap MyApp.hap` | 从 HAP/HAR/HSP/APP/ZIP 包提取并分析 native .so |
| **Package Summary** | `./scan hap-summary /reports/` | 从已有 JSON 报告生成汇总 XLSX（含 OpenSSL Usage 分类） |

## 源码扫描

基于 tree-sitter AST 精确解析，零误报。支持 C、C++、Rust。

```bash
# 扫描目录，输出 Excel 报告
./scan source /path/to/project/src -o report.xlsx

# 扫描单个文件，输出 JSON
./scan source /path/to/openssl_client.c -o report.json

# 控制并行度
./scan source /path/to/src -o report.xlsx -j 4

# 多项目扫描（每个项目生成独立报告）
./scan source /path/to/nginx /path/to/curl -o /tmp/reports/

# 合并多个报告（含跨项目 Symbol Summary）
./scan source-merge /tmp/reports/*.xlsx -o combined.xlsx

# 比较两次扫描报告的差异
./scan source-diff old_report.json new_report.json
./scan source-diff old.json new.json -o diff.xlsx
```

### `-o` 自动识别

`-o` 根据路径自动选择输出模式 — 有扩展名(.xlsx/.json)为文件模式，无扩展名或已存在目录为目录模式：

```bash
# 文件模式 - 输出单个文件
./scan source /path/to/src -o report.xlsx    # -> report.xlsx + report.json
./scan source /path/to/src -o report.json    # -> report.json

# 目录模式 - 输出到目录（以目标名命名）
./scan source /path/to/src -o /tmp/results   # -> /tmp/results/src.xlsx + src.json

# 多目标 + 目录模式 - 逐项目报告 + 合并
./scan source /path/to/nginx /path/to/curl -o /tmp/reports
#   -> /tmp/reports/nginx.xlsx  + nginx.json
#   -> /tmp/reports/curl.xlsx   + curl.json
#   -> /tmp/reports/merged.xlsx
```

### 输出示例

XLSX 单工作表，含自动筛选：

| File Path | File Name | Caller Function | Line | OpenSSL Symbol | Category | Call Arguments |
|-----------|-----------|-----------------|------|----------------|----------|----------------|
| /src/tls.c | tls.c | init_tls | 42 | SSL_CTX_new | ssl_core | (TLS_client_method()) |
| /src/tls.c | tls.c | init_tls | 42 | TLS_client_method | ssl_tls | () |
| /src/hash.c | hash.c | do_hash | 15 | EVP_DigestInit_ex | crypto_evp | (mdctx, EVP_sha256(), NULL) |

## 组合扫描（combo-scan）

`combo-scan` 是一种**组合模式**，将 `source-probe`、`source`、`source-merge` 三个独立命令串联为自动化流水线。用户也可以手动分步执行以获得更细粒度的控制：

```bash
# 手动三步（各命令可独立使用、调参、重试）
./scan source-probe /root > targets.txt                     # 探测
./scan source /project_a -o a.xlsx                          # 逐项目扫描
./scan source /project_b -o b.xlsx
./scan source-merge a.xlsx b.xlsx -o merged.xlsx            # 合并

# combo-scan 一键完成（等价于上述三步）
./scan combo-scan /root -o merged.xlsx
```

### 参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `root` | 根目录（必需） | - |
| `-o, --output PATH` | 文件路径(.xlsx/.json)仅输出合并结果；目录路径则输出全部结果 | - |
| `-j, --jobs` | 每项目并行工作数 | CPU 核心数 |
| `--exclude NAME` | 排除匹配的项目目录（子串匹配） | - |
| `--json-only` | 输出合并 JSON 而非 XLSX | - |
| `--no-recursive` | 不递归子目录 | - |

### 使用示例

```bash
# 扫描所有项目，排除大型项目
./scan combo-scan /path/to/opensource -o report.xlsx --exclude chromium aspect

# JSON 输出（无需 openpyxl 依赖）
./scan combo-scan /path/to/opensource -o report.json --json-only
```

### `-o` 自动识别

与 `source` 命令相同，`-o` 根据路径特征自动选择输出模式：

```bash
# 文件模式 - 仅输出合并结果
./scan combo-scan /opensource -o report.xlsx        # -> report.xlsx (N+2 sheets)
./scan combo-scan /opensource -o report.json --json-only  # -> report.json

# 目录模式 - 输出全部结果（合并 + 每项目 XLSX + JSON）
./scan combo-scan /opensource -o /tmp/scan_results
#   -> /tmp/scan_results/
#        merged.xlsx              合并工作簿 (Summary + 各项目 + Symbol Summary)
#        curl.xlsx                每项目 XLSX (Call Sites + Symbol Summary)
#        curl.json                每项目 JSON
#        nginx_src.xlsx
#        nginx_src.json
#        ...

# 目录模式 + --json-only（不生成 XLSX）
./scan combo-scan /opensource -o /tmp/scan_results --json-only
#   -> /tmp/scan_results/
#        merged.json              合并 JSON
#        curl.json                每项目 JSON
#        nginx_src.json
#        ...
```

### 执行流程

各阶段对应的独立命令：

```bash
./scan source-probe /root > targets.txt            # Phase 1: 探测
./scan source <project> -o <report> ...            # Phase 2: 逐项目扫描
./scan source-merge reports/*.xlsx -o merged.xlsx  # Phase 3: 合并
```

```
Phase 1: 探测 (source-probe)
  输入: root 目录
  任务: ripgrep Aho-Corasick 多模式搜索 -> 叶子目录合并为项目根目录
  产出: 项目目录列表

Phase 2: 扫描 (source)
  输入: 项目目录列表
  任务: 逐项目启动独立子进程, 进程隔离避免内存碎片 OOM
        各项目内部 ProcessPoolExecutor 并行 tree-sitter 解析
        超时 600 秒/项目
  产出: 每项目 JSON + XLSX (-o 目录模式)

Phase 3: 合并 (source-merge)
  输入: 所有项目 JSON 报告
  任务: 跨项目合并 + 符号去重统计
  产出: merged.xlsx (或 merged.json)
```

### 符号覆盖

源码扫描使用内置的 **9544 个 OpenSSL 标识符**（ELF 导出符号 + 头文件宏）：

| 数据集 | 数量 | 来源 | 示例 |
|--------|------|------|------|
| ELF 导出符号 | 6248 | libcrypto.so + libssl.so | SSL_CTX_ctrl, EVP_DigestInit_ex |
| 头文件宏 | 3298 | include/openssl/*.h | SSL_CTX_set_mode, OPENSSL_free, sk_X509_num |

宏在编译时展开，不出现在 ELF 符号表中，但在源码中是真实的 API 调用点。

## 更新内置符号数据

```bash
# 同时更新符号（从 .so）和宏（从头文件）
./scan update-data \
    --openssl-lib /path/to/libcrypto.so \
    --header-dir /path/to/openssl/include/openssl \
    --ossl-version 3.0.9

# 仅更新符号
./scan update-data --openssl-lib /path/to/libcrypto.so

# 仅更新宏
./scan update-data --header-dir /usr/include/openssl
```

## 输出格式

### ELF 扫描 - Excel 工作表（8 个）

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

### ELF 扫描 - HTML 报告

- 完全自包含（离线可用）
- 交互式组件排名表
- API 类别分布图表
- 组件详情弹窗（支持三级展开：组件→二进制→符号）
- 浏览器内 Excel 导出

### 源码扫描 - XLSX / JSON

- XLSX: Call Sites 工作表（自动筛选）+ Symbol Summary 工作表（去重符号统计）
- JSON: 结构化报告，含 meta/summary/call_sites/errors
- Merge XLSX: Summary + 每项目工作表 + Symbol Summary（含 Projects/Project List 列，标记各符号被哪些组件使用）
- Diff: 控制台摘要 / JSON 结构化差异 / XLSX 多工作表差异报告

## 符号分类

| 类别 | 前缀 | 说明 |
|------|------|------|
| ssl_core | SSL_ | SSL/TLS 核心功能 |
| crypto_evp | EVP_ | 高级加密接口 |
| crypto_x509 | X509_ | 证书处理 |
| crypto_ec | EC_, ECDSA_ | 椭圆曲线 |
| crypto_hash | SHA*, MD5_ | 哈希函数 |
| crypto_sm | SM2_, SM3_, SM4_ | 国密算法 |

完整分类和 combo-scan 详细参数见 [CLI 文档](docs/cli.md)。

## 可选：pip 安装

```bash
# 基础安装（ELF 扫描、包扫描、聚合、导出）
pip install -e .

# 源码扫描支持
pip install -e ".[source]"

# 全部开发依赖
pip install -e ".[dev]"
```

## 内置依赖

| 依赖 | 用途 | 位置 |
|------|------|------|
| pyelftools | ELF 解析 | _vendor/elftools |
| openpyxl | Excel 导出 | _vendor/openpyxl |
| et_xmlfile | openpyxl 依赖 | _vendor/et_xmlfile |

源码扫描依赖（已内置，`./scan source` 免安装可用；`pip install -e ".[source]"` 作为备选安装方式）：

| 依赖 | 用途 | 位置 |
|------|------|------|
| tree-sitter | AST 解析 | _vendor/tree_sitter |
| tree-sitter-c | C 语法 | _vendor/ |
| tree-sitter-cpp | C++ 语法 | _vendor/ |
| tree-sitter-rust | Rust 语法 | _vendor/ |

## 文档

- [CLI 完整文档](docs/cli.md) - 命令参数、输出格式、使用示例

## 许可证

Apache-2.0
