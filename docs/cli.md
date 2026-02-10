# OpenSSL Scanner CLI 文档

## 快速开始（免安装）

所有依赖已内置，仅需 Python 3.8+，克隆后直接运行：

```bash
git clone https://github.com/anthropics/openssl-scanner.git
cd openssl-scanner

# 扫描 ELF 二进制
./scan scan /path/to/binary -o report.json

# 扫描 OpenHarmony 应用包
./scan hap MyApp.hap -o report.json

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
  scan          扫描 ELF 二进制或目录
  source        扫描 C/C++/Rust 源码中的 OpenSSL API 调用点
  source-probe  快速探测目录中的 OpenSSL 使用（ripgrep Aho-Corasick）
  source-merge  合并多个源码扫描 XLSX 报告
  combo-scan    一键完成探测+扫描+合并流水线
  proc          扫描运行中进程加载的 OpenSSL 依赖（Linux）
  hap           扫描 OpenHarmony 应用包（HAP/HAR/HSP/APP）
  update-data   更新内置 OpenSSL 符号和宏数据
  aggregate     聚合多个扫描报告
  export        导出为 HTML 或 Excel

开发者命令（一般用户无需使用）：
  vendor-rg              内置 ripgrep 二进制
  vendor-tree-sitter     内置 tree-sitter 解析器
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
| `--sysroot PATH` | 根文件系统路径（自动发现所有库目录） |
| `-j, --jobs N` | 并行线程数（默认: CPU 核心数） |
| `--scan-dir` | 目录扫描模式 |
| `--no-recursive` | 不递归子目录 |
| `--json-only` | 仅输出 JSON |
| `-v, --verbose` | 详细日志 |
| `--log-file FILE` | 日志写入文件 |

### 示例

```bash
# 单二进制扫描（Tree Scan，自动检测 OpenSSL）
./scan scan /usr/bin/curl -o curl.json

# 目录扫描（Directory Scan）
./scan scan /usr/bin --scan-dir -j 8 -o usrbin.json

# 手动指定 OpenSSL 库路径（跳过自动检测）
./scan scan /path/to/app \
    --openssl-lib /lib/libcrypto.so.3 \
    --openssl-ssl /lib/libssl.so.3 \
    -o report.json

# 仅指定 libcrypto（不分析 SSL 符号）
./scan scan /path/to/app \
    --openssl-lib /opt/openssl-3.2/lib/libcrypto.so \
    -o report.json

# 交叉分析：用新版 OpenSSL 符号表分析旧二进制
./scan scan /old/system/bin/app \
    --openssl-lib /new/openssl-3.2/lib/libcrypto.so.3 \
    --openssl-ssl /new/openssl-3.2/lib/libssl.so.3 \
    -L /old/system/lib \
    -o upgrade_check.json

# 分析 OpenHarmony 镜像（自动发现所有库目录）
./scan scan /mnt/openharmony/system/bin/app \
    --sysroot /mnt/openharmony \
    -o report.json
```

### 跨系统分析（--sysroot）

分析来自其他系统的二进制时，使用 `--sysroot` 自动发现库目录：

```bash
# 挂载 OpenHarmony 镜像
mount -o loop system.img /mnt/oh

# 扫描镜像中的二进制（自动发现 /mnt/oh 下所有库目录）
./scan scan /mnt/oh/system/bin/curl --sysroot /mnt/oh -o curl.json

# 扫描整个 system 目录
./scan scan /mnt/oh/system --scan-dir --sysroot /mnt/oh -o system.json
```

`--sysroot` 会递归扫描指定目录，自动将所有包含 `.so` 文件的目录加入库搜索路径。

| 场景 | 命令 |
|------|------|
| 分析 rootfs 镜像 | `--sysroot /mnt/rootfs` |
| 分析 SDK 环境 | `--sysroot /opt/sdk/sysroot` |
| 分析容器导出 | `--sysroot /tmp/container-export` |

### 手动指定 OpenSSL 库

默认情况下，工具会自动从目标的依赖树中检测 OpenSSL 库。以下场景需要手动指定：

| 场景 | 说明 |
|------|------|
| **交叉分析** | 用不同版本的 OpenSSL 符号表分析二进制 |
| **自动检测失败** | 目标未直接依赖 OpenSSL（通过插件加载等） |
| **版本升级评估** | 用新版 OpenSSL 检查兼容性 |
| **离线分析** | 分析来自其他系统的二进制 |

```bash
# 示例：检查应用是否兼容 OpenSSL 3.2
./scan scan /current/bin/myapp \
    --openssl-lib /opt/openssl-3.2/lib/libcrypto.so.3 \
    --openssl-ssl /opt/openssl-3.2/lib/libssl.so.3 \
    -o openssl32_compat.json
```

### 两种扫描模式

| 模式 | 触发方式 | 特点 |
|------|----------|------|
| **Tree Scan** | 目标是文件 | 递归分析依赖树，生成 `dependency_tree`，多层 `by_depth` |
| **Directory Scan** | `--scan-dir` | 扫描所有 ELF，使用 `DependencyGraph` 计算 import chains |

---

## source - 源码扫描命令

基于 tree-sitter AST 分析 C/C++/Rust 源码中的 OpenSSL API 调用点。使用内置的预置符号数据（ELF 导出符号 + 头文件宏，共 9544 个标识符）。

### 语法

```bash
./scan source <target> [options]
```

### 参数

| 参数 | 说明 |
|------|------|
| `target` | 源文件或目录（可多个） |
| `-f, --from-file FILE` | 从文件读取目标路径列表（每行一个路径） |
| `-o, --output FILE` | 输出文件（.xlsx 或 .json，必需） |
| `-j, --jobs N` | 并行工作数（默认: CPU 核心数） |
| `--no-recursive` | 不递归子目录 |
| `--json-only` | 仅输出 JSON，不打印控制台摘要 |
| `-v, --verbose` | 详细日志 |
| `--log-file FILE` | 日志写入文件 |

### 支持的语言

| 扩展名 | 语言 | 解析器 |
|--------|------|--------|
| `.c`, `.h` | C | tree-sitter-c |
| `.cpp`, `.hpp`, `.cc`, `.cxx`, `.hxx` | C++ | tree-sitter-cpp |
| `.rs` | Rust | tree-sitter-rust |

### 示例

```bash
# 扫描整个项目源目录
./scan source /path/to/project/src -o report.xlsx

# 扫描单个文件
./scan source /path/to/openssl_client.c -o report.xlsx

# JSON 输出
./scan source /path/to/src -o report.json

# 控制并行度
./scan source /path/to/src -o report.xlsx -j 4

# 不递归
./scan source /path/to/src -o report.xlsx --no-recursive

# 详细日志输出
./scan source /path/to/src -o report.xlsx -v --log-file scan.log
```

### `-o` 输出路径自动识别

`-o` 根据路径特征自动选择输出模式：

| 路径形式 | 识别规则 | 输出行为 |
|----------|----------|----------|
| `report.xlsx` | 有 `.xlsx` 扩展名 | 文件模式：仅输出该文件 |
| `report.json` | 有 `.json` 扩展名 | 文件模式：仅输出 JSON |
| `/tmp/results` | 无扩展名 | 目录模式：自动创建目录，输出到其中 |
| `/tmp/existing_dir/` | 已存在目录 | 目录模式：输出到该目录 |

#### 单目标扫描

```bash
# 文件模式 - 输出 XLSX（自动附带同名 .json）
./scan source /path/to/src -o report.xlsx
#   -> report.xlsx        (Call Sites + Symbol Summary)
#   -> report.json        (自动生成的伴生 JSON)

# 文件模式 - 仅输出 JSON
./scan source /path/to/src -o report.json
#   -> report.json

# 文件模式 - JSON only（--json-only 抑制控制台摘要）
./scan source /path/to/src -o report.json --json-only
#   -> report.json

# 目录模式 - 无扩展名路径自动创建目录
./scan source /path/to/src -o /tmp/results
#   -> /tmp/results/src.xlsx    (以目标目录名命名)
#   -> /tmp/results/src.json

# 目录模式 + --json-only
./scan source /path/to/src -o /tmp/results --json-only
#   -> /tmp/results/src.json
```

#### 多目标扫描

```bash
# 多目录 -> 文件模式：生成合并 XLSX
./scan source /path/to/nginx /path/to/curl -o merged.xlsx
#   -> merged.xlsx        (Summary + nginx + curl + Symbol Summary)

# 多目录 -> 目录模式：逐项目报告 + 合并报告
./scan source /path/to/nginx /path/to/curl -o /tmp/reports
#   -> /tmp/reports/nginx.xlsx
#   -> /tmp/reports/nginx.json
#   -> /tmp/reports/curl.xlsx
#   -> /tmp/reports/curl.json
#   -> /tmp/reports/merged.xlsx
```

### XLSX 输出格式

两个工作表：

**"OpenSSL Call Sites"** - 完整调用点列表，含自动筛选，按 (File Path, Line) 排序：

| 列 | 说明 | 示例 |
|----|------|------|
| File Path | 文件绝对路径 | /src/tls.c |
| File Name | 文件名 | tls.c |
| Caller Function | 调用所在函数 | init_tls |
| Line | 行号 | 42 |
| OpenSSL Symbol | API 名称 | SSL_CTX_new |
| Category | 功能分类 | ssl_core |
| Call Arguments | 调用参数 | (TLS_client_method()) |

**"Symbol Summary"** - 去重后的符号统计，每个符号一行：

| 列 | 说明 | 示例 |
|----|------|------|
| OpenSSL Symbol | API 名称 | SSL_CTX_new |
| Category | 功能分类 | ssl_core |
| Calls | 调用次数 | 3 |
| Files | 使用文件数 | 2 |
| File List | 使用文件列表 | tls.c, ssl_lib.c |

### JSON 输出格式

```json
{
  "meta": {
    "tool_version": "1.0.0",
    "report_type": "source_scan",
    "scan_time": "2026-02-10T09:52:16",
    "target": "/path/to/src"
  },
  "summary": {
    "total_files_scanned": 344,
    "files_with_calls": 12,
    "total_call_sites": 637,
    "unique_symbols_count": 328,
    "unique_symbols": ["SSL_CTX_new", "EVP_DigestInit_ex", "..."],
    "symbols_by_category": {
      "ssl_core": ["SSL_CTX_new", "SSL_connect", "..."],
      "crypto_evp": ["EVP_DigestInit_ex", "EVP_sha256", "..."]
    }
  },
  "call_sites": [
    {
      "file_path": "/path/to/openssl.c",
      "file_name": "openssl.c",
      "caller_function": "init_tls",
      "line_number": 42,
      "column": 4,
      "ossl_symbol": "SSL_CTX_new",
      "category": "ssl_core",
      "call_args": "(TLS_client_method())",
      "language": "c"
    }
  ],
  "errors": []
}
```

### 符号覆盖说明

源码扫描使用两个内置数据集的并集：

| 数据集 | 数量 | 来源 | 说明 |
|--------|------|------|------|
| ELF 导出 | 6248 | data/openssl_symbols.json | 编译后的真实函数 |
| 头文件宏 | 3298 | data/openssl_macros.json | 编译时展开的宏和内联函数 |
| **合计** | **9544** | 并集（2 个重叠） | |

宏在编译时展开为底层函数调用（如 `SSL_CTX_set_mode` -> `SSL_CTX_ctrl`），不出现在 ELF 符号表中，但在源码中是真实的 API 调用点。以 curl 为例，289 个唯一 OpenSSL 符号中有 51 个（18%）是宏。

> 使用 `update-data` 命令可针对不同 OpenSSL 版本更新内置数据。

---

## source-merge - 报告合并命令

合并多个源码扫描 XLSX 报告为一个多工作表工作簿，便于跨项目对比分析。

### 语法

```bash
./scan source-merge <input1.xlsx> [input2.xlsx ...] -o <output.xlsx>
```

### 参数

| 参数 | 说明 |
|------|------|
| `inputs` | 源码扫描 XLSX 报告文件（一个或多个） |
| `-o, --output FILE` | 输出合并 XLSX 文件（必需） |
| `-v, --verbose` | 详细日志 |
| `--log-file FILE` | 日志写入文件 |

### 示例

```bash
# 合并指定文件
./scan source-merge nginx.xlsx curl.xlsx wolfssl.xlsx -o combined.xlsx

# 合并目录下所有报告（Shell 通配符展开）
./scan source-merge /tmp/reports/*.xlsx -o combined.xlsx
```

### 输出工作簿结构

| 工作表 | 内容 |
|--------|------|
| **Summary** | 每项目统计（文件数、调用点、唯一符号、Top 分类）+ TOTAL 行 |
| **\<项目名\>** | 每个项目的完整调用点数据（与单项目报告格式相同） |
| **Symbol Summary** | 跨项目去重后的符号统计 |

**Symbol Summary 列：**

| 列 | 说明 | 示例 |
|----|------|------|
| OpenSSL Symbol | API 名称 | SSL_CTX_new |
| Category | 功能分类 | ssl_core |
| Calls | 跨项目总调用次数 | 191 |
| Files | 跨项目去重文件数 | 61 |
| File List | 去重后的文件名列表 | ngx_event_openssl.c, openssl.c, ... |
| Projects | 使用该符号的项目数 | 3 |
| Project List | 项目名称列表 | curl, spdm-emu, wolfssl |

> Symbol Summary 中的 Projects/Project List 列仅在 merge 报告中出现，单项目 XLSX 的 Symbol Summary 不包含这两列。

---

## combo-scan - 组合扫描命令

`combo-scan` 是一种**组合模式**，将三个独立命令（`source-probe` + `source` + `source-merge`）串联为自动化流水线。用户也可以手动分步执行以获得更细粒度的控制：

```bash
# 手动三步（各命令可独立使用、调参、重试）
./scan source-probe /root > targets.txt                     # 探测
./scan source /project_a -o a.xlsx                          # 逐项目扫描
./scan source /project_b -o b.xlsx
./scan source-merge a.xlsx b.xlsx -o merged.xlsx            # 合并

# combo-scan 一键完成（等价于上述三步）
./scan combo-scan /root -o merged.xlsx
```

### 语法

```bash
./scan combo-scan <root> -o <output> [options]
```

`-o` 自动识别：有扩展名(.xlsx/.json)视为文件，仅输出合并结果；无扩展名或已存在目录视为目录，输出全部结果。

### 参数

| 参数 | 说明 |
|------|------|
| `root` | 根目录（必需） |
| `-o, --output PATH` | 输出路径：文件(.xlsx/.json)仅合并结果，目录则含全部结果(合并+每项目 XLSX+JSON) |
| `-j, --jobs N` | 每项目并行工作数（默认: CPU 核心数） |
| `--no-recursive` | 扫描项目时不递归子目录 |
| `--exclude NAME [NAME ...]` | 排除匹配的项目目录，子串匹配 |
| `--json-only` | 输出合并 JSON 而非 XLSX，抑制控制台摘要 |
| `-v, --verbose` | 详细日志 |
| `--log-file FILE` | 日志写入文件 |

### 示例

```bash
# 扫描所有项目，输出合并 XLSX
./scan combo-scan /path/to/opensource -o report.xlsx

# 排除大型项目（子串匹配目录名）
./scan combo-scan /path/to/opensource -o report.xlsx --exclude chromium aspect

# 全部输出到指定目录（合并结果 + 各项目报告）
./scan combo-scan /path/to/opensource -o /tmp/scan_results/

# JSON 输出（无需 openpyxl 依赖）
./scan combo-scan /path/to/opensource -o report.json --json-only

# 详细日志 + 日志文件
./scan combo-scan /path/to/opensource -o report.xlsx -v --log-file scan.log

# 限制每项目并行度
./scan combo-scan /path/to/opensource -o report.xlsx -j 4
```

### `-o` 输出路径详解

`-o` 根据路径特征自动选择输出模式：

| 路径形式 | 识别规则 | 输出行为 |
|----------|----------|----------|
| `report.xlsx` | 有 `.xlsx` 扩展名 | 文件模式：仅输出合并 XLSX |
| `report.json` | 有 `.json` 扩展名（需 `--json-only`） | 文件模式：仅输出合并 JSON |
| `/tmp/results` | 无扩展名 | 目录模式：合并结果 + 每项目 XLSX + JSON |
| `/tmp/existing_dir/` | 已存在目录 | 目录模式：同上 |

#### 文件模式（仅合并结果）

```bash
# XLSX 文件模式 - 仅输出合并工作簿
./scan combo-scan /path/to/opensource -o report.xlsx
#   -> report.xlsx
#      Sheets: [Summary, project_a, project_b, ..., Symbol Summary]

# JSON 文件模式 - 仅输出合并 JSON
./scan combo-scan /path/to/opensource -o report.json --json-only
#   -> report.json
#      { "projects": [...], "total_projects": N, "total_symbols": M }
```

#### 目录模式（全部结果）

```bash
# 无扩展名路径 - 自动创建目录，输出全部结果
./scan combo-scan /path/to/opensource -o /tmp/scan_results
#   -> /tmp/scan_results/
#        merged.xlsx                      合并工作簿
#        curl.xlsx                        每项目 XLSX
#        curl.json                        每项目 JSON
#        nginx_src.xlsx
#        nginx_src.json
#        libwebsockets.xlsx
#        libwebsockets.json
#        ...

# 目录模式 + --json-only（不生成 XLSX）
./scan combo-scan /path/to/opensource -o /tmp/scan_results --json-only
#   -> /tmp/scan_results/
#        merged.json                      合并 JSON
#        curl.json                        每项目 JSON
#        nginx_src.json
#        libwebsockets.json
#        ...
```

#### 实际输出对比

以扫描含 3 个项目的目录为例：

```bash
# 文件模式: 1 个文件
./scan combo-scan /opensource -o report.xlsx
#   输出 1 个文件:
#     report.xlsx (5 sheets: Summary + 3 projects + Symbol Summary)

# 目录模式: 2N+1 个文件（N = 项目数）
./scan combo-scan /opensource -o /tmp/results
#   输出 7 个文件:
#     merged.xlsx          合并工作簿 (5 sheets)
#     project_a.xlsx       单项目 (2 sheets: Call Sites + Symbol Summary)
#     project_a.json       单项目 JSON
#     project_b.xlsx
#     project_b.json
#     project_c.xlsx
#     project_c.json
```

### 执行流程

```
Phase 1: 探测 (Probe)
  输入: root 目录
  任务: rg --count-matches 搜索 OpenSSL 符号模式 (Aho-Corasick 多模式匹配)
  产出: 包含 OpenSSL 调用的叶子目录列表
  |
  v
Phase 1.5: 合并 (Consolidate)
  输入: 叶子目录列表
  任务: 将同一项目的子目录合并为项目根目录
        curl/lib/ + curl/src/ -> curl/
        应用 --exclude 过滤，名称冲突追加序号
  产出: 去重后的项目目录列表 + 项目名称映射
  |
  v
Phase 2: 扫描 (Scan)
  输入: 项目目录列表
  任务: 逐项目启动独立子进程:
        python3 -m openssl_scanner source <project> -o <tmp> -j <jobs>
        -o 目录模式: 子进程输出 .xlsx (自动生成伴生 .json)
        -o 文件模式 / --json-only: 子进程输出 .json
        超时: 600 秒/项目，超时后 SIGTERM 终止进程组
        -o 目录模式: 将 XLSX+JSON 复制到输出目录
  产出: 每项目 JSON (必有) + 每项目 XLSX (-o 目录模式且非 --json-only)
  |
  v
Phase 3: 合并 (Merge)
  输入: 所有项目的 JSON 报告
  任务: 默认:      SourceMergeExporter.merge_from_json() -> 多工作表 XLSX
        --json-only: _combo_merge_json() -> 合并 JSON
  产出: merged.xlsx 或 merged.json
  |
  v
清理: 删除 $TMPDIR/combo_scan_XXXX/ 临时目录
```

**阶段总结:**

| 阶段 | 输入 | 关键操作 | 产出 |
|------|------|----------|------|
| Phase 1 探测 | root 目录 | ripgrep 多模式搜索 | 叶子目录列表 |
| Phase 1.5 合并 | 叶子目录 | 路径合并 + exclude 过滤 | 项目目录列表 |
| Phase 2 扫描 | 项目目录 | 独立子进程 tree-sitter 解析 | 每项目 JSON/XLSX |
| Phase 3 合并 | JSON 报告集 | 跨项目合并 + 符号去重统计 | merged.xlsx/json |

### 临时文件和目录结构

```
$TMPDIR/                               系统临时目录
  combo_scan_XXXX/                     自动创建，完成后自动删除
    curl.xlsx (或 .json)               各项目临时报告
    nginx_src.xlsx (或 .json)
    libwebsockets.xlsx (或 .json)
    ...

-o 文件模式 (如 -o report.xlsx):
  report.xlsx                          仅合并工作簿

-o 目录模式 (如 -o /tmp/results):
  /tmp/results/
    merged.xlsx                        合并工作簿
    curl.xlsx                          每项目 XLSX
    curl.json                          每项目 JSON
    nginx_src.xlsx
    nginx_src.json
    ...

-o 文件模式 + --json-only (如 -o report.json --json-only):
  report.json                          仅合并 JSON

-o 目录模式 + --json-only (如 -o /tmp/results --json-only):
  /tmp/results/
    merged.json                        合并 JSON
    curl.json                          每项目 JSON
    nginx_src.json
    ...
```

项目命名规则：
- 相对于 root 的路径，`/` 替换为 `_`
- 例: `libwebsockets` -> `libwebsockets.json`
- 例: `oh/scanner` -> `oh_scanner.json`
- 名称冲突时追加 `_<序号>`

### XLSX 输出格式

与 `source-merge` 相同的多工作表结构：

| 工作表 | 内容 |
|--------|------|
| **Summary** | 每项目统计（文件数、调用点、唯一符号、Top 分类）+ TOTAL 行 |
| **\<项目名\>** | 每个项目的完整调用点数据 |
| **Symbol Summary** | 跨项目去重后的符号统计（含 Projects/Project List 列） |

### JSON 输出格式（--json-only）

```json
{
  "projects": [
    {
      "project": "curl",
      "meta": { "tool_version": "...", "scan_time": "..." },
      "summary": {
        "total_files_scanned": 100,
        "total_call_sites": 612,
        "unique_symbols_count": 318
      },
      "call_sites": [ ... ],
      "errors": []
    }
  ],
  "total_projects": 58,
  "total_symbols": 6225
}
```

### 设计说明

**进程隔离**: 每个项目在独立子进程中扫描，避免 CPython pymalloc 内存碎片导致 OOM。OS 在子进程退出时回收全部内存。

**顺序而非并行**: 每个项目内部已使用 ProcessPoolExecutor 并行分析文件。嵌套并行（线程池套进程池）会导致 fork+pymalloc OOM。

**数据文件检测**: 嵌入式二进制数据文件会导致 tree-sitter 解析器异常缓慢。`_is_data_blob()` 检查文件前 512 字节，跳过无 C 关键字的纯 hex 数据文件。

**符号链接环检测**: `_collect_source_files` 跟踪已访问的真实路径，检测并跳过会导致 `os.walk` 无限递归的符号链接环。

---

## proc - 进程扫描命令

分析 Linux 运行中进程加载的共享库中的 OpenSSL 依赖。通过读取 `/proc/<pid>/maps` 获取已加载的库列表。

> 仅支持 Linux 系统。

### 语法

```bash
./scan proc [options]
```

### 参数

| 参数 | 说明 |
|------|------|
| `--pid PID` | 目标进程 PID |
| `--name NAME` | 按进程名搜索 |
| `--openssl-lib PATH` | 指定 libcrypto.so 路径 |
| `--openssl-ssl PATH` | 指定 libssl.so 路径 |
| `-o, --output FILE` | 输出文件 |
| `-L, --lib-path PATH` | 额外库搜索路径（可多次使用） |
| `-j, --jobs N` | 并行线程数 |
| `--json-only` | 仅输出 JSON |
| `--include-deleted` | 包含已删除（不可访问）的库 |
| `-v, --verbose` | 详细日志 |
| `--log-file FILE` | 日志写入文件 |

### 示例

```bash
# 扫描指定进程
./scan proc --pid 1234 -o report.json

# 按进程名搜索并扫描
./scan proc --name nginx -o nginx_openssl.json

# 使用指定 OpenSSL 库
./scan proc --pid 1234 --openssl-lib /usr/lib/libcrypto.so.3 -o report.json
```

---

## hap - 包扫描命令

扫描 OpenHarmony 应用包（HAP/HAR/HSP/APP）中打包的 native .so 库的 OpenSSL 依赖。

### 背景

OpenHarmony 应用包本质是 ZIP 压缩文件，native 库位于 `libs/<abi>/` 目录下。工具会自动：
1. 解压包内的 .so 文件
2. 解析 `module.json` 提取元数据（bundleName、版本等）
3. 检测打包的 OpenSSL 库（如 libcrypto.so.3）
4. 对所有 native 库进行符号分析

### 支持的包格式

| 格式 | 扩展名 | 说明 |
|------|--------|------|
| **HAP** | .hap | Harmony Ability Package，应用能力包 |
| **HAR** | .har | Harmony Archive，静态共享包 |
| **HSP** | .hsp | Harmony Shared Package，动态共享包 |
| **APP** | .app | 应用发布包，内含多个 HAP/HSP |

### 语法

```bash
./scan hap <target> [options]
```

### 参数

| 参数 | 说明 |
|------|------|
| `target` | HAP/HAR/HSP/APP 文件或包含包的目录 |
| `--abi ABI` | 指定目标 ABI（默认自动选择，优先 arm64-v8a） |
| `--openssl-lib PATH` | 指定外部 libcrypto.so（包未内置 OpenSSL 时使用） |
| `--openssl-ssl PATH` | 指定外部 libssl.so（可选） |
| `-o, --output FILE` | 输出文件（默认: openssl_deps_report.json） |
| `-j, --jobs N` | 并行线程数（默认: CPU 核心数） |
| `--json-only` | 仅输出 JSON |
| `--keep-extracted` | 保留解压的临时文件 |
| `-v, --verbose` | 详细日志 |
| `--log-file FILE` | 日志写入文件 |

### ABI 自动选择

包内可能包含多个 ABI 目录。未指定 `--abi` 时按以下优先级自动选择：

```
arm64-v8a > armeabi-v7a > armeabi > x86_64 > x86
```

### 示例

```bash
# 扫描单个 HAP 包
./scan hap MyApp.hap -o report.json

# 扫描 APP 发布包（自动分析所有内含 HAP/HSP）
./scan hap MyApp.app -o report.json

# 扫描第三方 HAR 库
./scan hap thirdparty.har -o report.json

# 指定 ABI
./scan hap MyApp.hap --abi armeabi-v7a -o report.json

# 批量扫描目录下所有包
./scan hap /path/to/packages/ -o report.json

# 使用外部 OpenSSL 参考库（包未内置时）
./scan hap MyApp.hap --openssl-lib /system/lib64/libcrypto.so.3 -o report.json

# 保留解压文件用于调试
./scan hap MyApp.hap -o report.json --keep-extracted -v

# 导出 HTML 报告
./scan hap MyApp.hap -o report.json
./scan export report.json -o report.html
```

### OpenSSL 检测逻辑

工具按以下顺序检测 OpenSSL 库：

1. **包内检测** - 检查提取的 .so 文件名是否匹配 `libcrypto*`、`libssl*` 等模式
2. **命令行指定** - 使用 `--openssl-lib` 指定的外部库路径
3. **自动发现** - 从提取的 .so 列表中自动发现

> 注意：版本化的库名（如 `libcrypto.so.3`、`libssl.so.1.1`）均可正确识别。

### JSON 报告结构（包扫描）

```json
{
  "meta": {
    "tool_version": "1.0.0",
    "report_type": "package",
    "scan_time": "2026-02-09T21:00:00",
    "scan_root": "/path/to/MyApp.hap",
    "target_arch": "aarch64",
    "package": {
      "package_path": "/path/to/MyApp.hap",
      "package_type": "hap",
      "bundle_name": "com.example.myapp",
      "module_name": "entry",
      "module_type": "entry",
      "version_name": "1.0.0",
      "version_code": 1000000,
      "min_api_version": 11,
      "device_types": ["default", "tablet"],
      "scanned_abi": "arm64-v8a",
      "abis_available": ["arm64-v8a", "armeabi-v7a"],
      "native_libs_count": 5,
      "bundled_openssl": true
    }
  },
  "summary": {
    "total_files_scanned": 5,
    "files_with_openssl_deps": 2,
    "unique_openssl_symbols": 535,
    "openssl_libs_found": ["libcrypto.so.3", "libssl.so.3"]
  },
  "openssl_symbols": {
    "by_file": { "..." : {} },
    "by_category": { "..." : {} },
    "all_unique": ["SSL_connect", "EVP_DigestInit", "..."]
  }
}
```

### 包类型差异

| | HAP/HAR/HSP | APP |
|--|-------------|-----|
| 内部结构 | libs/\<abi\>/*.so + module.json | 多个 .hap/.hsp 子包 |
| 扫描方式 | 直接提取 native 库 | 逐个解压子包后分析 |
| 元数据 | 单个 module.json | 外层 + 每个子包各有 module.json |
| 报告 | 单包报告 | 包含子包聚合信息 |

---

## update-data - 更新内置数据

更新内置的 OpenSSL 符号和宏数据。源码扫描（`source` 命令）依赖 `data/` 目录下的预置数据进行匹配。不同 OpenSSL 版本的符号集合不同，使用此命令可针对目标版本生成精确的匹配数据。

### 数据文件说明

| 文件 | 内容 | 来源 | 用途 |
|------|------|------|------|
| `data/openssl_symbols.json` | ELF 导出函数符号 | libcrypto.so + libssl.so | ELF 扫描 + 源码扫描 |
| `data/openssl_macros.json` | 头文件宏和内联函数 | include/openssl/*.h | 仅源码扫描 |

### 语法

```bash
./scan update-data [options]
```

### 参数

| 参数 | 说明 |
|------|------|
| `--openssl-lib PATH` | libcrypto.so 路径（更新 openssl_symbols.json） |
| `--openssl-ssl PATH` | libssl.so 路径（与 --openssl-lib 一起使用） |
| `--header-dir PATH` | OpenSSL include/openssl/ 目录（更新 openssl_macros.json） |
| `--ossl-version VER` | 版本号（未指定时从路径自动检测） |
| `-o, --output-dir DIR` | 输出目录（默认: 内置 data/ 目录） |
| `-v, --verbose` | 详细日志 |
| `--log-file FILE` | 日志写入文件 |

> 至少需要 `--openssl-lib` 或 `--header-dir` 之一。

### 示例

```bash
# 同时更新符号和宏（推荐）
./scan update-data \
    --openssl-lib /path/to/libcrypto.so \
    --header-dir /path/to/openssl/include/openssl \
    --ossl-version 3.0.9

# 仅更新符号（从编译后的 .so 提取）
./scan update-data --openssl-lib /path/to/libcrypto.so

# 同时提取 libcrypto + libssl
./scan update-data \
    --openssl-lib /path/to/libcrypto.so \
    --openssl-ssl /path/to/libssl.so

# 仅更新宏（从头文件提取）
./scan update-data --header-dir /usr/include/openssl

# 输出到自定义目录
./scan update-data \
    --openssl-lib /path/to/libcrypto.so \
    -o /tmp/openssl_data/
```

### 版本自动检测

未指定 `--ossl-version` 时，工具会尝试从库文件路径中提取版本号：

```
/path/to/openssl-3.0.9/lib/libcrypto.so  -> 3.0.9
/path/to/OpenSSL-1.1.1w/lib/libcrypto.so -> 1.1.1w
```

### 宏分类

头文件宏分为 5 类：

| 类别 | 说明 | 数量（3.0.9） | 示例 |
|------|------|---------------|------|
| explicit_define | 显式 #define 宏 | 1180 | SSL_CTX_set_mode, OPENSSL_free |
| alias_define | 别名/兼容宏 | 258 | SSLeay_version -> OpenSSL_version |
| inline_function | static inline 函数 | 5 | OPENSSL_LH_strhash |
| sk_template | STACK_OF 模板宏 | 1800 | sk_X509_num, sk_SSL_CIPHER_value |
| lh_template | LHASH 模板宏 | 56 | lh_SSL_SESSION_insert |

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
| `-v, --verbose` | 详细日志 |
| `--log-file FILE` | 日志写入文件 |

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
| `-v, --verbose` | 详细日志 |
| `--log-file FILE` | 日志写入文件 |

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
- 离线分析来自其他系统的二进制

```bash
# 示例：用 OpenSSL 3.2 符号表分析旧应用
./scan scan /old/app --openssl-lib /opt/openssl-3.2/lib/libcrypto.so.3
```

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

**Q: hap 命令和 scan 命令有什么区别?**

`scan` 直接分析 ELF 文件或目录，`hap` 先从 OpenHarmony 应用包（ZIP 格式）中提取 native .so 库，再进行分析。`hap` 还会解析 `module.json` 提取包元数据（bundleName、版本等）。

```bash
# scan: 直接分析 ELF
./scan scan /system/lib64/libcurl.so -o report.json

# hap: 从包中提取后分析
./scan hap MyApp.hap -o report.json
```

**Q: HAP 包没有内置 OpenSSL 怎么办?**

使用 `--openssl-lib` 指定设备上或 SDK 中的 OpenSSL 库作为参考：

```bash
./scan hap MyApp.hap --openssl-lib /path/to/libcrypto.so.3 -o report.json
```

**Q: HTML 报告需要网络吗?**

不需要。完全自包含，所有 JS/CSS/图表库都已嵌入。

---

## 退出码

| 码 | 含义 |
|---|------|
| 0 | 成功 |
| 1 | 失败 |
| 130 | 用户中断 (Ctrl+C) |
