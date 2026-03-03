# 源码扫描结果 Diff 设计

**模块**: `source_diff.py` (新建) + `__main__.py` (扩展)

**状态**: 设计阶段

---

## 1. 概述

比较两份源码扫描 JSON 报告，在四个层级产出结构化差异：摘要、符号、
文件、调用点。同时支持单项目 (`source_scan`) 和多项目 (`combo_scan`)
报告。

```
source-diff old.json new.json [-o diff.json|diff.xlsx]

  old.json ----+
               |    load_report()     diff_single()
               +--> 路径归一化    ->  构建身份映射表
               |                      三路划分
  new.json ----+                      逐层聚合
                                          |
               +-------- DiffResult ------+
               |              |           |
               v              v           v
           终端文本        diff.json    diff.xlsx
         (人类可读)       (结构化)     (5个Sheet)
```

combo-scan diff 增加第五层（项目级差异），并将每个项目的
比较委托给 `diff_single()` 完成。

## 2. 使用场景

| 场景              | 旧报告           | 新报告           | 关注点                      |
|-------------------|------------------|------------------|-----------------------------|
| 版本升级审计       | v3.1 扫描结果    | v3.2 扫描结果    | 新增/移除了哪些 OpenSSL 调用 |
| 重构影响评估       | 重构前           | 重构后           | API 依赖面是否变化           |
| combo-scan 对比   | 上次全量扫描     | 本次全量扫描     | 哪些子项目发生了变动         |
| CI 回归检测       | 基线 JSON        | PR 扫描 JSON     | 退出码 1 表示有变化          |

## 3. 输入格式

仅接受 JSON 输入。每次 `source` 扫描在请求 XLSX 输出时都会自动
生成伴生 JSON 文件（参见 `_export_result()`），因此 JSON 始终可用。

支持两种 schema，通过 `meta.report_type` 自动检测：

**单项目** (`report_type: "source_scan"`):
```json
{
  "meta": { "tool_version", "report_type", "scan_time", "target" },
  "summary": {
    "total_files_scanned", "files_with_calls",
    "total_call_sites", "unique_symbols_count",
    "unique_symbols", "symbols_by_category"
  },
  "call_sites": [
    { "file_path", "file_name", "caller_function",
      "line_number", "column", "ossl_symbol",
      "category", "call_args", "language", "detection_method" }
  ],
  "errors": []
}
```

**多项目** (`report_type: "combo_scan"`):
```json
{
  "meta": {
    "report_type": "combo_scan", "merge_time",
    "total_projects", "total_call_sites", "total_unique_symbols"
  },
  "projects": [
    {
      "project", "target",
      "total_files_scanned", "files_with_calls",
      "total_call_sites", "unique_symbols",
      "symbols_by_category", "call_sites": [...]
    }
  ]
}
```

## 4. 调用点身份标识与匹配

### 4.1 身份键

行号在代码编辑后会漂移，因此匹配键为：

```
identity = (relative_file_path, caller_function, ossl_symbol)
```

- `relative_file_path`: 相对于 `target` 的路径，跨机器可比较
- `caller_function`: 函数级稳定，仅在函数重命名时变化
- `ossl_symbol`: 具体调用的 OpenSSL API

### 4.2 基于计数的 Diff

同一身份键可能出现多次（如 `send_data()` 中三次调用 `SSL_write`）。
算法比较出现次数：

```
old_map[key] = [call1, call2, call3]   (3 次)
new_map[key] = [call1, call2, ...]     (5 次)
  -> delta = +2
```

### 4.3 匹配算法

```
输入:  old_call_sites[], new_call_sites[]

步骤 1: 路径归一化
  rel_path = os.path.relpath(file_path, target)
  如提供 --old-prefix / --new-prefix 则先剥离前缀

步骤 2: 构建身份映射表
  key = (rel_path, caller_function, ossl_symbol)
  old_map: key -> [{ line, args, category }]
  new_map: key -> [{ line, args, category }]

步骤 3: 三路划分
  added_keys   = new_map.keys() - old_map.keys()
  removed_keys = old_map.keys() - new_map.keys()
  common_keys  = old_map.keys() & new_map.keys()

步骤 4: 分类 common keys
  for key in common_keys:
    old_count = len(old_map[key])
    new_count = len(new_map[key])
    if old_count == new_count 且行号相同:
      -> UNCHANGED
    elif old_count == new_count 且行号不同:
      -> MOVED (相同调用，不同行号)
    else:
      -> CHANGED (计数差 = new_count - old_count)

步骤 5: 向上聚合
  call_site_delta -> symbol_delta   (按 ossl_symbol 分组)
  call_site_delta -> file_delta     (按 file_path 分组)
  file_delta      -> project_delta  (仅 combo，按 project 分组)
  all             -> summary_delta  (总计)
```

## 5. Diff 层级

### 层级 0: 项目级差异 (仅 combo_scan)

```
added_projects:     新报告有、旧报告无的项目
removed_projects:   旧报告有、新报告无的项目
changed_projects:   两份都有但调用点不同的项目
unchanged_projects: 两份都有且调用点相同的项目
```

### 层级 1: 摘要差异

四个指标，各含 `{ old, new, delta }`:

| 指标                 | 说明                    |
|---------------------|-------------------------|
| total_files_scanned | 解析的源文件总数         |
| files_with_calls    | 包含 OpenSSL API 的文件数 |
| total_call_sites    | 调用点总数               |
| unique_symbols_count| 去重后的 OpenSSL 符号数  |

### 层级 2: 符号级差异

```
added:    新报告有、旧报告无的符号
removed:  旧报告有、新报告无的符号
category_delta: 每个类别 { old_count, new_count, delta }
```

其中 "count" 是该类别中去重符号数（非调用次数）。

### 层级 3: 文件级差异

```
added_files:   新报告有调用、旧报告无的文件
removed_files: 旧报告有调用、新报告无的文件
changed_files: 两份都有但调用数或符号不同的文件
  每文件: old_calls, new_calls, delta,
          old_symbols, new_symbols, delta_symbols,
          added_symbols[], removed_symbols[]
unchanged_files_count: 整数（默认不逐一列出）
```

### 层级 4: 调用点级差异

最细粒度。每条记录包含：

```
status:          ADDED | REMOVED | CHANGED | MOVED | UNCHANGED
file_path:       相对路径
caller_function: 所在函数名
ossl_symbol:     OpenSSL API 名称
category:        符号分类
old_line:        旧报告中的行号（ADDED 时为 null）
new_line:        新报告中的行号（REMOVED 时为 null）
old_args:        旧报告中的调用参数（ADDED 时为 null）
new_args:        新报告中的调用参数（REMOVED 时为 null）
old_count:       旧报告中的出现次数（CHANGED 时使用）
new_count:       新报告中的出现次数（CHANGED 时使用）
```

默认不输出 UNCHANGED 条目。使用 `--include-unchanged` 可包含。

## 6. JSON 输出 Schema

```json
{
  "meta": {
    "report_type": "source_diff",
    "diff_time": "2026-03-03T13:00:00",
    "tool_version": "1.x.x",
    "old_report": "baseline.json",
    "new_report": "current.json",
    "old_scan_time": "2026-02-15T10:00:00",
    "new_scan_time": "2026-03-01T10:00:00"
  },

  "summary_delta": {
    "total_files_scanned":  { "old": 120, "new": 125, "delta": 5  },
    "files_with_calls":     { "old": 45,  "new": 48,  "delta": 3  },
    "total_call_sites":     { "old": 612, "new": 648, "delta": 36 },
    "unique_symbols_count": { "old": 289, "new": 295, "delta": 6  }
  },

  "symbol_delta": {
    "added":   ["EVP_MAC_init", "EVP_MAC_update", "EVP_MAC_final"],
    "removed": ["DES_ecb_encrypt", "DES_set_key"],
    "unchanged_count": 284,
    "category_delta": {
      "crypto_evp":    { "old": 45, "new": 53, "delta": 8 },
      "crypto_legacy": { "old": 12, "new":  9, "delta": -3 }
    }
  },

  "file_delta": {
    "added_files":   ["src/mac_wrapper.c", "src/kdf_new.c"],
    "removed_files": ["src/des_compat.c"],
    "changed_files": [
      {
        "file": "src/tls.c",
        "old_calls": 42,  "new_calls": 47, "delta": 5,
        "old_symbols": 18, "new_symbols": 20, "delta_symbols": 2,
        "added_symbols":   ["SSL_CTX_set_min_proto_version"],
        "removed_symbols": []
      }
    ],
    "unchanged_files_count": 40
  },

  "call_site_delta": [
    {
      "status": "added",
      "file_path": "src/mac_wrapper.c",
      "caller_function": "init_mac",
      "ossl_symbol": "EVP_MAC_init",
      "category": "crypto_evp",
      "new_line": 42,
      "new_args": "(ctx, key, keylen, params)"
    },
    {
      "status": "removed",
      "file_path": "src/des_compat.c",
      "caller_function": "legacy_encrypt",
      "ossl_symbol": "DES_ecb_encrypt",
      "category": "crypto_legacy",
      "old_line": 88,
      "old_args": "(input, output, &ks, DES_ENCRYPT)"
    },
    {
      "status": "changed",
      "file_path": "src/tls.c",
      "caller_function": "init_ssl",
      "ossl_symbol": "SSL_CTX_new",
      "category": "ssl_core",
      "old_count": 1, "new_count": 2, "delta": 1
    },
    {
      "status": "moved",
      "file_path": "src/tls.c",
      "caller_function": "init_ssl",
      "ossl_symbol": "SSL_connect",
      "category": "ssl_core",
      "old_line": 55,
      "new_line": 62,
      "args": "(ssl)"
    }
  ],

  "project_delta": {
    "added_projects":   ["new_module"],
    "removed_projects": ["deprecated_lib"],
    "changed_projects": [
      {
        "project": "curl",
        "old_calls": 612, "new_calls": 624, "delta": 12,
        "old_symbols": 289, "new_symbols": 295, "delta_symbols": 6,
        "symbols_added": ["EVP_MAC_init"],
        "symbols_removed": ["DES_ecb_encrypt"]
      }
    ],
    "unchanged_projects": ["openssl", "zlib"]
  }
}
```

`project_delta` 仅在两份输入均为 `combo_scan` 时出现。

## 7. XLSX 输出布局

### 7.1 配色方案

复用项目现有颜色，并新增 diff 状态专用填充：

| 用途              | 颜色     | 十六进制   | 来源               |
|-------------------|----------|------------|---------------------|
| 调用点表头         | 蓝色     | `#E8F4FC` | source_exporter.py  |
| 摘要表头           | 绿色     | `#F0F8E8` | source_exporter.py  |
| 状态: ADDED       | 浅绿     | `#C6EFCE` | (新增, Excel 标准)  |
| 状态: REMOVED     | 浅红     | `#FFC7CE` | (新增, Excel 标准)  |
| 状态: CHANGED     | 浅黄     | `#FFEB9C` | (新增, Excel 标准)  |
| 状态: MOVED       | 浅灰     | `#D9D9D9` | (新增)              |
| Delta 正值        | 绿色字体  | `#006100` | (新增, Excel 标准)  |
| Delta 负值        | 红色字体  | `#9C0006` | (新增, Excel 标准)  |
| Delta 零          | 灰色字体  | `#808080` | (新增)              |

### 7.2 Sheet 1: Summary Delta (摘要差异)

表头填充: `#F0F8E8`（绿色，与现有 Summary 页一致）。

```
| 指标                | Old    | New    | Delta  |
|---------------------|--------|--------|--------|
| Files Scanned       | 120    | 125    | +5     |
| Files with Calls    | 45     | 48     | +3     |
| Call Sites           | 612    | 648    | +36    |
| Unique Symbols      | 289    | 295    | +6     |
|                     |        |        |        |
| Category Breakdown  |        |        |        |
| crypto_evp          | 45     | 53     | +8     |
| crypto_legacy       | 12     | 9      | -3     |
| ssl_core            | 30     | 30     | 0      |
```

Delta 列：正值绿色字体，负值红色字体，零灰色字体。
按绝对 delta 降序排列。

列定义: `(Metric, 30), (Old, 12), (New, 12), (Delta, 12)`

### 7.3 Sheet 2: Symbol Delta (符号差异)

表头填充: `#E8F4FC`（蓝色）。

```
| Symbol              | Category       | Status    | Old Calls | New Calls | Delta |
|---------------------|----------------|-----------|-----------|-----------|-------|
| EVP_MAC_init        | crypto_evp     | ADDED     | 0         | 3         | +3    |
| DES_ecb_encrypt     | crypto_legacy  | REMOVED   | 5         | 0         | -5    |
| SSL_CTX_new         | ssl_core       | CHANGED   | 8         | 10        | +2    |
```

- Status 列单元格按 7.1 配色表填充
- 默认不包含 UNCHANGED 行；使用 `--include-unchanged` 可包含
- 排序: Status (ADDED > REMOVED > CHANGED > UNCHANGED), 然后 Category, 然后 Symbol

列定义: `(OpenSSL Symbol, 35), (Category, 20), (Status, 12),
          (Old Calls, 12), (New Calls, 12), (Delta, 10)`

### 7.4 Sheet 3: File Delta (文件差异)

表头填充: `#E8F4FC`（蓝色）。

```
| File Path           | Status   | Old Calls | New Calls | Delta | Old Syms | New Syms | Added Symbols       | Removed Symbols     |
|---------------------|----------|-----------|-----------|-------|----------|----------|---------------------|---------------------|
| src/mac_wrapper.c   | ADDED    | 0         | 5         | +5    | 0        | 3        | EVP_MAC_init, ...   |                     |
| src/des_compat.c    | REMOVED  | 8         | 0         | -8    | 4        | 0        |                     | DES_ecb_encrypt,... |
| src/tls.c           | CHANGED  | 42        | 47        | +5    | 18       | 20       | SSL_CTX_set_min_... |                     |
```

排序: Status (ADDED > REMOVED > CHANGED), 然后绝对 delta 降序。

列定义: `(File Path, 60), (Status, 12), (Old Calls, 12), (New Calls, 12),
          (Delta, 10), (Old Symbols, 12), (New Symbols, 12),
          (Added Symbols, 40), (Removed Symbols, 40)`

### 7.5 Sheet 4: Call Site Delta (调用点差异)

表头填充: `#E8F4FC`（蓝色）。

```
| Status  | File Path       | Caller Function | OpenSSL Symbol | Category     | Old Line | New Line | Old Args              | New Args              |
|---------|-----------------|-----------------|----------------|--------------|----------|----------|-----------------------|-----------------------|
| ADDED   | src/tls.c       | init_ssl        | SSL_CTX_set_.. | ssl_core     |          | 62       |                       | (TLS_1_2_VERSION)     |
| REMOVED | src/des_compat.c| legacy_encrypt  | DES_ecb_encry..| crypto_legacy| 88       |          | (input, output, ...)  |                       |
| MOVED   | src/tls.c       | init_ssl        | SSL_connect    | ssl_core     | 55       | 62       | (ssl)                 | (ssl)                 |
```

排序: Status, 然后 File Path, 然后 New Line (REMOVED 用 Old Line)。

列定义: `(Status, 12), (File Path, 50), (Caller Function, 30),
          (OpenSSL Symbol, 35), (Category, 20),
          (Old Line, 10), (New Line, 10),
          (Old Args, 50), (New Args, 50)`

### 7.6 Sheet 5: Project Delta (仅 combo_scan)

表头填充: `#F0F8E8`（绿色）。

```
| Project    | Status    | Old Calls | New Calls | Delta | Old Symbols | New Symbols | Added Symbols       | Removed Symbols     |
|------------|-----------|-----------|-----------|-------|-------------|-------------|---------------------|---------------------|
| curl       | CHANGED   | 612       | 624       | +12   | 289         | 295         | EVP_MAC_init        | DES_ecb_encrypt     |
| new_mod    | ADDED     | 0         | 85        | +85   | 0           | 42          | SSL_CTX_new, ...    |                     |
| depr_lib   | REMOVED   | 42        | 0         | -42   | 18          | 0           |                     | DES_set_key, ...    |
```

列定义: `(Project, 30), (Status, 12), (Old Calls, 12), (New Calls, 12),
          (Delta, 10), (Old Symbols, 12), (New Symbols, 12),
          (Added Symbols, 40), (Removed Symbols, 40)`

## 8. 终端输出格式

不指定 `-o` 时，打印人类可读摘要：

```
  Source Diff: baseline.json -> current.json
  ============================================

  Summary:
    Files Scanned:    120 -> 125  (+5)
    Files with Calls:  45 ->  48  (+3)
    Call Sites:       612 -> 648  (+36)
    Unique Symbols:   289 -> 295  (+6)

  Symbols Added (3):
    + EVP_MAC_init        [crypto_evp]
    + EVP_MAC_update      [crypto_evp]
    + EVP_MAC_final       [crypto_evp]

  Symbols Removed (2):
    - DES_ecb_encrypt     [crypto_legacy]
    - DES_set_key         [crypto_legacy]

  Category Changes:
    crypto_evp:     45 -> 53  (+8)
    crypto_legacy:  12 ->  9  (-3)

  Files Added (2):
    + src/mac_wrapper.c      (5 calls, 3 symbols)
    + src/kdf_new.c          (8 calls, 4 symbols)

  Files Removed (1):
    - src/des_compat.c       (8 calls, 4 symbols)

  Files Changed (3):
    ~ src/tls.c              42 -> 47 calls (+5)
    ~ src/crypto.c           18 -> 22 calls (+4)
    ~ src/ssl_util.c         10 ->  8 calls (-2)
```

combo-scan diff 时在前面增加 Project Delta 段。

## 9. 路径归一化

两份报告中的文件路径可能因不同的 checkout 位置而不同。

### 9.1 自动归一化

默认将路径相对化到 `meta` 中的 `target` 字段：

```python
def _normalize_path(file_path, target):
    if os.path.isabs(file_path) and target:
        return os.path.relpath(file_path, target)
    return file_path
```

### 9.2 手动前缀剥离

当自动归一化不足时（如不同机器上 `target` 值不同），
使用显式前缀剥离：

```bash
./scan source-diff old.json new.json \
    --old-prefix /ci/workspace/v3.1/src \
    --new-prefix /ci/workspace/v3.2/src
```

## 10. 模块结构

```
src/openssl_scanner/
  source_diff.py                  (~400-500 行, 新建)
    |
    +-- DiffStatus(Enum)
    |     ADDED, REMOVED, CHANGED, MOVED, UNCHANGED
    |
    +-- @dataclass MetricDelta
    |     old: int, new: int, delta: int
    |
    +-- @dataclass CallSiteDelta
    |     status, file_path, caller_function, ossl_symbol, category,
    |     old_line, new_line, old_args, new_args, old_count, new_count
    |
    +-- @dataclass SymbolDelta
    |     symbol, category, status, old_calls, new_calls, delta
    |
    +-- @dataclass FileDelta
    |     file_path, status, old_calls, new_calls, delta,
    |     old_symbols, new_symbols, added_symbols, removed_symbols
    |
    +-- @dataclass ProjectDelta
    |     project, status, old_calls, new_calls, delta,
    |     old_symbols, new_symbols, symbols_added, symbols_removed
    |
    +-- @dataclass DiffResult
    |     meta: dict
    |     summary_delta: dict[str, MetricDelta]
    |     symbol_delta: { added, removed, unchanged_count, category_delta }
    |     file_delta: { added_files, removed_files, changed_files, ... }
    |     call_site_delta: list[CallSiteDelta]
    |     project_delta: optional (仅 combo)
    |
    |     def is_empty() -> bool
    |       任意层级无 added/removed/changed 时返回 True
    |
    +-- load_report(path, prefix=None) -> dict
    |     读取 JSON，检测 report_type，归一化路径
    |
    +-- diff_single(old_data, new_data, ...) -> DiffResult
    |     核心: 身份映射 -> 三路划分 -> 聚合
    |
    +-- diff_combo(old_data, new_data, ...) -> DiffResult
    |     按项目名匹配，对每个项目调用 diff_single
    |
    +-- SourceDiffJsonExporter
    |     .export(result: DiffResult, path: str) -> None
    |
    +-- SourceDiffExcelExporter
    |     .export(result: DiffResult, path: str) -> None
    |     5 个 Sheet: Summary Delta, Symbol Delta, File Delta,
    |                 Call Site Delta, Project Delta (仅 combo)
    |
    +-- format_console(result: DiffResult) -> str
          终端人类可读输出
```

CLI 部分在 `__main__.py` 新增约 80 行：

```
+-- create_source_diff_parser(subparsers)
+-- cmd_source_diff(args) -> int
```

## 11. CLI 接口

```
openssl-scanner source-diff OLD NEW [-o OUTPUT] [OPTIONS]

位置参数:
  OLD                  基线报告 (JSON)
  NEW                  当前报告 (JSON)

选项:
  -o, --output PATH    输出路径 (.json 或 .xlsx)；省略则输出到终端
  --summary-only       跳过调用点差异（仅层级 1-3）
  --include-unchanged  在输出中包含未变化的条目
  --old-prefix PATH    从旧报告路径中剥离此前缀
  --new-prefix PATH    从新报告路径中剥离此前缀
  --ignore-categories  要排除的类别（空格分隔）
  -v, --verbose        增加详细程度
  --log-file PATH      日志写入文件
```

### 退出码

| 代码 | 含义                           |
|------|--------------------------------|
| 0    | 未检测到变化                    |
| 1    | 检测到变化（diff 非空）         |
| 2    | 错误（文件未找到、解析错误）    |

退出码 1 表示有变化，遵循 `diff(1)` 惯例，便于 CI 集成：

```bash
./scan source-diff baseline.json current.json || echo "API 使用面发生了变化！"
```

## 12. 用法示例

```bash
# 终端快速查看
./scan source-diff baseline.json current.json

# JSON diff 用于 CI 流水线
./scan source-diff baseline.json current.json -o diff.json

# XLSX diff 用于人工审阅
./scan source-diff baseline.json current.json -o diff.xlsx

# 仅看摘要（跳过数千条调用点条目）
./scan source-diff baseline.json current.json -o diff.xlsx --summary-only

# 跨机器比较（不同 checkout 路径）
./scan source-diff old.json new.json \
    --old-prefix /ci/workspace/v3.1 \
    --new-prefix /ci/workspace/v3.2

# combo-scan 全量对比
./scan source-diff last_month_combo.json this_month_combo.json -o delta.xlsx

# 过滤噪音类别
./scan source-diff old.json new.json --ignore-categories crypto_err openssl_util

# CI 门禁：OpenSSL API 使用面变化则失败
./scan source-diff baseline.json pr_scan.json -o /dev/null
if [ $? -eq 1 ]; then
  echo "WARNING: 此 PR 中 OpenSSL API 使用发生了变化"
fi
```

## 13. 设计决策

| # | 决策                                        | 理由                                                            |
|---|---------------------------------------------|----------------------------------------------------------------|
| 1 | 仅接受 JSON 输入（不接受 XLSX）              | JSON 是数据层；XLSX 是展示层。伴生 JSON 始终存在。               |
| 2 | 身份键 = (路径, 函数, 符号)                  | 对行号漂移有弹性。                                              |
| 3 | 重复调用采用计数 diff                        | 同一函数中多次调用同一 API 是真实模式。简单计数即可处理。        |
| 4 | 默认排除 UNCHANGED                           | 大型代码库中数千条未变化条目产生噪音。通过选项可包含。          |
| 5 | MOVED 作为独立状态                           | 审计价值："相同依赖，代码被重构" 与 "无变化" 是不同信息。       |
| 6 | 第一版即支持 combo                            | 边际成本低：combo diff = 单项目 diff 循环 + 项目级聚合。        |
| 7 | 退出码 1 表示有变化                           | 匹配 `diff(1)` 惯例；无需额外解析即可用于 CI 集成。            |
| 8 | 不支持 XLSX 对 XLSX diff                     | 避免 openpyxl 读依赖复杂性；JSON 是规范数据格式。              |
| 9 | 状态颜色使用 Excel 标准调色板                 | `#C6EFCE`/`#FFC7CE`/`#FFEB9C` 是 Excel 内置的好/差/中性条件格式。|

## 14. 测试策略

```
tests/test_source_diff.py (~400 行)

测试分类:
  1. load_report()
     - source_scan JSON
     - combo_scan JSON
     - 无效 JSON / 缺少字段
     - 带前缀剥离的路径归一化

  2. diff_single()
     - 相同报告 -> 空 diff, 退出码 0
     - 仅新增符号
     - 仅移除符号
     - 混合 add/remove/change/move
     - 基于计数的 diff（重复调用）
     - 类别 delta 聚合
     - 文件 delta 聚合

  3. diff_combo()
     - 新增/移除项目
     - 变化项目委托给 diff_single
     - 项目名匹配

  4. 导出器
     - JSON 往返（导出 -> 加载 -> 验证结构）
     - XLSX Sheet 数量和表头验证
     - 终端输出格式冒烟测试

  5. CLI 集成
     - 退出码 0（无变化）
     - 退出码 1（有变化）
     - 退出码 2（错误输入）
     - --summary-only 标志
     - --include-unchanged 标志
     - --ignore-categories 过滤器
```

## 15. 后续扩展

- **XLSX diff 输出带超链接**: 变化的符号链接到文档
- **HTML diff 报告**: 左右对照可视化比较
- **趋势追踪**: 多版本 diff 链 (v1 -> v2 -> v3)
- **阈值告警**: "如果新增超过 N 个 crypto_legacy 调用则告警"
- **HAP 扫描 diff**: 扩展到 HAP 二进制扫描结果（不同 JSON schema）
