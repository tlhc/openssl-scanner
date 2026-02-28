# Custom Pattern 扫描设计

**模块**: `custom_matcher.py` (新建) + `elf_analyzer.py` (扩展) + `hap_report.py` (扩展)

**状态**: 已实现, 待提交

---

## 1. 概述

在现有 HAP 扫描管线中, 与 OpenSSL 检测并行运行自定义字符串匹配。
两者完全独立, 互不影响。

```
cmd_hap():
  extract HAP -> .so files
    |
    +-- OpenSSL pipeline (existing)
    |     remove OpenSSL .so -> scan_directory() -> classify
    |
    +-- Custom pattern pipeline (new, runs on remaining .so)
    |     load patterns -> scan .dynsym UND + .rodata -> aggregate
    |
    +-- build_hap_summary_row(openssl_result, custom_result)
          |
          v
        summary.xlsx (OpenSSL columns + Custom Match column)
```

## 2. 数据存储

文件: `data/custom_patterns.json`

```json
{
  "version": "1.0",
  "description": "Custom pattern groups for non-OpenSSL library detection",
  "groups": {
    "openHiTLS": [
      "HITLS_Init",
      "HITLS_CFG_NewConfig",
      "HITLS_CFG_SetVersion",
      "HITLS_New",
      "HITLS_Connect",
      "HITLS_Accept",
      "HITLS_Read",
      "HITLS_Write",
      "HITLS_Close",
      "HITLS_Free"
    ],
    "wolfSSL": [
      "wolfSSL_Init",
      "wolfSSL_CTX_new",
      "wolfSSL_new",
      "wolfSSL_connect",
      "wolfSSL_accept",
      "wolfSSL_read",
      "wolfSSL_write",
      "wolfSSL_free",
      "wolfSSL_CTX_free",
      "wolfSSL_Cleanup"
    ]
  }
}
```

按 library 分组。后续可通过编辑此文件添加更多库。

## 3. 搜索机制

每个 .so 文件搜索两个位置:

### 3.1 .dynsym UND

```
undefined_symbols = elf_analyzer.get_undefined_symbols(path)
matches = set(undefined_symbols) & all_patterns
```

确定性高: 编译时动态链接引用。

### 3.2 .rodata

```
strings = elf_analyzer.extract_rodata_strings(path)
matches = {s for _, s in strings if s in all_patterns}
```

不使用 clustering (与 dlopen_analyzer 不同):
- OpenSSL 有 6248 符号, 偶然匹配率高, 需要 clustering 过滤
- Custom patterns 是精选函数名, 偶然匹配概率极低
- 每次命中都有意义

### 3.3 公共函数

新增 `elf_analyzer.extract_rodata_strings()`:

```python
def extract_rodata_strings(elf_path, section_names=None, min_len=4):
    """Extract printable ASCII strings from .rodata/.data sections.

    Returns Set[str] of unique printable strings.
    """
```

`custom_matcher` 调用此公共函数。

注意: `dlopen_analyzer` 保留自有的 `extract_c_strings_with_offsets()` 实现,
因为 clustering 算法需要 `(byte_offset, string)` 元组来计算字节距离,
而 `extract_rodata_strings` 只返回 flat `Set[str]`, API 需求不同。

## 4. 数据结构

```python
@dataclass
class CustomMatch:
    file: str          # libfoo.so
    group: str         # wolfSSL
    pattern: str       # wolfSSL_Init
    location: str      # dynsym_und / rodata

@dataclass
class CustomResult:
    matches: Dict[str, Set[str]]   # group -> matched patterns
    details: List[CustomMatch]      # per-file details
    summary_text: str               # "wolfSSL (3), openHiTLS (2)"
```

## 5. Summary.xlsx

### 新增列

```
_HAP_SUMMARY_COLUMNS 新增 (最后一列):
  ('custom_match', 22, 'Custom Match')
```

### 值格式

```
wolfSSL (3)                   -- 单个库
wolfSSL (3), openHiTLS (2)    -- 多个库
(空)                          -- 无匹配
```

括号内数字 = 匹配的唯一 pattern 数量。

### 示例

```
+---------------------------+------+---------------+-----------------+
| Package Name              | Type | OpenSSL Usage | Custom Match    |
+---------------------------+------+---------------+-----------------+
| com.foo.app/entry (foo)   | hap  | System-Link   | openHiTLS (5)   |
| com.bar.app/entry (bar)   | hap  | None          | wolfSSL (3)     |
| com.baz.lib (baz)         | har  | Bundled       |                 |
+---------------------------+------+---------------+-----------------+
```

## 6. Per-package JSON

```json
{
  "package_info": {
    "...existing fields...",
    "custom_match": "openHiTLS (3)",
    "custom_match_groups": {
      "openHiTLS": ["HITLS_Connect", "HITLS_Init", "HITLS_Read"],
      "wolfSSL": []
    }
  }
}
```

- `custom_match`: 摘要文本, 直接用于 XLSX Custom Match 列
- `custom_match_groups`: 按组分类的匹配符号列表 (sorted), 用于 JSON 详情

子 XLSX 不加 custom match 数据 (第一阶段)。

## 7. 默认行为

- 如果 `data/custom_patterns.json` 存在且非空: 自动启用
- 如果文件不存在或 groups 为空: 跳过, 不报错
- 无需 CLI flag 显式启用

## 8. 实现范围

| 文件 | 修改类型 | 说明 |
|------|---------|------|
| `data/custom_patterns.json` | 新建 | openHiTLS + wolfSSL + mbedTLS + libsodium (739 patterns) |
| `elf_analyzer.py` | 扩展 | 新增 `extract_rodata_strings()` 公共函数 (返回 Set[str]) |
| `dlopen_analyzer.py` | 微调 | MAX_SECTION_SIZE 调整; 保留自有 offset-aware 提取 (clustering 需要) |
| `custom_matcher.py` | 新建 | CustomMatcher, CustomResult, scan_file/scan_directory |
| `hap_report.py` | 扩展 | Custom Match 列, build_hap_summary_row 接收 custom_result |
| `__main__.py` | 修改 | cmd_hap() 加载 custom patterns, 调用 custom scan |

## 9. 测试计划

| 测试 | 覆盖 |
|------|------|
| load_patterns: 正常/空/缺失 | 加载逻辑 |
| scan_file: .dynsym UND 匹配 | 符号表匹配 |
| scan_file: .rodata 匹配 | 字符串匹配 |
| scan_file: 无匹配 | 空结果 |
| scan_directory: 多文件聚合 | 按组汇总 |
| summary_text 格式 | "wolfSSL (3)" 格式正确 |
| 集成: cmd_hap + custom | 端到端验证 |
