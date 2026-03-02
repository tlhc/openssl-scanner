# HAP 提取与扫描设计

**模块**: `hap_extractor.py` + `hap_report.py` + `__main__.cmd_hap()`

---

## 1. 概述

从 OpenHarmony 包 (HAP/HAR/HSP/APP/ZIP) 中提取 native `.so`，扫描 OpenSSL
依赖，输出报告。

```
                               +------------------+
*.hap / *.har / *.hsp -+------>| _extract_single  |--+
                       |       +------------------+  |
*.app -----------------+------>| _extract_app     |--+---> Scanner.scan_directory()
                       |       +------------------+  |        |
*.zip -----------------+------>| _extract_zip     |--+        v
                       |       +------------------+       ScanResult
directory of packages -+                                      |
                                                              v
                                                    JSON / XLSX / summary.xlsx
```

## 2. 包格式

```
APP 应用包
  +-- entry.hap
  +-- feature.hap
  +-- shared.hsp
  |
  每个 HAP/HSP:
    +-- module.json           (元数据)
    +-- libs/
    |   +-- arm64-v8a/        (ABI 目录)
    |   |   +-- libentry.so
    |   |   +-- libcrypto.so.3  (内置 OpenSSL, 可选)
    |   +-- armeabi-v7a/
    +-- resources/
    +-- ets/
```

| 扩展名 | 说明 |
|--------|------|
| `.hap` | Harmony Ability Package (能力包) |
| `.har` | Harmony Archive (共享库归档) |
| `.hsp` | Harmony Shared Package (共享包) |
| `.app` | 应用包, 内含 HAP/HSP |
| `.zip` | 通用容器, 可嵌套包 |

支持的 ABI (优先级顺序):

| ABI | e_machine | 说明 |
|-----|-----------|------|
| `arm64-v8a` | 0xB7 EM_AARCH64 | 主要架构 |
| `armeabi-v7a` | 0x28 EM_ARM | |
| `armeabi` | 0x28 EM_ARM | 遗留架构 |
| `x86_64` | 0x3E EM_X86_64 | 模拟器 |
| `x86` | 0x03 EM_386 | 模拟器 |

未指定 ABI 时提取全部; `ABI_PRIORITY` 仅影响 metadata 中的排列顺序。

## 3. 数据结构

### HapMetadata

```python
@dataclass
class HapMetadata:
    package_path: str
    package_type: str          # "hap" / "har" / "hsp" / "app" / "zip"
    bundle_name: str           # app.bundleName
    module_name: str           # module.name
    module_type: str           # "entry" / "feature" / "shared"
    version_name: str
    version_code: int
    min_api_version: int
    device_types: List[str]
    abis_found: List[str]
    native_libs: Dict[str, List[str]]   # ABI -> [filenames]
```

`module.json` 缺失或格式错误时，各字段回退为空值，提取和扫描正常进行。

### HapExtractResult

```python
@dataclass
class HapExtractResult:
    metadata: HapMetadata
    extract_dir: str
    so_files: List[str]
    openssl_lib: Optional[str]      # 内置 libcrypto 路径
    openssl_ssl: Optional[str]      # 内置 libssl 路径
    sub_packages: List[HapExtractResult]
```

APP 包形成树状结构:

```
HapExtractResult (APP)
  +-- so_files: [all .so merged]
  +-- sub_packages:
       +-- HapExtractResult (entry.hap)
       +-- HapExtractResult (feature.hap)
```

## 4. 提取流水线

### 4.1 分发

```
extract(package_path, abi, extract_dir)
  +-- .app  --> _extract_app()
  +-- .zip  --> _extract_zip()
  +-- other --> _extract_single()
```

### 4.2 _extract_single (HAP/HAR/HSP)

```
打开 ZipFile
  -> 读取 module.json
  -> 发现 libs/<abi>/ (ELF magic 校验)
  -> 构建 HapMetadata
  -> 提取 ELF 文件到 <extract_dir>/<abi>/
  -> _detect_openssl() 检测内置 libcrypto/libssl
```

未指定 ABI 时提取所有 ABI; 指定不存在的 ABI 抛出 ValueError。

### 4.3 _extract_app (APP 应用包)

```
打开 ZipFile
  -> 构建 APP 级元数据
  -> 遍历每个 .hap/.hsp 条目:
       路径穿越检查
       _safe_extract_member() 提取到临时位置
       _extract_single() 处理子包
  -> 合并所有 so_files
```

### 4.4 _extract_zip (递归处理)

ZIP 可能是:
- 扁平包 (含 libs/ 目录)
- 容器 (嵌套 .hap/.har/.hsp/.zip)
- 两者兼有

```
扫描嵌套包
  -> 未发现嵌套:       回退到 _extract_single()
  -> 深度 >= 20:       警告, 回退到 _extract_single()
  -> 存在嵌套:
       提取外层 libs/ (如有)
       遍历每个嵌套条目:
         名称去重 (entry_2.hap)
         路径穿越检查
         创建 sub_extract_dir/<stem>/
         .zip -> 递归 _extract_zip(_depth+1)
         其他 -> _extract_single()
       合并所有 so_files
```

设计要点:
- `MAX_ZIP_DEPTH = 20` 防止 zip 炸弹
- 每个嵌套包提取到独立子目录，避免同名 `.so` 覆盖
- 外层 libs/ 和嵌套包同时处理

## 5. 安全性

**路径穿越防护**: 每个提取路径通过 `os.path.realpath()` 做目录限制检查。

**大小限制**: `MAX_EXTRACT_SIZE = 20 GB`, 逐块写入, 超限立即删除部分文件。

**ELF 识别**: 通过 magic bytes `\x7fELF` 识别, 不依赖文件扩展名。
同时校验 `e_machine` 是否匹配声明的 ABI。

## 6. CLI 集成

### 6.1 规划阶段

```
cmd_hap(args)
  -> 收集目标 (文件 + 目录)
  -> plan_packages() -> List[PkgEntry]
```

`plan_packages()` 将容器 (.zip/.app) 展开为内部条目，但不执行提取:

```python
class PkgEntry:
    path: str           # 独立包路径, 或 None
    container: str      # 容器路径, 或 None
    zip_entry: str      # 容器内条目名
    display_name: str   # 例如 "bundle_entry.hap"
```

### 6.2 即时提取 (JIT)

`extract_pkg_entry()` 按需提取，每次只处理一个包:
- 独立包: 直接返回路径
- 容器条目: 提取到临时文件, finally 中清理

### 6.3 扫描流程

```
遍历每个 PkgEntry:
  1. 增量检查: 若 JSON+XLSX 缓存存在且比源文件新则跳过
  2. 提取包 -> HapExtractResult
  3. 移除内置 OpenSSL 库 (防止扫描 OpenSSL 自身)
  4. Scanner.scan_directory() 使用 ProcessPoolExecutor 并行分析
  5. 将 package_info 附加到 ScanResult
  6. per-package 模式: 立即写入报告
  7. 输出进度行
```

### 6.4 输出模式

| 参数 | 行为 |
|------|------|
| `-o report.xlsx` | 合并为单个报告 |
| `-o /tmp/reports/` | 每包独立 JSON + XLSX + summary.xlsx |
| `--json-only` | 不生成 XLSX |
| `--force` | 忽略缓存, 重新扫描 |

### 6.5 增量扫描

per-package 模式下, 通过 mtime 比较跳过已扫描的包:

```
cached = (json 存在 AND json_mtime >= source_mtime)
         AND (json_only OR xlsx 存在)
```

支持可恢复的批量扫描。

## 7. 汇总报告

### 7.1 分类 (`classify_hap_detection`)

逐文件分析, 聚合为包级别分类:

```
检测方式: Dynamic / Static / dlopen / Mixed / None

ossl_type (内部分类):
  Self-Contained  -- 所有依赖在包内解决 (输出时映射为 None)
  System-Link     -- 存在未解析的外部 OpenSSL 依赖
  In-APP-Link     -- System-Link 由同一应用版本的兄弟 HAP 解决
  No-OpenSSL      -- 无 OpenSSL 符号 (输出时映射为 None)
```

逐库解析: 每个 `.so` 的依赖独立评估; 任一文件有未解析的
外部依赖即标记为 System-Link。高/中置信度的静态提供者加入
bundled 集合参与依赖解析。

内部 `ossl_type` 与 `bundled_openssl` 在 `build_hap_summary_row()`
中合并为最终的 `openssl_usage` 列:

```
bundled_openssl (字符串 "Yes ...")  ->  Bundled (static) / Bundled (static, shared)
bundled_openssl (True)              ->  Bundled
ossl_type == No-OpenSSL             ->  None
ossl_type == System-Link            ->  System-Link
ossl_type == In-APP-Link            ->  In-APP-Link
其他                                ->  None
```

优先级: 打包的 .so 文件 > 静态提供者 > 依赖解析分类。

辅助函数:
- `detect_static_providers(scan_result)`:
  识别包内静态链接 OpenSSL 的 .so 文件 (高/中置信度)。
  按 basename 跨 ABI 去重, 保留符号数最多的条目。
  返回 `(bundled_str, providers_list)`。
- `_dt_needed_resolved(openssl_libs, bundled_basenames, patterns)`:
  检查 DT_NEEDED 中的 OpenSSL 库是否全部由包内 bundled 库满足。
  对原始 basename 做 pattern 匹配 (非 stem), 再用 stem 比较 bundled 集合。
- `_dlopen_targets_resolved(dlopen_libs, bundled_basenames, patterns)`:
  检查 dlopen 加载的 OpenSSL 目标是否全部由包内 bundled 库满足。
  逻辑同上。
- `_deps_include_provider(direct_deps, providers)`:
  检查 DT_NEEDED 中是否包含已知的静态 OpenSSL 提供者。
  用于 .so 有 OpenSSL UND 符号但无 OpenSSL 命名的 DT_NEEDED 的场景 --
  符号通过非 OpenSSL 库路由 (如 libfoo.so 内置了静态 OpenSSL)。

### OpenSSL Usage 分类速查表

| OpenSSL Usage | 含义 | 判定条件 | 示例 |
|---|---|---|---|
| None | 无 OpenSSL 使用 | 包内所有 `.so` 均无 OpenSSL 符号 (UND/.rodata/dlsym), 或依赖已在包内解决但无独立 bundled OpenSSL `.so` | `libentry.so` 只调用系统 API, 不涉及加密 |
| Bundled | 打包了独立的 OpenSSL `.so` | 包内 `libs/` 目录含 `libcrypto.so*` 或 `libssl.so*` (由 `OPENSSL_LIBRARY_PATTERNS` 匹配) | `libs/arm64-v8a/` 中同时存在 `libentry.so` 和 `libcrypto.so.3` |
| Bundled (static) | 静态链接 OpenSSL 到某个 `.so` 中, 仅自用 | 包内某 `.so` 检测到 OpenSSL 版本字符串 + 佐证符号, 以 `-fvisibility=hidden` 编译; 包内无其他 `.so` 在 DT_NEEDED 中引用该文件 | `libfoo.so` 内含 `OpenSSL 3.0.9` 字符串, 无其他库依赖它 |
| Bundled (static, shared) | 静态链接 OpenSSL 到某个 `.so` 中, 且被其他库共享使用 | 同上, 但包内有其他 `.so` 的 DT_NEEDED 包含该静态提供者 -- 提供者充当包内 OpenSSL 门面 | `libfoo.so` 静态内置 OpenSSL; `libapp.so` DT_NEED `libfoo.so` 通过它使用 OpenSSL |
| System-Link | 依赖系统 OpenSSL | `.so` 有 OpenSSL UND 符号但 DT_NEEDED 指向的库不在包内 | `libentry.so` DT_NEED `libcrypto.so.3` 但包内无此文件 |
| In-APP-Link | 由同一应用版本的兄弟 HAP 提供 | 单 HAP 看是 System-Link, 但同一 `(bundle_name, version_code, version_name)` 的兄弟 HAP 打包了所需 OpenSSL 库或通过静态链接提供 | `entry.hap` DT_NEED `libcrypto.so.3`; `feature.hap` (同一应用版本) 携带 `libcrypto.so.3` |

`build_hap_summary_row()` 中的优先级:

```
bundled_openssl (字符串 "Yes ...")  ->  Bundled (static) / Bundled (static, shared)
bundled_openssl (True)              ->  Bundled
ossl_type == No-OpenSSL             ->  None
ossl_type == System-Link            ->  System-Link
ossl_type == In-APP-Link            ->  In-APP-Link
其他 (Self-Contained)               ->  None
```

### 7.1.1 跨 HAP 聚合 (`aggregate_app_classification`)

逐 HAP 分类完成后, 第二阶段对 System-Link 的 HAP 进行跨 HAP 重分类:
如果同一应用版本的兄弟 HAP 提供了所需的 OpenSSL 库, 则将
System-Link 升级为 In-APP-Link。

```
阶段 1: 逐 HAP 分类
  classify_hap_detection(result) 对每个 HAP 独立分类
    -> (method, static_syms, dynamic_syms, dlopen_syms, ossl_type)

阶段 2: 跨 HAP 聚合
  aggregate_app_classification(all_results, per_hap_classifications)
    -> 更新后的分类列表, System-Link 可能升级为 In-APP-Link
```

**分组键:** 按 `(bundle_name, version_code, version_name)` 分组 -- 来自 `module.json`
的 `app` 段, 是 OpenHarmony 应用版本的规范标识。同一应用版本的所有 HAP 共享这三个
值, 无论打包形式 (.app 容器、.zip 包、或独立文件)。

缺失元数据时, `bundle_name` 和 `version_code` 回退到 `package_path` (每包唯一),
确保不会产生误分组。

流程:

```
                    all_results[]
                         |
              按 (bundle_name, version_code, version_name) 分组
              缺失字段回退到 package_path
                         |
              +----------+-----------+
              |                      |
         组大小 >= 2            组大小 == 1
              |                      |
              v                      v
     +------------------+     不做聚合
     | 同一应用版本      |     (保持逐 HAP 结果)
     | member_idxs[]    |
     +------------------+
              |
    从所有成员收集:
      app_bundles = bundled_openssl_files
                  + 静态提供者 (高/中置信度)
      app_providers = {member_idx: {provider .so 名称}}
              |
    对每个 System-Link 成员:
      sibling_provs = 其他成员的提供者 (排除自身)
      使用 extra_bundled + sibling_providers 重新分类
              |
         +----+----+
         |         |
      解析为     仍为
      Self-     System-
      Contained Link
         |         |
         v         v
    In-APP-Link  不变
```

两条解析路径可将 System-Link 升级为 In-APP-Link:

| 路径 | 机制 | 示例 |
|------|------|------|
| Stem 匹配 | 兄弟打包了独立的 `libcrypto.so.3`, 通过 `_lib_stem()` 比较解析消费者的 `DT_NEEDED: libcrypto.so.3` | feature.hap 携带 `libcrypto.so.3`, entry.hap 链接它 |
| Provider 匹配 | 兄弟有 `libfoo.so` 内置静态 OpenSSL (高/中置信度), 消费者的 `DT_NEEDED: libfoo.so` 由 `_deps_include_provider()` 解析 | feature.hap 携带 `libfoo.so` (内部静态 OpenSSL), entry.hap 的 `libapp.so` DT_NEED `libfoo.so` |

约束规则:
- 按语义标识 `(bundle_name, version_code, version_name)` 分组
- 缺失 `bundle_name` 或 `version_code` 时回退到 `package_path` (不会误分组)
- 至少 2 个成员才进行聚合 (单成员组不变)
- 低置信度的静态提供者被排除
- 排除自身提供者 (HAP 不能解析自己的 System-Link)
- 不修改输入分类列表 (返回新列表)

### 7.2 汇总 XLSX

`generate_hap_summary()` 输出:

| 列名 | 内容 |
|------|------|
| Package Name | bundle_name 或文件名 |
| Type | hap/har/hsp/app/zip |
| Version | version_name |
| ABI | 逗号分隔 |
| .so Files | native 库数量 |
| OpenSSL Usage | None / System-Link / In-APP-Link / Bundled / Bundled (static) / Bundled (static, shared) |
| Detection | Dynamic / Static / dlopen / Mixed |
| Static Symbols | 每包静态符号数 |
| Dynamic Symbols | 每包动态符号数 |
| dlopen Symbols | 每包 dlopen 符号数 |
| Total Symbols | 每包总符号数 |
| Top Category | 最多使用的分类 |
| ssl_core | ssl_core 分类符号数 |
| crypto_evp | crypto_evp 分类符号数 |
| crypto_x509 | crypto_x509 分类符号数 |
| crypto_ec | crypto_ec 分类符号数 |
| crypto_hash | crypto_hash 分类符号数 |
| crypto_sm | crypto_sm 分类符号数 |
| crypto_bio | crypto_bio 分类符号数 |
| Other Cats | 其余分类合计 |
| dlopen Libs | 检测到的库名 |
| Custom Match | 非 OpenSSL 库匹配 (如 "mbedTLS (167)") |

TOTAL 行使用算术求和 (每列 = 各包对应值之和), 使 Excel 用户看到
TOTAL = SUM(可见行), 符合电子表格直觉。

### 7.3 `hap-summary` 子命令

从已有 JSON 报告重新生成 summary.xlsx, 无需重新扫描:

```
收集 *.json -> load_scan_result_from_json() -> generate_hap_summary()
```

## 8. 文件名冲突

三层去重:

1. **嵌套包名**: 同一 ZIP 内同名条目自动加后缀 (`entry_2.hap`)
2. **输出文件**: `resolve_hap_output_names()` 确保输出路径唯一
3. **容器展开**: `plan_packages()` 为内部包添加容器前缀 (`bundle_entry.hap`)

## 9. OpenSSL 检测

### 内置库检测

匹配 `OPENSSL_LIBRARY_PATTERNS` (basename 前缀):
`libcrypto.`, `libcrypto-`, `libcrypto_`, `libssl.`, `libssl-`, `libssl_`,
`libcrypto_openssl`, `libssl_openssl`, `libopenssl`,
`libboringssl`, `libboringcrypto`

扫描前从提取目录中**删除**匹配的库, 避免扫描 OpenSSL 本身产生大量自引用符号。

### 三种检测方式

| 方式 | 机制 |
|------|------|
| Dynamic | `.dynsym` UND 符号 vs OpenSSL 导出表 |
| Static | 版本字符串 + 佐证符号 + `-fvisibility=hidden` |
| dlopen | 字符串聚类 + 反汇编交叉验证 |

## 10. 错误处理

| 场景 | 行为 |
|------|------|
| module.json 缺失/格式错误 | 空元数据, 继续处理 |
| 无效 ZIP 条目 / BadZipFile | 警告, 跳过 |
| 架构不匹配 | 警告, 仍然提取 |
| 超出大小限制 | 删除部分文件, 抛出异常 |
| 无 native 库 | 返回空结果 |
| 路径穿越 | 警告, 跳过 |
| 超出最大嵌套深度 | 警告, 按扁平包处理 |

清理: `HapExtractor.cleanup()` 递归删除临时目录;
`cmd_hap()` 在 finally 中清理容器临时文件。

## 11. 性能

- **即时提取 (JIT)**: 每次只提取一个包, 避免内存膨胀
- **包间串行, 文件并行**: 包间串行控制内存;
  包内 `.so` 通过 `ProcessPoolExecutor` 并行分析
- **内置库移除**: 跳过 libcrypto/libssl 避免无效扫描
- **分析提前退出**: 无 dlopen/dlsym 则跳过 dlopen 分析;
  无原始匹配则跳过聚类 + 反汇编

## 12. 文件映射

```
src/openssl_scanner/
  hap_extractor.py          extract / _extract_single / _extract_app / _extract_zip
                            _safe_extract_member / _detect_openssl / find_packages
                            cleanup / parse_metadata
  hap_report.py             plan_packages / extract_pkg_entry / merge_hap_results
                            resolve_hap_output_names / hap_write_single_report
                            collect_bundled_names / detect_static_providers
                            classify_hap_detection / aggregate_app_classification
                            build_hap_summary_row / generate_hap_summary
                            load_scan_result_from_json
                            _lib_stem / _dt_needed_resolved / _dlopen_targets_resolved
                            _deps_include_provider
  __main__.py               cmd_hap / cmd_hap_summary
  constants.py              OPENSSL_LIBRARY_PATTERNS
  scanner.py                Scanner.scan_directory / _build_file_result
  custom_matcher.py         CustomMatcher / scan_file / scan_directory
  elf_analyzer.py           extract_rodata_strings (custom_matcher 共用)

tests/
  test_hap_extractor.py
  test_hap_integration.py
  test_custom_matcher.py
  test_reporter.py
```
