# 设计与数据格式

本文定义实际实现的命令、模块、同步协议和本地格式。用户可见功能与行为见 [req.md](req.md)，尚未实现的增量优化研究见 [incremental.md](incremental.md)。

## 结构与命令

唯一入口 `main.py` 委托 `advisories.cli`；全部应用代码位于 `advisories/`，源插件在 `advisories/sources/`。测试在 `tests/`，质量脚本在 `scripts/`。默认路径相对项目根解析，不依赖调用者工作目录。

| 命令 | 输入与作用 | 输出及状态影响 |
| --- | --- | --- |
| `update` | `--product` 逗号分隔 ID，`--min-severity` 默认 high，`--sources` 选择源，`--days` 默认3；`--since`/`--history` 控制回溯 | 更新同步缓存和所选产品 catalog；stdout 为一行结果，stderr 为进度、逐源统计、错误；不修改摘要历史 |
| `summary` | catalog；默认 high、近3天；可再筛产品/等级/时间；`--history` 取消时间窗口 | Markdown 产品表；默认更新已展示历史，重复无变化 stdout 为空；`--all` 不读写历史，`--shown` 仅读历史 |
| `detail` | 必须一个产品和确切 `--severity`，默认近3天 | 该产品该级别时间范围内缓存活跃漏洞的 Markdown，不读写展示历史 |

三者都有 `--products`、`--state`、`--output`；summary 另有 `--dedup-history`。退出码 0 成功，1 更新部分来源失败，2 参数或整体错误。输出文件不得覆盖配置、主状态、进度或所使用的展示历史。

## 文件清单及通用约定

所有运行时 JSON 为 UTF-8；写入时缩进2格、保留非 ASCII 字符、结尾换行。时间为 ISO8601，内部生成时间带 UTC `Z` 或 `+00:00`；保留外部时间原格式（NVD 无时区按 UTC 解释）。字典键、产品 ID、漏洞编号和哈希均为字符串。计数为非负整数。未知外部时间可为 null/缺省。严重性为 `critical/high/medium/moderate/low/none/unknown`，moderate 比较时等于 medium。

| 文件 | 格式与生命周期 |
| --- | --- |
| `products.json` | 产品对象数组；用户配置 |
| `state.json` | 主缓存对象，`version:1`；同步状态、收录目录、OSV 详情缓存、最后一次统计 |
| `<state路径>.cve-progress.json` | CVE 可续传批次对象；每100条原子保存，主状态写入成功后清理成功的 CVE 任务进度 |
| `dedup-history.json` | `version:2` 摘要展示历史；只记录成功展示 |
| `<原路径>.lock` | 空/无业务内容的文本文件，进程通过文件描述符 flock 排他锁协调读写；文件存在不等于锁被持有 |
| `<原路径>.new` | JSON 原子替换的临时文件，与目标 JSON 同格式；失败后可能残留，不作为缓存读取 |
| `--output` 路径 | update 为文本，summary/detail 为 Markdown，不作为状态回读 |

JSON、lock、Python 字节码和 `.venv/` 被 Git 忽略。`pyproject.toml` 是 uv 项目/依赖配置，`uv.lock` 为 uv 生成的 TOML 锁文件（同样忽略），不是漏洞状态。Makefile 定义开发命令，不保存业务数据。

## 产品配置对象

```json
[
  {
    "id": "uv",
    "label": "uv / uvx",
    "repositories": ["astral-sh/uv"],
    "packages": [{"ecosystem": "PyPI", "name": "uv"}],
    "keywords": ["uv", "uvx", "astral-sh/uv"],
    "nvd_keywords": ["astral uv"],
    "vendors": ["astral"]
  }
]
```

- `id`：稳定唯一产品标识，命令行使用此值；`label`：显示名，可缺省。
- `repositories`：GitHub `owner/repo` 字符串数组；`packages`：`{ecosystem,name}` 数组，可为空；`keywords`：产品候选发现与身份匹配名称数组。
- `nvd_keywords`：可选，覆盖 NVD 自动关键词合并策略。
- `vendors`：可选厂商名称数组；`vendor_aliases`：可选厂商别名数组，提供时优先于 vendors。
- PyPI、Go、npm、crates.io 是当前配置使用的生态。GHSA 映射为 pip/go/npm/rust；PyPI 包比较按 `[-_.]+` 合并、转小写，crates.io 比较忽略大小写及下划线/连字符差异。

## 主状态对象

```json
{
  "version": 1,
  "units": {
    "ghsa:uv": {
      "checkpoint": "2026-10-29T12:00:00Z",
      "collection_hash": "sha256-hex",
      "records": {"GHSA-example": "NormalizedRecord（下文定义）"}
    },
    "cve": {
      "checkpoint": "2026-10-29T12:00:00Z",
      "collection_hash": "sha256-hex",
      "records": {"CVE-2026-1234": "NormalizedRecord"},
      "cve_seen": {"CVE-2026-1234": "Inspection（下文定义）"},
      "coverage": {"uv": {"checkpoint": "2026-10-29T12:00:00Z", "collection_hash": "sha256-hex"}}
    }
  },
  "catalog": {
    "uv": {
      "records": ["MergedRecord（下文定义）"],
      "min_severity": "high",
      "updated_at": "2026-10-29T12:00:00+00:00",
      "errors": []
    }
  },
  "source_caches": {
    "osv": {"details": {}, "indexes": {}}
  },
  "last_update": {
    "generated_at": "2026-10-29T12:00:00+00:00",
    "elapsed_seconds": 1.23,
    "sources": {"osv": "SourceStatistics（下文定义）"},
    "errors": []
  }
}
```

示例中的类型名称是占位说明，实际值为对应对象。`units` 必须存在；`catalog/source_caches/last_update` 可缺省。一个普通 unit 对应 `source:product_id`；CVE 使用全局 `cve`。GHSA/OSV 虽批量请求，仍保存原有 per-product unit，不迁移成一个全局检查点。

Unit 的 checkpoint 仅在该任务完整成功后更新，表示本次查询的开始时刻，防止执行期间的新变化被越过；records 是按来源主 ID 索引的最新规范化证据。通常按 ID 覆盖合并；OSV 成功读取完整包索引后替换所选产品的 OSV records，索引中消失的项不再作为该源当前结果。批量源整批失败时，不提交任何产品检查点或详情缓存。

catalog 按产品保存已确认归属且达到门槛的活跃漏洞，只替换本次选中的产品。errors 是 `{source:字符串,error:字符串}` 数组；目前本轮源错误附在本轮所选产品目录上，保守提示数据可能过期。同步 records 可含低于收录门槛的证据，显示层只能读取 catalog。

## NormalizedRecord：来源证据

```json
{
  "id": "GHSA-example",
  "aliases": ["CVE-2026-1234"],
  "products": ["uv"],
  "title": "Advisory title",
  "description": "Original advisory text",
  "severity": "high",
  "scores": [{"source":"GitHub","version":"3.1","score":8.8,"vector":"CVSS:3.1/..."}],
  "published": "2026-10-27T12:00:00Z",
  "modified": "2026-10-29T10:00:00Z",
  "url": "https://github.com/advisories/GHSA-example",
  "affected": [],
  "withdrawn": false,
  "kind": "vulnerability",
  "references": [],
  "match_basis": "exact-package"
}
```

`id/products/severity/kind` 在采集归一化时校验；其他字段由适配器提供，未知文本通常为空字符串，未知时间为 null/缺省。kind 为 vulnerability 或旧版 security-release；release 不计入漏洞目录。match_basis 为 exact-package、exact-repository、keyword-candidate、product-description-or-reference 等来源声明，调度器赋值。来源声明不是本机利用判定。

scores 保留多来源：通常 `{source,version,score:number,vector:string|null}`；OSV 也可能是 `{type:"CVSS_V3",score:"CVSS:3.1/..."}`，不得假定 score 总为数字。references 保留字符串 URL 或来源给出的引用对象。

affected 保留来源结构，不统一扁平化：

| 来源 | 结构与使用字段 |
| --- | --- |
| GHSA/项目 | `[{package:{ecosystem,name}, vulnerable_version_range, first_patched_version, patched_versions, vulnerable_functions}]`；两个修复字段按接口存在其一，first_patched_version 可为字符串或 `{identifier}` |
| OSV | `[{package:{ecosystem,name,purl?}, ranges:[{type,repo?,events:[{introduced}|{fixed}|{last_affected}|{limit}]}], versions:[string], ecosystem_specific?, database_specific?}]` |
| CVE | `[{vendor,product,platforms?,versions:[{version,status,lessThan?,lessThanOrEqual?,versionType?,changes?}],defaultStatus?,...}]`；保留 CNA/ADP 各容器内容 |
| NVD | `[{operator?,negate?,nodes:[{operator,negate,cpeMatch:[{vulnerable,criteria,versionStartIncluding?,versionStartExcluding?,versionEndIncluding?,versionEndExcluding?,matchCriteriaId?}]}]}]` |

不识别的来源扩展字段保留在原结构中；提取器不把未识别信息伪装成已理解的修复建议。

## MergedRecord：跨来源漏洞

字段：`id`（优先 CVE）、`aliases`（包含主编号的完整编号数组）、`products`、`severity`（各源最高）、`withdrawn`、`withdrawal_conflict`、`needs_review:true`、`evidence`、`fingerprint`。

evidence 为 `[{source:unit_key,...NormalizedRecord}]`。用传递闭包合并别名；同一编号不同源证据保留。官方 CVE/NVD rejected 优先认定撤回，否则所有证据撤回才整体撤回。catalog 中 products 被收窄到单产品数组。

fingerprint 为稳定 JSON（键排序、紧凑分隔、UTF-8）的 SHA-256 十六进制；内容含来源、ID/别名/产品、规范化空白后的标题/正文、评级、评分、affected、withdrawn、kind，不含时间和独立引用列表。

## OSV 共享详情与索引缓存

```json
{
  "details": {
    "GHSA-example": {
      "modified": "2026-10-29T10:00:00Z",
      "record": {"id":"GHSA-example","modified":"2026-10-29T10:00:00Z","aliases":[],"affected":[]}
    }
  },
  "indexes": {
    "PyPI:uv": {"GHSA-example":"2026-10-29T10:00:00Z"}
  }
}
```

位于 `source_caches.osv`。details.record 是未经归一化的完整 OSV 对象（包括 summary/details/severity/published/withdrawn/references 等实际返回字段），同一 ID 在多个产品间共享。details.modified 使用实际详情中的 modified，不用较旧索引时间覆盖。比较时统一 UTC 到索引提供的微秒精度：索引可能为6位小数，详情为9位，不能把格式精度差异误当更新。超出该精度后索引/详情版本仍不一致时下一轮重新检查。

每轮 querybatch 查询选中产品的准确包，单批最多100个查询。结果只含 ID/modified，按每个包独立 token 分页；循环 token、响应数量不匹配或缺 ID/modified 均失败。只对新 ID 或 modified 不同的 ID 请求详情。成功完整索引替换所选包 indexes，其他包缓存保留。分页 token 不持久化为跨轮游标。当前未对不再配置的历史详情做垃圾回收。

## 检查点与配置指纹

collection_hash 只描述采集身份，不包括 min_severity、显示名、本次选择的其他产品或产品列表顺序。hash 输入为 `{source,product:product_id,config:{所需字段}}`，使用上述 SHA-256 规则。

| 源 | 单产品相关配置 |
| --- | --- |
| GHSA/OSV | packages |
| 项目 | repositories |
| NVD | keywords、nvd_keywords |
| CVE/其他源 | packages、repositories、keywords、vendors、vendor_aliases |

相关配置变更或无检查点时使用 `until-days`；否则 `checkpoint-overlap_days`。显式 since 优先；history 对支持全历史的源置 since=null。源失败不推进检查点。

GHSA 按生态、起始 UTC 日期分组，每组最多20个包名，使用 affects=包名1,包名2（不能发送重复同名 affects 参数，实测会只匹配最后一项），每请求最多100条；modified 为起始日期到本次日期的闭区间，日期精度会重叠而非漏边界。按返回 vulnerabilities.package 的准确生态/包名映射产品，不把整批公告标给所有产品。

CVE 的 coverage 保存每产品独立 checkpoint/hash，取本次所选产品最早需要覆盖的起点读取日志；只选部分产品或改变等级不会重置其他产品的覆盖状态。新增产品/匹配配置变化需重新检查其窗口内的详情。全局 collection_hash/批次 config_hash 为排序后的 `(product_id,CVE产品hash)` 数组的哈希，保证顺序无关且不含级别。

## CVE Inspection 与批次文件

```json
{
  "modified": "2020-01-01T00:00:00Z",
  "checked_at": "2026-10-29T12:00:00Z",
  "products": {"uv":"product-collection-hash"}
}
```

`cve_seen[CVE_ID]` 保存上述 Inspection。modified 是上游公告版本，checked_at 是本地成功检查时刻，products 表示该版本已按哪些产品配置检查。清理依据 checked_at 与日志覆盖起点，不能用 modified 清理：旧公告可能最近才入库。版本变化时只保留此次重新检查的产品哈希；其他产品下一次仍需检查。旧版 `ID:时间字符串` 没有作用域与本地检查时间，安全地重新下载一次，成功后转新结构。

批次文件：`{config_hash:string, records:[NormalizedRecord], seen:{CVE_ID:Inspection}}`，没有单独 version 字段。config_hash 匹配才加载。每100条保存成功检查项和相关 records；相关记录按 ID 去重，非关注正文不保留。批次中某条失败仍先保存成功项，然后报告失败；进度文件不表示源完整成功，也不推进 coverage。HTTP 工作线程共享该源的统计归属。

## 展示历史与 Markdown 格式

```json
{"version":2,"records":{"uv:CVE-2026-1234":{"fingerprint":"sha256-hex"},"uv:GHSA-example":{"fingerprint":"sha256-hex"}}}
```

键为 `product_id:advisory_alias`，所有别名都登记。展示 fingerprint 与合并指纹不同：排除 ID、别名、纯编号标题、时间、独立引用列表，保留来源及有效内容、汇总级别和撤回状态；防止只新增 CVE 编号就重复显示。只在输出成功后更新实际展示项。旧 version:1 历史无法证明按产品展示，视为新历史并在下一次成功展示时写 version:2；其他未知版本报错。

summary Markdown 表列为：产品、Critical、High、受影响版本/组件、公告修复版本、证据标签。计数基于本次选择项；空结果返回空字符串。detail Markdown 按漏洞分节，列别名/级别/标签、版本证据表，再按来源展示时间、评分 JSON、URL、引用格式正文和 affected JSON。

版本提取支持前述主要结构；CPE 排除上界不直接等同修复版；Chrome 正文明确 prior to VERSION 可补充修复边界。项目 patched_versions 和全局 first_patched_version 均支持。保留分支/平台；无法确认时标未知，不靠版本字符串大小合并成“全部修复版本”。

标签由保守文本规则提取，当前标签集含 RCE、Code Execution、Crash、DoS、UAF、Sandbox Escape、Privilege Escalation、File Read、File Write。否定语句过滤，未做 AI 推断；不保证完整攻击链识别。表格转义竖线与换行，正文作为引用，不执行其中内容。

## SourceStatistics 与诊断输出

每次 update 的 `last_update.sources[source]` 包含以下整数计数。只保存最后一轮，不无限累计；stdout 仍为更新摘要，逐源统计写 stderr。

| 字段 | 含义 |
| --- | --- |
| requests | HTTP 尝试数，包含重试和 requests 自动重定向；连接失败的尝试也计数 |
| response_bytes | 收到并读取的响应正文**解压后**字节数，包括 HTTP 错误正文和重定向正文；不是 TLS/HTTP 头或线上压缩字节量 |
| retries | 初次尝试之外的重试次数 |
| http_errors | HTTP >=400 或网络异常次数；JSON 内容无效由源错误报告，不计为 HTTP 错误 |
| cache_hits | OSV 已缓存详情跳过 GET 的 ID 数；CVE 已检查同版本且覆盖选中产品而跳过详情的 ID 数；不是连接复用次数 |
| not_modified | 收到 HTTP 304 的次数；本轮没有实现 ETag 正文缓存，正常应为0 |
| new | 来源返回的 `(产品unit,ID)` 此前不存在的条数；CVE 按全局 unit 计 |
| changed | 同一 unit/ID 的有效内容指纹变化条数，不含纯时间/独立引用变化 |
| removed | 完整 OSV 包索引成功刷新后从该产品源记录中移除的条数 |
| unchanged | 本轮源返回但有效内容未变化的条数；CVE 跳过下载的条目计 cache_hits，不重复计这里 |

共享公告映射多个产品时 new/changed/unchanged 可以多次计数，HTTP 和 OSV 详情缓存命中按实际请求/ID计一次。统计用于比较网络开销与本地记录变化，不用于判断已通知。失败批次的网络消耗照常统计，检查点和共享缓存仍不提交。

## 原子性、兼容与工程约束

源接口保持 `collect(client,product,since,until,context) -> {records,metadata}`。可声明 `BATCH=True` 并实现 `collect_many(client,contexts,until,cache) -> (按产品ID的结果映射,新共享缓存)`，调度器合并网络请求但独立保存产品 unit。OSV 结果另带 `replace_records:true`。metadata 不允许覆盖 records/checkpoint/config_hash/collection_hash。成功提交只在主调度线程，避免并发修改主状态。

JSON 通过同目录 `.new` 写入后 replace；状态/摘要历史分别原子，跨文件不保证事务。所有命令锁 state，summary 使用历史时还锁历史。HTTP 每工作线程独立 Session，结束关闭；代理/凭据不写入缓存。更新失败仍保存成功源、统计和错误。

主状态 version:1 的扩展字段向后兼容。旧 unit.config_hash 是旧的全局指纹，不可当新 collection_hash：第一次迁移按回溯窗口重新建立覆盖，此后不因选中列表/等级变化重置。未知旧扩展字段可保留但不参与新逻辑。无 catalog 的旧缓存需先 update；不会由显示命令隐式导入。

Python >=3.10，uv 管理依赖，Make 管理验证。质量门限覆盖全部源码/测试/脚本：McCabe <=10、认知复杂度 <=15、每文件 MI >=30。测试包括批量分页/正确包名映射、共享详情复用、失败不提交、检查点隔离、CVE 延迟入库/范围变化、HTTP 字节/重试统计及三个显示命令行为。

## 日志与版本范围合并

应用诊断统一使用标准 logging，CLI 默认 INFO，StreamHandler 默认 stderr，格式为级别、模块名、消息；不覆盖调用方已配置的 handler。stdout 仅保留命令结果，--output 仍控制结果文件，不重定向日志。

摘要的受影响范围与公告修复版本按产品、组件/平台标签隔离合并。纯数字点分版本支持比较运算、逗号连接的交集和 || 连接的并集：例如 >=1, >=2 化为 >=2；不同公告的范围取并集，>=1 与 >=2 合并为 >=1。重叠或无空隙的区间合并，开闭边界及空隙保留。版本尾零等价比较，显示保留公告中的版本写法。组件标签使用 casefold 统一大小写。Chrome 采用稳定版本累计修复策略：同一组件/平台标签内的纯数字修复版本按数字元组取最大值，作为本次摘要的升级目标；明确区分的分支标签独立处理。其他产品的离散修复版本仍保留，不默认套用累计修复策略。未知修复信息的警告保留，结果不保证覆盖未收录漏洞。预发布、通配符、文字修饰及矛盾条件不猜测语义，原样保留；详情保留逐源原始证据。

Detail 支持互斥的 --days（默认3，正有限数）、--since（ISO 时间，无时区按 UTC）、--history（取消时间限制）。任一来源的 published/modified 落在起点至当前 UTC 时间的闭区间即可；未知或未来时间不命中普通窗口。输出标明实际起止时间或全部历史，不读取展示去重历史。
