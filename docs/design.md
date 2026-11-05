# 设计与数据格式

本文定义实际实现的命令、模块、同步协议和本地格式。用户可见功能与行为见 [req.md](req.md)，剩余功能及优化见 [tasks.md](tasks.md)。

## 结构与命令

唯一入口 `main.py` 委托 `advisories.cli`；全部应用代码位于 `advisories/`，源插件在 `advisories/sources/`。测试在 `tests/`，质量脚本在 `scripts/`。默认路径相对项目根解析，不依赖调用者工作目录。

| 命令 | 输入与作用 | 输出及状态影响 |
| --- | --- | --- |
| `update` | `--product` 逗号分隔 ID，`--min-severity` 默认 high，`--sources` 选择源，`--days` 默认3；`--since`/`--history` 控制回溯 | 更新同步缓存和所选产品 catalog；stdout 为一行结果，stderr 为进度、逐源统计、错误；不修改摘要历史 |
| `summary` | catalog；默认 critical、近3天；可再筛产品/等级/时间；`--history` 取消时间窗口 | Markdown 产品表；默认更新已展示历史，重复无变化 stdout 为空；`--all` 不读写历史，`--shown` 仅读历史 |
| `detail` | 必须一个产品，`--severity` 可选，默认 high + critical，默认近3天 | 该产品该级别时间范围内缓存活跃漏洞的 Markdown，不读写展示历史 |

三者都有 `--products`、`--state`、`--output`；summary 另有 `--dedup-history`。退出码 0 成功，1 更新部分来源失败，2 参数或整体错误。输出文件不得覆盖配置、主状态、进度或所使用的展示历史。

## 文件清单及通用约定

所有运行时 JSON 为 UTF-8；普通 JSON 写入时缩进2格、保留非 ASCII 字符、结尾换行。压缩 HTTP 缓存使用紧凑 JSON。时间为 ISO8601，内部生成时间带 UTC `Z` 或 `+00:00`；保留外部时间原格式（NVD 无时区按 UTC 解释）。字典键、产品 ID、漏洞编号和哈希均为字符串。计数为非负整数。未知外部时间可为 null/缺省。严重性为 `critical/high/medium/moderate/low/none/unknown`，moderate 比较时等于 medium。

| 文件 | 格式与生命周期 |
| --- | --- |
| `products.json` | 产品对象数组；用户配置 |
| `state.json` | 主缓存对象，`version:1`；同步状态、收录目录、OSV 详情缓存、最后一次统计 |
| `<state所在目录>/http-cache.json.gz` | 独立 gzip HTTP 缓存，内部为 `{version:1, entries:{缓存键:缓存项}}`；可删除重建，仅 update 读取 |
| `<state路径>.cve-progress.json` | CVE 可续传批次对象；每100条原子保存，主状态写入成功后清理成功的 CVE 任务进度 |
| `history.json` | `version:2` 摘要展示历史；只记录成功展示 |
| `<state所在目录>/advisories.lock` | 空/无业务内容的文本文件，进程通过文件描述符 flock 排他锁协调读写；文件存在不等于锁被持有 |
| `<原路径>.new` | JSON 原子替换的临时文件，与目标 JSON 同格式；失败后可能残留，不作为缓存读取 |
| `--output` 路径 | update 为文本，summary/detail 为 Markdown，不作为状态回读 |

JSON、运行时 lock、Python 字节码和 `.venv/` 被 Git 忽略，uv.lock 例外放行。`pyproject.toml` 是 uv 项目/依赖配置，`uv.lock` 为 uv 生成的 TOML 依赖锁文件（纳入版本控制），不是漏洞状态。Makefile 定义开发命令，不保存业务数据。

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

- `min_version`：可选的纯数字点分版本字符串（如 `"1.106.6"`），缺省或 null 不过滤。仅 summary 校验并使用，非法值报错；不参与采集指纹、检查点或缓存。按受影响范围与 `[min_version, +∞)` 是否可能相交过滤，不是单点版本检测。所有有效来源均须提供匹配产品的可理解范围且完全低于门限，才隐藏。支持数字 GHSA 比较区间、OSV SEMVER/ECOSYSTEM 事件和显式版本、CVE 数字范围、NVD CPE 数字边界；预发布、Git 范围、CVE changes/custom/defaultStatus=affected、未知或缺失信息保守保留。仅依赖修复版本不能隐藏。撤回证据不参与判断；历史在过滤后按原规则处理，修改门限不清空历史，`--all`/`--shown` 仍应用门限。summary 的 `--ignore-min-version`（默认 false）跳过本次最低版本校验和过滤，可与这些选项组合；不写配置，不改变等级、时间和历史语义。
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

字段：`id`（优先 CVE）、`aliases`（包含主编号的完整编号数组）、`products`、`severity`（未撤回来源最高，无有效来源时 unknown）、`withdrawn`、`withdrawal_conflict`、`needs_review:true`、`evidence`、`fingerprint`。

evidence 为 `[{source:unit_key,...NormalizedRecord}]`。用传递闭包合并别名；同一编号不同源证据保留。官方 CVE/NVD rejected 优先认定撤回，否则所有证据撤回才整体撤回。catalog 中 products 被收窄到单产品数组。

产品归属扫描跳过明确 `vulnerable:false` 的节点。未撤回证据才参与归属、评级、版本、标签、时间筛选和展示指纹；原始 evidence 及同步指纹仍完整保留，detail 仅使用活跃来源生成简洁结论。官方 rejected 的整体撤回优先级不变。已有 catalog 在下次 update 时按新规则重建。

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

summary 直接输出 Markdown 表格，不输出标题或前置说明段落。表列为：产品、Critical、High、受影响版本/组件、公告修复版本、证据标签。计数基于本次选择项；空结果返回空字符串。detail Markdown 在时间范围后按漏洞 ID 列出描述，选择首个具有非空 description 的活跃来源，以引用保留原文段落；无描述显示“暂无原始描述”。不拼接多个来源，不序列化证据对象。末尾使用六列表格：漏洞 ID、威胁级别、公告时间、受影响版本、后果、原始链接。版本按组件合并重复范围并分行展示，可解析的 CPE 展示版本及更新标记；后果使用已有保守标签规则，排除 UAF 等缺陷类型并翻译为中文，无结论显示未知。链接取首个有 URL 的活跃来源。默认筛选 high/critical 派生优先级，显式 severity 仍精确匹配；本地格式不变。

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
| not_modified | 收到 HTTP 304 的次数；配合持久化正文缓存统计实际304 |
| new | 来源返回的 `(产品unit,ID)` 此前不存在的条数；CVE 按全局 unit 计 |
| changed | 同一 unit/ID 的有效内容指纹变化条数，不含纯时间/独立引用变化 |
| removed | 完整 OSV 包索引或项目完整核对成功后从该产品源记录中移除的条数 |
| unchanged | 本轮源返回但有效内容未变化的条数；CVE 跳过下载的条目计 cache_hits，不重复计这里 |

共享公告映射多个产品时 new/changed/unchanged 可以多次计数，HTTP 和 OSV 详情缓存命中按实际请求/ID计一次。统计用于比较网络开销与本地记录变化，不用于判断已通知。失败批次的网络消耗照常统计，检查点和共享缓存仍不提交。

## 原子性、兼容与工程约束

源接口保持 `collect(client,product,since,until,context) -> {records,metadata}`。可声明 `BATCH=True` 并实现 `collect_many(client,contexts,until,cache) -> (按产品ID的结果映射,新共享缓存)`，调度器合并网络请求但独立保存产品 unit。OSV 结果另带 `replace_records:true`。metadata 不允许覆盖 records/checkpoint/config_hash/collection_hash。成功提交只在主调度线程，避免并发修改主状态。

JSON 通过同目录 `.new` 写入后 replace；状态/摘要历史分别原子，跨文件不保证事务。所有命令在读取或写入业务数据前，仅获取状态文件所在目录的 advisories.lock，使用 LOCK_EX | LOCK_NB；冲突立即退出，异常或正常返回均随文件描述符关闭释放，不删除锁文件。summary --all 和 detail 也获取同一个锁；不同状态文件名但相同目录仍互斥。独立目录不得交叉共享业务文件。旧的逐文件 .lock 不再使用。HTTP 每工作线程独立 Session，结束关闭；代理/凭据不写入缓存。更新失败仍保存成功源、统计和错误。

主状态 version:1 的扩展字段向后兼容。旧 unit.config_hash 是旧的全局指纹，不可当新 collection_hash：第一次迁移按回溯窗口重新建立覆盖，此后不因选中列表/等级变化重置。未知旧扩展字段可保留但不参与新逻辑。无 catalog 的旧缓存需先 update；不会由显示命令隐式导入。

Python >=3.10，uv 管理依赖，Make 管理验证。质量门限覆盖全部源码/测试/脚本：McCabe <=10、认知复杂度 <=15、每文件 MI >=30。测试包括批量分页/正确包名映射、共享详情复用、失败不提交、检查点隔离、CVE 延迟入库/范围变化、HTTP 字节/重试统计及三个显示命令行为。

## 日志与版本范围合并

应用诊断统一使用标准 logging，CLI 默认 INFO，StreamHandler 默认 stderr，格式为级别、模块名、消息；不覆盖调用方已配置的 handler。stdout 仅保留命令结果，--output 仍控制结果文件，不重定向日志。

摘要的受影响范围与公告修复版本按产品、组件/平台标签隔离合并。纯数字点分版本支持比较运算、逗号连接的交集和 || 连接的并集：例如 >=1, >=2 化为 >=2；不同公告的范围取并集，>=1 与 >=2 合并为 >=1。重叠或无空隙的区间合并，开闭边界及空隙保留。版本尾零等价比较，显示保留公告中的版本写法。组件标签使用 casefold 统一大小写。Chrome 采用稳定版本累计修复策略：同一组件/平台标签内的纯数字修复版本按数字元组取最大值，作为本次摘要的升级目标；明确区分的分支标签独立处理。其他产品的离散修复版本仍保留，不默认套用累计修复策略。未知修复信息的警告保留，结果不保证覆盖未收录漏洞。预发布、通配符、文字修饰及矛盾条件不猜测语义，原样保留；详情保留逐源原始证据。

Detail 支持互斥的 --days（默认3，正有限数）、--since（ISO 时间，无时区按 UTC）、--history（取消时间限制）。任一来源的 published/modified 落在起点至当前 UTC 时间的闭区间即可；未知或未来时间不命中普通窗口。输出标明实际起止时间或全部历史，不读取展示去重历史。

## 分通道调度与限流

调度队列为 cve、github（ghsa+project）、nvd、osv。CVE 首先提交，每通道最多一个活跃采集任务，完成或失败后再提交该通道下一任务。--jobs（默认6）限制外层工作线程，四个内置通道最多同时4任务，jobs=1仍可执行。CVE 的 --workers 默认8，独立限制详情下载线程。

主调度线程仍负责状态提交。GitHub API 请求另有共享互斥，覆盖 CVE release 元数据查询，避免与 GHSA/project 重叠。每线程 Session 继续复用。限流冷却按主机存于内存：Retry-After 优先，其次 GitHub remaining=0/reset；429或明确限流403默认至少60秒退避。重试最多3次，耗尽后冷却仍约束后续任务；普通403不重试，5xx保留指数退避。NVD 请求间隔限速不变。

## HTTP 条件缓存格式

HTTP 缓存存于 `<state所在目录>/http-cache.json.gz`，主状态不再包含 http_cache 正文。新文件不存在时兼容读取旧 `<state路径>.http-cache.json.gz`，后续保存只写新名称。同目录的状态共享 HTTP 缓存，所有命令使用同一目录锁，防止并行覆盖；需完全隔离时使用不同目录。旧版内嵌 http_cache 仍可读取，存在时优先于旁文件，下一次成功保存自动迁出。旁文件缺失视为空缓存；损坏或版本不支持时记录 warning 并重新获取，离线 summary/detail 不读取旁文件。键为 URL（含编码后的参数）及请求 headers 的稳定 SHA-256；headers 包含认证上下文，只有摘要入键，令牌/完整请求头不持久化。

每个值为 {source, body, link, etag, last_modified, used_at}：

- source：ghsa/project/cve；
- body：成功解析的完整 JSON（任意 JSON 类型）；
- link：原响应 Link 字符串；
- etag/last_modified：原验证头字符串，可为 null；
- used_at：本地使用时刻，Unix 秒数（浮点）。

仅缓存 GHSA/项目 GET 和 CVE deltaLog；不缓存 POST、NVD、CVE单条和压缩包。请求优先 If-None-Match，否则 If-Modified-Since。304必须已有完整正文才能复用，分页继续使用保存的 Link。200只有完整解析成功且有验证头才保存；失败源持久化时恢复旧缓存。按 used_at 保留最近512项，不保证按字节限制。压缩文件通过同目录 `.new` 写入后原子替换，再原子保存主状态。两者不构成跨文件事务：若缓存已更新但主状态提交失败，下次最多复用较新完整 HTTP 响应，业务检查点仍以旧主状态为准，仍须处理响应。压缩写入失败时主状态不提交。旁文件路径及输出冲突在 CLI 校验，所有操作共用目录锁。

项目 unit 新增 full_checked_at（UTC ISO时间）；首次/配置变化/history/间隔7天完整核对，其他轮次 updated 倒序并在记录更新时间早于 since 时停止。完整成功使用 replace_records 替换项目来源快照，增量保留旧记录；缺失/无效更新时间不早停。

## CVE 压缩包加速与统计补充

--cve-bundle auto（默认）/off。当天版本时间落在 UTC 0点至 until 的待查记录不少于200，才读取官方 latest release 元数据。选择当天 delta ZIP，声明大小不超过16 MiB且不超过待查数×2048字节。压缩包下载后在内存解析，仅采用 ID 和 cveMetadata.dateUpdated 与待查日志一致的记录，其余仍走原单条下载。不是跨日游标，不改变日志覆盖检查或检查点。

下载限制16 MiB，ZIP声明解压总量限制128 MiB，不写解压文件；临时内存字节不持久化，不新增业务文件。格式为官方 ZIP 中的 CVE JSON 对象，读取 cveMetadata 与 containers，复用原归一化流程。失败回退单条请求，不把压缩包失败单独视为源失败。

response_bytes 仍是 HTTP 解码后正文大小：ZIP正文按ZIP字节计，不按ZIP内部解压体积计。not_modified 现在统计实际304；cache_hits仍只计跳过的OSV/CVE详情，304单独计数。removed扩展为OSV完整索引或项目完整核对移除的源记录数。压缩包复用条数写诊断日志；元数据、重定向与ZIP请求均计入CVE来源统计。


## NVD 已知漏洞复核

在正常关键词/修改时间查询后，按产品的 NVD unit 检查已有记录，每7天独立按 CVE ID 复核。查询参数 cveIds 为最多100个逗号分隔 ID，resultsPerPage=100；无关键词、等级或时间限制，仍在 NVD 串行通道及原限速下执行。本轮关键词查询已返回的记录视为已检查，不重复查询。

unit 新增可选 known_checked_at 对象：键为 CVE ID，值为最近成功接收该记录的本地 UTC ISO 时间（例如 {"CVE-2026-22812":"2026-10-29T14:00:00Z"}）。缺失字段/时间的旧记录首次复核；每次成功关键词查询或 ID 复核更新时间，与上游 modified 无关。不保存独立复核文件。

响应 totalResults 必须等于所请求 ID 数，返回 ID 必须属于请求集合且不重复；如接口分页则继续读取直到完整。空结果、缺 ID、异常响应或请求失败使该产品 NVD 任务失败，不提交本轮记录、known_checked_at 或检查点，保留旧缓存并报告可能过期。不得把查不到解释为撤回。

成功结果按 ID 覆盖旧证据，重新经过现有归属/严重性/撤回合并规则后生成 catalog。归属变化可移出该产品目录，但同步层保留证据；其他来源仍可能独立确认产品归属。只有官方 Rejected 等明确证据才按现有规则撤回。复核 HTTP 开销和记录变化计入既有 NVD 统计。

## 数据源参考

- [GitHub REST 最佳实践](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)
- [项目安全公告](https://docs.github.com/en/rest/security-advisories/repository-advisories)
- [OSV querybatch](https://google.github.io/osv.dev/post-v1-querybatch/)
- [NVD API](https://nvd.nist.gov/developers/vulnerabilities)
- [CVE 官方下载协议](https://github.com/CVEProject/cvelistV5#how-to-download-the-cve-list)

## 摘要版本的产品隔离

摘要提取版本前按结构化归属筛选：GHSA/OSV 包按生态与包名匹配配置（支持生态别名及包名规范化）；CVE 按产品名、别名及厂商匹配；NVD 按 CPE 产品及厂商匹配。已匹配产品节点内的组件、平台和范围事件继承归属，不按扁平标签猜测。明确属于其他产品的子树排除，无法确认归属的范围不进入摘要。Chrome 正文版本提取只用于 Chrome 产品。detail 按当前产品整理版本，原始证据保留在缓存；不修改缓存格式。

## CVE 检查索引共享作用域

磁盘上的 `units.cve.cve_seen_scopes` 为 `{局部引用字符串: {product_id:配置哈希}}`；`cve_seen[ID]` 为 `{modified, checked_at, products_ref:引用字符串}`。相同的整个产品/配置哈希映射只保存一次，引用从 `"0"` 起按本次编码顺序分配，写入时仅保存仍被引用的作用域。不同配置版本、不同产品子集不能共用一个映射。业务内存解码回旧 `products` 映射，不改变 inspected、清理和检查点语义。

进度文件采用同样方式：`seen_scopes` 为引用表，`seen[ID].products_ref` 指向它。引用只在所属主状态或进度文件内有效，加载后再合并，不能直接合并两份磁盘引用。旧版内嵌 products 和更早的时间字符串兼容读取；保存转为共享格式。缺失、非法引用或映射应报错，不能当作已检查。编解码不修改调用者对象，未使用的旧作用域随下一次写入回收。

## Chrome 门限兼容

Google Chrome 的 CVE 证据可能使用 `versionType: custom` 且 `version == lessThan` 重复记录修复边界。仅对 Chrome 产品、Google/Chrome 结构化节点，且同一证据正文明确写出 `Google Chrome ... prior to VERSION` 并与该边界完全一致时，门限过滤将该条解释为 `< VERSION`。不改写缓存，不推广到其他 custom 范围；changes、未知状态、其他分支和跨来源冲突仍保守保留。

Chrome 证据完全没有结构化范围（affected 缺省、空列表或仅空对象）时，可采用同一证据正文明确的 Chrome prior to 数字边界；存在非空但未知/矛盾结构时不以正文覆盖。

## KEV

kev 为批量源，一次获取 CISA 官方 JSON 全目录，本地按 dateAdded 筛选从本次 UTC 日期回退两个自然月（月底截到目标月末）至当天的闭区间，不受 --days/--since/--history 或检查点缩短。每产品使用 kev:product_id unit，成功后合并证据，窗口外旧证据保留；失败不提交任何产品检查点。部分产品更新不修改其他 unit。

vendorProject/product 转为 affected 的 vendor/product 确认归属。severity=unknown、scores=[]，不推断版本。原条目完整保存在 kev 对象；正文含 requiredAction、dueDate、勒索软件使用情况和 notes。published/modified 使用 dateAdded，代表 KEV 收录日期而非 CVE 发布时间；不使用目录发布时间冒充单条修改时间。按 CVE ID 合并。有效 KEV 证据使派生筛选优先级为 critical，原始及合并 severity 不变；无新增持久化字段。update、summary 和 detail 使用派生优先级。摘要 KEV/Critical/High 互斥计数；detail critical 包含 KEV，其他等级不重复列出。KEV 来源加入改变展示指纹，撤回 KEV 不提供优先级。最低版本判断仍保守处理未知范围，因此没有版本范围的 KEV 证据会使条目保留。HTTP 缓存沿用通用机制。

官方格式：https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json 。

## 更新取消与等待诊断

调度器每30秒记录尚未完成的任务。首次 Ctrl-C 设置 HTTP 取消事件，唤醒限流及重试等待，取消尚未启动的任务，等待在途请求返回后退出。正在执行的网络请求仍受 timeout 约束，并非强制杀线程。保存已交付成功任务及 HTTP 缓存，未完成来源标记 interrupted、保留原检查点；CVE 批次进度继续保留。update 返回130，不修改展示历史。

所有子命令共享 `-p` / `--product` 和 `-d` / `--days` 别名，分别解析为 product 和 days 字段；默认值、校验及时间参数互斥规则保持不变。

详情总表威胁级别使用合并 severity，公告时间取首个有 published 的活跃非 KEV 来源，保留原始格式；缺失显示未知，不使用更新时间代替。

summary --list 提供窄屏列表：每个软件依次输出名称、KEV/Critical/High 个数、受影响版本、公告修复版本、后果，共五行加一个空行。软件名前加 `## `，其余四行前加 `- `。长行自然折行，内容换行折叠为空格。复用产品分组、版本汇总和中文后果映射；缺失后果显示未知。筛选和展示历史规则不变，查看已展示内容可加 --all。

HTTP 缓存运行时采用写时替换：初始化仅复制索引，prepare 仅复制条目元数据，正文由旧快照与当前缓存共享并视为只读。304 更新访问时间时创建新条目，不修改旧快照；交给调用者的正文仍深拷贝，200 存入的正文也深拷贝，防止调用者修改污染缓存。输入缓存及 snapshot 返回值仅供只读使用；失败来源仍恢复旧快照。磁盘格式不变。

## SQLite 状态格式（第一版）

SQLite 后端由 .sqlite/.db 扩展名选择，需要 SQLite >= 3.45 的 JSONB 功能，启动连接时检查；不新增 Python 依赖。默认仍为 state.json，显式 --state 使用新文件。SQLite application_id=1396786244，user_version=1；逻辑状态 version 仍为1，JSON 路径与嵌套结构不变。

nodes 表：path TEXT PRIMARY KEY、kind TEXT（dict/list/value）、body BLOB（SQLite JSONB），使用普通 rowid 表以减少大 JSONB 文档的溢出页浪费。path 是键/列表下标组成的紧凑 JSON 数组；dict/list 的 body 是有序子键数组，value 的 body 是该节点完整 JSON。根对象、units/catalog/source_caches 容器及各来源/产品容器拆分；unit 的 records/cve_seen/known_checked_at、catalog records、source_caches 的 details/indexes 按条目拆分。其他复杂字段作为独立 JSONB 文档。CVE 检查范围仍采用现有 pack/unpack 引用格式。

保存以事务 upsert 节点，仅内容或 kind 改变时写入；临时表记录存活路径并删除过期节点。检查点与全部业务状态同一事务提交，失败回滚。HTTP 缓存仍先写独立旁文件，与现有跨文件失败语义相同；目录排他锁不变。读取使用只读连接，逐节点解码；summary/detail 仅读取根目录元数据、catalog 容器及指定产品子树，不读取其他来源或 HTTP 缓存。update 当前仍还原完整运行时状态；完全按批次加载和证据正文去重留待后续优化。

migrate-state --state old.json --output new.sqlite 仅允许同目录、目标与其 SQLite 辅助文件/续传文件均不存在；沿用目录锁。转换完整原始逻辑状态（包括旧内嵌 HTTP 缓存），校验 integrity_check 与反序列化一致性，复制旧 CVE 续传文件到新路径。失败删除本次新建文件；源 JSON、共享 HTTP 旁文件和展示历史不修改。默认回滚日志模式，不启用 WAL。输出路径不能碰撞 SQLite -journal/-wal/-shm 文件。运行时 SQLite 及辅助文件不入库。

SQLite 每次保存（含 update 与迁移）在业务事务提交后、目录锁释放前执行 VACUUM，回收空闲页并整理文件。事务失败不执行 VACUUM；VACUUM 失败仅记录 warning，不撤销或误报已提交的检查点。summary/detail 使用 mode=ro，不执行空间回收。VACUUM 会重写数据库，故增量 SQL 写入不代表整个保存过程仅有增量磁盘 I/O；耗时计入 update 总耗时。
