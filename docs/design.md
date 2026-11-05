# 设计与数据格式

功能见 [req.md](req.md)，用法见 [../README.md](../README.md)，未完成工作见 [tasks.md](tasks.md)。本文统一定义实现、持久化格式、兼容规则及性能依据。

## 架构与命令

`main.py` 委托 `advisories.cli`；实现位于 `advisories/`，适配器位于 `advisories/sources/`，回归测试和质量脚本位于 `tests/`、`scripts/`。默认路径相对项目根目录。

| 命令 | 默认与流程 | 状态影响 |
| --- | --- | --- |
| update | high、3天；采集 → 合并证据 → 重建所选产品 catalog → 保存 | 更新来源、目录和统计，不写展示历史 |
| summary | critical、3天；读取所选 catalog → 门限/时间/历史过滤 → 输出 | 成功后登记展示历史；--all/--shown 不登记 |
| detail | 单产品、high + critical、3天；按确切等级和时间读取 catalog | 不读写展示历史 |
| migrate-state | 显式源 JSON 和目标 SQLite；离线转换并校验 | 保留源文件、复制续传进度，不推进检查点 |

公共参数为 --products、--state、--output、-p/--product；update/summary/detail 支持 -d/--days。detail 的 days/since/history 互斥；summary 另有 --dedup-history。默认状态为 state.sqlite，不自动回退 JSON。退出码：0成功，1部分来源失败，2参数或整体错误，130更新取消。日志用标准 logging（默认 INFO、stderr），stdout/--output 仅输出结果；不覆盖调用方 handler。

## 文件与持久化

| 文件 | 内容与兼容 |
| --- | --- |
| products.json | 产品配置数组 |
| state.sqlite（默认）或显式 JSON 状态 | 逻辑 version:1，格式见下文；.sqlite/.db 选择 SQLite 后端 |
| 同目录 http-cache.json.gz | `{version:1,entries:{key:HttpEntry}}`；可重建，仅 update 加载 |
| `<state>.cve-progress.json` | `{config_hash,records:[NormalizedRecord],seen,seen_scopes?}`；无独立 version |
| history.json | `{version:2,records:{"product:alias":{fingerprint}}}` |
| 同目录 advisories.lock | 所有命令共用目录级排他锁，文件存在不代表锁被持有 |
| `<JSON路径>.new` | 原子替换临时文件，不作为缓存读取 |

JSON 使用 UTF-8、保留非 ASCII 字符；普通文件缩进2格并以换行结尾，HTTP 缓存使用紧凑 JSON。时间为 ISO8601，内部生成 UTC 时间，外部原格式保留；无时区时间按 UTC 解释。未知时间为 null/缺省，未知文本通常为空字符串。严重性为 critical/high/medium/moderate/low/none/unknown，moderate 与 medium 同级。

### 原子性与隔离

- 业务读写前获取目录锁 `LOCK_EX | LOCK_NB`，冲突立即退出，关闭描述符释放，不删除锁文件；summary --all 和 detail 也锁定。不同文件名但同目录仍互斥，独立目录不得交叉共享状态或历史。
- JSON 通过同目录 .new + replace 提交；SQLite 通过事务提交。HTTP 缓存先写，主状态后写，展示历史单独写，跨文件不保证事务。缓存写失败不提交主状态；主状态失败仍保留旧检查点，较新完整 HTTP 响应可在下次复用。
- 输出路径不得覆盖配置、状态、历史、锁、HTTP 缓存、续传文件或 SQLite -journal/-wal/-shm。代理和凭据不落盘、不入日志。
- 运行时 JSON、SQLite及辅助文件、lock、字节码和虚拟环境不入库，依赖锁 uv.lock 例外。Python >=3.10，uv 管理依赖；make check 覆盖源码/测试/脚本，McCabe ≤10、认知复杂度 ≤15、每文件 MI ≥30。

### SQLite JSONB

要求 SQLite >=3.45，连接时验证 jsonb() 可用；application_id=1396786244、user_version=1，逻辑状态仍为 version:1。使用普通 rowid 表，避免大文档在 WITHOUT ROWID 表中的溢出页浪费。

```sql
CREATE TABLE nodes (
    path TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    body BLOB NOT NULL
);
```

path 为键/下标组成的紧凑 JSON 数组；kind=dict/list 时 body 是有序子键数组，kind=value 时是完整文档，均编码为 SQLite JSONB。拆分根对象、units/catalog/source_caches 及其来源/产品容器；unit 的 records/cve_seen/known_checked_at、catalog.records、source_caches 的 details/indexes 按条目拆分，其余字段独立存文档。

保存事务 upsert 改变的节点，临时存活路径表用于删除过期节点；检查点和全部业务状态一起提交，异常回滚。提交后、释放目录锁前 VACUUM；事务失败不回收，VACUUM 失败仅警告，已提交结果有效。默认回滚日志，不启用 WAL。VACUUM 会重写全库，增量 SQL 不等于全程增量磁盘 I/O。

读取使用 mode=ro、逐节点解码。summary/detail 只加载根目录元数据和所选产品 catalog；update 仍还原完整运行时状态。

migrate-state 仅接受同目录的新目标，目标及其辅助/续传文件须不存在。转换完整源状态（包括旧内嵌 HTTP 缓存），验证 integrity_check 与解码一致性，再复制旧续传文件；失败删除本次新建文件。源 JSON、共享 HTTP 缓存、展示历史不修改。

## 逻辑数据模型

### 产品配置

| 字段 | 结构与用途 |
| --- | --- |
| id、label? | 稳定产品 ID、显示名 |
| packages | `[{ecosystem,name}]`，可为空 |
| repositories | GitHub `owner/repo` 数组 |
| keywords、nvd_keywords? | 候选关键词；显式 nvd_keywords 覆盖 NVD 自动合并 |
| vendors、vendor_aliases? | 厂商数组；有别名时优先使用别名 |
| min_version? | 纯数字点分版本字符串；缺省/null 不过滤，仅 summary 校验使用 |

生态别名归一化：GHSA 使用 pip/go/npm/rust；PyPI 名称大小写及 `[-_.]+` 等价，crates.io 大小写、下划线与连字符等价。min_version 不进入采集指纹。

### 主状态与 unit

| 路径 | 结构 |
| --- | --- |
| version | 固定1 |
| units（必需） | `{unit_key:Unit}`；通常为 source:product_id，CVE 为全局 cve |
| Unit | `{checkpoint,collection_hash,records:{id:NormalizedRecord},...来源元数据}` |
| catalog? | `{product_id:{records:[MergedRecord],min_severity,updated_at,errors}}` |
| source_caches? | `{osv:{details,indexes},...}` |
| last_update? | `{generated_at,elapsed_seconds,sources:{source:SourceStatistics},errors}` |
| errors | `[{source:string,error:string}]` |

checkpoint 表示本轮查询开始时间，仅完整成功后提交；records 通常按 ID 合并覆盖。OSV 完整包索引和项目完整核对通过 replace_records 替换来源快照。批量来源失败不提交任何产品检查点或共享详情缓存。

catalog 仅包含产品归属已确认、达到门槛的活跃漏洞，只替换本轮所选产品；本轮错误附在这些目录上提示可能过期。同步 records 可保留低等级和撤回证据，显示层不得绕过 catalog。

旧 unit.config_hash 是全局指纹，不能当作 collection_hash；首次按回溯窗口重建覆盖。旧扩展字段可保留但不参与新逻辑；无 catalog 的旧缓存须先 update，显示命令不隐式导入。

### NormalizedRecord 与 MergedRecord

NormalizedRecord 字段：`id,aliases,products,title,description,severity,scores,published,modified,url,affected,withdrawn,kind,references,match_basis`。归一化校验 id/products/severity/kind；kind 为 vulnerability 或旧 security-release，release 不进入漏洞目录。match_basis 由适配器声明，可为 exact-package、exact-repository、keyword-candidate、product-description-or-reference 等，不代表可利用性。

scores 通常为 `[{source,version,score:number,vector:string|null}]`，OSV 也可能为 `{type:"CVSS_V3",score:"CVSS:3.1/..."}`。references 保留 URL 字符串或原引用对象。affected 保留来源结构及未知扩展字段：

| 来源 | affected 结构 |
| --- | --- |
| GHSA/项目 | `[{package:{ecosystem,name},vulnerable_version_range,first_patched_version?,patched_versions?,vulnerable_functions?}]`；first_patched_version 可为字符串或 `{identifier}` |
| OSV | `[{package:{ecosystem,name,purl?},ranges:[{type,repo?,events:[{introduced}|{fixed}|{last_affected}|{limit}]}],versions:[string],ecosystem_specific?,database_specific?}]` |
| CVE | `[{vendor,product,platforms?,versions:[{version,status,lessThan?,lessThanOrEqual?,versionType?,changes?}],defaultStatus?,...}]`；保留 CNA/ADP 容器证据 |
| NVD | `[{operator?,negate?,nodes:[{operator,negate,cpeMatch:[{vulnerable,criteria,versionStartIncluding?,versionStartExcluding?,versionEndIncluding?,versionEndExcluding?,matchCriteriaId?}]}]}]` |

MergedRecord 为 `{id,aliases,products,severity,withdrawn,withdrawal_conflict,needs_review:true,evidence,fingerprint}`；evidence 为 `[{source:unit_key,...NormalizedRecord}]`。别名按传递闭包合并，id 优先 CVE，aliases 含主 ID；catalog 将 products 收窄到单产品。severity 取未撤回来源最高值，无有效来源则 unknown。官方 CVE/NVD Rejected 优先判定撤回，否则须全部来源撤回。

明确 vulnerable:false 的节点不确认产品归属；撤回来源不参与归属、等级、版本、后果、时间或展示指纹，但保留原证据与同步指纹。

### 指纹与检查点

哈希统一为键排序、紧凑分隔、UTF-8 JSON 的 SHA-256 十六进制。

- 同步 fingerprint：来源、ID/别名/产品、空白归一化后的标题/描述、评级、评分、affected、withdrawn、kind；排除时间和独立引用列表。
- collection_hash：`{source,product:product_id,config}`。GHSA/OSV config 用 packages，项目用 repositories，NVD 用 keywords/nvd_keywords，CVE/其他源用 packages/repositories/keywords/vendors/vendor_aliases；不含等级、显示名、其他选中产品或列表顺序。
- 查询起点：显式 since 优先；支持全历史的源在 history 下取 null；无检查点/配置变化取 until-days，否则 checkpoint-overlap_days。失败或跳过不推进。
- CVE `coverage:{product_id:{checkpoint,collection_hash}}` 按产品独立更新，读取所选产品最早所需起点；全局 collection_hash 和批次 config_hash 为排序后的 `(product_id,CVE产品hash)` 数组哈希。

### CVE 检查与续传

运行时 `cve_seen:{CVE_ID:{modified,checked_at,products:{product_id:hash}}}`。modified 标识上游版本，checked_at 是本地成功检查时间；仅按 checked_at 与日志覆盖起点清理。版本变化时旧产品作用域失效，未重新检查的产品下次仍需处理。旧 `ID:时间字符串` 无法证明作用域，重新下载一次。

磁盘 `cve_seen_scopes:{局部引用:{product_id:hash}}`，条目用 products_ref 替代 products；同一完整映射共享引用，不同配置/子集不混用。引用从字符串 "0" 起按编码顺序分配，未使用映射不保存；解码恢复运行时 products，不修改调用者对象。缺失/非法引用或映射报错，旧内嵌 products 仍兼容。

续传文件为 `{config_hash,records:[NormalizedRecord],seen,seen_scopes?}`，config_hash 匹配才加载。seen 使用相同编码，但引用仅在该文件内有效，先解码再与主状态合并。每100条保存成功检查项和按 ID 去重的相关记录，非关注正文不保存；批次失败仍保存已成功项，再报错。续传不等于完整成功，不推进 coverage；主状态保存后才清除已成功 CVE 任务进度。

## 调度与来源协议

适配器接口 `collect(client,product,since,until,context) -> {records,metadata}`；BATCH=True 的源提供 `collect_many(client,contexts,until,cache) -> (按产品ID的结果映射,新缓存)`。metadata 不得覆盖 records/checkpoint/config_hash/collection_hash。主调度线程提交成功结果，工作线程不修改主状态。

通道为 cve、github（GHSA+项目）、nvd、osv、kev，每通道最多一个活跃任务。CVE 先提交；--jobs 默认6控制外层线程，--workers 默认8控制 CVE 详情线程。每线程独立 Session，结束关闭；GitHub API 另有共享互斥，覆盖 CVE release 请求。

NVD 请求启动间隔：有 NVD_API_KEY 为0.7秒，否则6.2秒。冷却按主机共享：Retry-After 优先，其次 GitHub rate-limit reset；429/明确限流403默认60秒指数退避，最多尝试3次，普通403不重试，5xx/网络异常退避重试。不阻塞其他主机。

调度器每30秒打印未完成任务。Ctrl-C 设置取消事件，唤醒限流/重试等待，取消未启动任务，等待在途请求按 timeout 结束；保存已交付成功来源和缓存，未完成来源记 interrupted，保留旧检查点及 CVE 进度，返回130。

### GHSA 与项目公告

GHSA 按生态及起始 UTC 日期分组，每组最多20包，单个 affects 参数用逗号连接，不能重复参数；每页最多100条。modified 日期闭区间允许重叠；按 vulnerabilities.package 准确映射产品，不能把整批公告标给所有产品。

项目 unit 保存 full_checked_at（UTC ISO）。首次、配置变化、history 或间隔7天完整核对并替换该源快照；其余按 updated 倒序，记录更新时间早于 since 时停止。缺失/无效时间不早停，增量保留旧记录。

### OSV

`source_caches.osv.details:{ID:{modified,record:完整OSV原文}}`；`indexes:{"生态:包名":{ID:modified}}`。详情跨产品共享，modified 采用实际详情版本，不被旧索引覆盖；比较统一 UTC 至微秒精度，避免索引6位与详情9位小数造成假更新，真实版本不一致下一轮再查。

querybatch 每批最多100查询，仅返回 ID/modified；每包独立 token 分页，token 不跨轮持久化。循环 token、响应数量不符、缺 ID/modified 均失败。仅下载新 ID 或版本变化的详情；完整成功后替换所选包索引及 OSV records，其他包不变。历史详情清理尚未实现。

### CVE 日志与压缩包

按日志 fetchTime 发现变化，不能用旧公告 modified 代替入库时间。请求起点早于日志最早覆盖时明确失败。详情下载复用已检查版本/作用域与续传记录，按100条提交批次。

--cve-bundle 默认 auto，可 off。当日 UTC 0点至 until 的待查版本不少于200条时查询官方 latest release，选当日 delta ZIP，声明大小 ≤16 MiB 且 ≤待查数×2048字节。下载限制16 MiB、ZIP声明解压总量限制128 MiB，仅内存解析，不落解压文件。仅采用 ID 与 cveMetadata.dateUpdated 完全匹配的条目，其余回退单条下载；包失败不单独判来源失败，不改变日志覆盖或检查点。

### NVD 查询、配额与复核

关键词优先 nvd_keywords，否则从 keywords 提取共同有效词以减少冗余；仍须后续产品归属确认。修改时间窗口最多120天，每页最多2000条，产品内关键词/窗口/分页串行。

每轮先构造已选产品/来源任务，再执行 nvd_sampling.select_jobs，统一使用本轮 until：

1. 目标 `(N + 2) // 3`，N 为本次 NVD 产品数。--nvd-full、--since、--history 全选。
2. collection_hash 不符，或 checkpoint 缺失/非法/未来/已满72小时，均必选；允许超过目标。
3. 其余按成功检查点的 UTC date 分桶，剩余名额从最旧日期补足。能容纳整组则全选，边界组用 random.sample 无放回抽取；不以时分秒排序。
4. 保留原任务顺序和所有非 NVD 任务。每次配额独立，不存每日计数。空结果也算成功检查；跳过不调用适配器、不计完成/失败、不修改任何 unit 字段。日志记录目标、选中和跳过数；配额不进入 collection_hash。

正常关键词查询后，按 `known_checked_at:{CVE_ID:本地UTC成功接收时间}` 复核满7天或无检查时间的已知记录；本轮已返回记录不重复查。每批 cveIds 最多100个、resultsPerPage=100，无关键词/等级/时间限制。totalResults 必须等于请求 ID 数，返回 ID 必须属于集合、不重复，分页须完整；空结果/缺失/失败不提交该产品的记录、检查时间或检查点。

成功复核按 ID 覆盖旧证据并重新判归属/等级/撤回；归属变化可移出 catalog，同步层仍保留证据。查不到不代表撤回，其他来源可独立确认归属。开销计入 NVD 统计。

### KEV

一次获取 CISA 全目录，本地筛选 dateAdded 从本次 UTC 日期回退两个自然月（月底截断）至当天的闭区间；不受 days/since/history 或检查点缩短。按产品保存 kev:product_id unit，完整成功才合并，窗口外旧证据保留。

vendorProject/product 映射 affected 的 vendor/product；severity=unknown、scores=[]，不推断版本。原条目保存在 kev 对象，正文含 requiredAction、dueDate、勒索软件使用情况和 notes。published/modified 使用 dateAdded，仅表示 KEV 收录时间。

活跃 KEV 证据将派生筛选优先级设为 critical，不改变原始/合并 severity。摘要 KEV/Critical/High 互斥计数，detail critical 包含 KEV；撤回 KEV 不提供优先级，新增 KEV 改变展示指纹。无版本范围的 KEV 证据使最低版本过滤保守保留。

## HTTP 缓存

每项 `{source,body,link,etag,last_modified,used_at}`：body 为完整解析结果，link 为分页头，验证头可 null，used_at 为本地 Unix 秒浮点数。key 为 URL（含参数）及请求 headers 的稳定 SHA-256；含认证上下文但不保存令牌或完整请求头。

仅缓存 GHSA/项目 GET 和 CVE deltaLog，不缓存 POST、NVD、CVE详情/ZIP。优先 If-None-Match，其次 If-Modified-Since；304 必须有完整正文并复用分页链接，200 完整解析且有验证头才缓存。失败来源恢复旧快照，按 used_at 留最近512项，无字节上限。

初始化仅复制索引，prepare 仅复制元数据，正文内部共享只读；304 写时替换访问时间，返回调用者及200入缓存的正文仍深拷贝，防止污染旧快照。输入缓存和 snapshot 返回值只读。

旁文件缺失时兼容旧 `<state>.http-cache.json.gz`，保存只写新名称；旧主状态内嵌 http_cache 优先读取，update 保存时迁出。旁文件缺失视为空，损坏/版本不支持则 warning 后重抓；离线显示不加载。所有主状态变体沿用目录锁和共享旁文件。

## 展示与版本处理

### 历史与输出格式

展示历史键为 `product_id:advisory_alias`，全部别名登记。展示 fingerprint 排除 ID/别名/纯编号标题/时间/独立引用列表，保留活跃来源有效内容、汇总严重性和撤回状态；新增编号不重复通知。只登记成功输出项。旧 version:1 无法证明按产品展示，按新历史处理并在下次成功输出时写 version:2，其他版本报错。

summary 表列为产品、KEV、Critical、High、受影响版本/组件、公告修复版本、证据标签；空结果返回空字符串。--list 复用分组/计数/版本，每产品5行加空行，名称加 `## `，其余加 `- `，后果映射中文且排除缺陷类型；内容换行折为空格，长行交终端折行。两种格式共用历史。

detail 选择首个有 description 的活跃来源，用引用保留段落，缺失显示“暂无原始描述”。末尾表列为编号、威胁级别、公告时间、影响版本、后果、原始链接。级别用合并 severity（首字母大写）；时间取首个有 published 的活跃非 KEV 来源原值，不用 modified/KEV收录时间替代；链接取首个活跃 URL。缺失显示未知。表格转义竖线/换行，不执行正文。

时间过滤采用任一活跃来源 published/modified 在起点至 now 的闭区间；未知/未来时间不命中普通窗口。summary 已展示内容发生重要变化仍可再次出现，--all/--shown 不改历史。detail 默认派生 high/critical，显式 severity 精确匹配。

### 产品隔离、版本合并与门限

提取前按结构化归属过滤：GHSA/OSV 比较生态/包名，CVE 比较产品/别名/厂商，NVD 比较 CPE 产品/厂商；组件、平台、范围继承已匹配节点的归属。明确其他产品或无法确认归属的范围不进入摘要，Chrome 正文提取仅用于 Chrome。

数字点分版本支持比较、逗号交集和 `||` 并集；重叠/相邻范围合并，保留开闭边界、空隙和分支。尾零等价比较，显示保留来源写法；组件标签 casefold。Chrome 同组件稳定修复版取数字最大值，不跨平台/分支，也不推广到其他产品。CPE 排除上界不直接等于修复版；项目 patched_versions/first_patched_version 均支持。预发布、Git、自定义或矛盾范围保守保留。

min_version 只在 summary 使用：所有活跃证据均能确认受影响范围完全低于门限才隐藏；不能仅凭修复版本推断。支持 GHSA 比较区间、OSV SEMVER/ECOSYSTEM 事件与显式版本、CVE 数字范围、NVD CPE 边界；未知状态、changes 或不可比较范围保留。--ignore-min-version 跳过此次校验/过滤，--all/--shown 默认仍应用门限，不修改历史或配置。

Chrome 特例：Google/Chrome 结构化节点若 versionType=custom 且 version==lessThan，仅在同一证据正文明确 `Google Chrome ... prior to VERSION` 与边界一致时解释为 `< VERSION`；完全无结构化范围时也可采用该正文边界。存在非空未知/矛盾结构、changes、未知状态或冲突时不覆盖，不改写缓存。

标签用保守文本规则提取 RCE、Code Execution、Crash、DoS、UAF、Sandbox Escape、Privilege Escalation、File Read、File Write，过滤否定语句；非 AI 分析，不保证完整攻击链。detail/list 只映射后果，排除 UAF 等缺陷类型。

## 统计与性能依据

`last_update.sources[source]` 仅保存最后一轮计数，诊断写 stderr；共享公告的产品记录变化可重复计数，HTTP 和缓存命中按实际请求/ID计。失败批次开销照记，不代表业务提交。

| 字段 | 含义 |
| --- | --- |
| requests / retries | HTTP 尝试（含连接失败、重试、自动重定向）/额外尝试次数 |
| response_bytes | 解压后响应正文，含错误与重定向；不含协议头，ZIP按压缩包字节计 |
| http_errors | HTTP ≥400 或网络异常；JSON无效作为来源错误 |
| cache_hits / not_modified | OSV/CVE详情被省略的 ID 数 / 实际304次数 |
| new / changed / unchanged | 同一产品unit/ID的新增、有效内容指纹变化、不变条数；CVE按全局unit计 |
| removed | 完整 OSV 索引或项目完整核对移除的来源记录数 |

### SQLite 基准

同内容 JSON 24,866,846字节（紧凑14,596,783），SQLite 18,690,048字节，VACUUM 后18,472,960，比原 JSON 小25.7%。每后端7次独立 .venv Python 进程交替运行取中位数；包含启动/导入/退出，不含 uv；RSS 为 Linux ru_maxrss。使用临时副本、热文件缓存，无联网，原数据未修改。

summary 使用 --all --min-severity high；全历史加 --history，单产品为 hermes；两后端输出哈希一致。

| 场景 | JSON → SQLite 秒 | JSON → SQLite 峰值 MiB |
| --- | ---: | ---: |
| 全产品近3天 summary | 0.310 → 0.163 | 149.3 → 44.4 |
| 全产品全历史 summary | 0.376 → 0.226 | 149.4 → 44.4 |
| 单产品近3天 summary | 0.259 → 0.086 | 149.5 → 31.5 |
| 加载状态及HTTP缓存 | 0.440 → 0.507 | 236.9 → 219.8 |
| 加载后原样保存，含HTTP缓存/VACUUM | 1.137 → 1.674 | 275.8 → 219.9 |

摘要收益来自按产品读取；update 全量节点查询/解码、比较及 VACUUM 仍有成本。数据不代表冷盘、联网采集、catalog 重建或增删工作负载下的完整 update 峰值。

### NVD 配额离线估算

2026-11-05 03:31 UTC 仅读取配置和数据库计算，未联网或改状态。87产品均在2026-11-04 08:11:23 UTC成功检查、配置匹配，必选0个，同一日期桶中随机选29个。基础查询92次：83产品各1次、3产品各2次、1产品3次；无到期复查。每查询一页且无重试时，期望 `92×29/87=30.67` 次，减少66.7%，单次29～34次；上次实测92次不能保证未来分页相同。

一般公式：必选和完整日期桶计全部成本；边界桶 n 个产品抽 k 个，期望为 `k/n × 桶内总成本`；更新日期更近的桶为零。必选超额、成本分布、额外分页或重试均会改变降幅，不能视为长期固定节省比例。

## 官方协议参考

- [GitHub REST 最佳实践](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)、[项目安全公告](https://docs.github.com/en/rest/security-advisories/repository-advisories)
- [OSV querybatch](https://google.github.io/osv.dev/post-v1-querybatch/)、[NVD API](https://nvd.nist.gov/developers/vulnerabilities)
- [CVE 下载协议](https://github.com/CVEProject/cvelistV5#how-to-download-the-cve-list)、[KEV 格式](https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json)
