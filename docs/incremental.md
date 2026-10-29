# 增量更新研究（2026-10-29）

本文件保留最初接口调研与改进方案。后续已实现 GHSA 批量包查询、OSV 批量索引/共享详情、逐源统计、产品级检查点及 CVE 索引清理；当前精确格式与行为以 [design.md](design.md) 为准。下文“现状”指调研时基线。目标同时记录 HTTP 请求数与响应字节量，避免把并发提速误认为减少工作量。

## 现状与机会

关注配置为 22 产品、23 个包、4 个生态、21 仓库。当前无额外分页/重试时约 90 次基础请求，再加 CVE 变更详情请求：GHSA 23、OSV 23、项目 21、NVD 约 22、CVE 日志 1。

| 来源 | 现状 | 改进 | 边界 |
| --- | --- | --- | --- |
| GHSA | 每包查询 reviewed；modified 下界按天，默认重叠两天 | 按生态、时间游标分组批量 affects；固定窗口；ETag | 返回变更后的整条公告，不是 JSON patch；不同起点需分组，新增包不能继承老包游标 |
| 项目 | 每仓库每次扫描全部公告，未使用 since | sort=updated,direction=desc；越过水位停止分页；稳定请求参数+ETag | 没有 documented since 参数；第一页可能仍含旧记录；分页期间变动需重叠窗口与周期核对 |
| OSV | 每包 query 获取完整历史 | querybatch 获取 ID+modified；仅新 ID/modified 变化时 GET /v1/vulns/{id}；跨包共享详情缓存 | 无通用 since 查询；仍需传输轻量索引。首次 1+N 详情请求可能多于现状；分页按包维护，不能忽略 token |
| NVD | 每关键词按修改时间查询，2000/页，120天窗口 | 保留按产品增量；减少重叠；候选全局时间流与产品查询对比成本后再选择 | 全局流减少请求但可能增加无关正文传输，不默认启用；关键词消失/撤回需要已知 ID 周期核对 |
| CVE | 每次下载滚动 deltaLog，按 ID/dateUpdated 下载变更详情 | 日志条件请求；已检查索引使用本地检查时间/日志入库时间清理；大量变更时比较官方压缩增量包成本 | 日志更新会重传整份日志；详情匹配前无法确定产品。官方小时包是当天基线后的累计差量，不是相邻小时 patch |

## 已做只读接口验证

- GitHub global affects 同时提供 uv、ruff：HTTP 200。当前查询时间窗没有记录，验证的是批量参数可被接受，不据此证明完整映射正确。
- OSV querybatch，无 version，查询 uv、ruff：HTTP 200，响应 782 字节；分别 11/0 条，条目仅包含 id、modified。
- uv 仓库公告 sort=updated,direction=desc,per_page=1：HTTP 200 带 ETag；相同 URL 使用 If-None-Match 再请求：HTTP 304、正文 0 字节。

## 本地实现应先纠正的点

1. update 配置指纹包含全部本次产品及 min_severity，任意切换都可能使既有源重拉。应拆分采集身份（源/生态/包或仓库、匹配配置）与收录策略；当前同步层已有全等级证据，级别变更优先重建 catalog，不清空同步游标。
2. CVE seen 依据公告 dateUpdated 是否早于滚动日志起点清理，延迟入库的旧记录可能反复下载。独立存 fetched_at/ingested_at，dateUpdated 仅用于版本比较。
3. CVE 全局进度与产品范围混合。独立全局日志游标、已下载索引、有限期详情缓存及每产品匹配覆盖水位；新增产品必须重新匹配其回溯窗口，不默认为已覆盖。
4. 当前固定两天重叠，在每日更新时会重复覆盖约三天。按源设小重叠并周期回补，不能直接去掉重叠；公开 API 没有一致快照和统一延迟保证。
5. 撤回/删除/匹配字段变化要处理。仅按当前关键词或只取 High/Critical 会漏掉降级/撤回；已知 ID 需刷新或周期核对，失败或缺页不更新覆盖水位。

## 推荐实施顺序

1. 指标：每源 requests、response_bytes、304、new/changed/unchanged、失败/重试数；区分解压后字节量与线上传输字节量。
2. 修复指纹粒度和 CVE seen 清理，按产品与源保持独立覆盖水位。
3. HTTP 条件缓存：URL+参数+响应表示+认证上下文作为键，正文存在且完整才允许使用 304；失败不得缓存；不保存明文令牌。
4. OSV 批量索引+共享详情；GHSA 按生态批量查询，准确按返回 package 分配产品，不能整批标给每个产品。
5. 项目公告更新倒序+早停+条件请求，保留周期全量核对。
6. CVE 详情请求与官方增量包按实际字节/记录数选路；跨午夜或断更需证明覆盖连续，否则回退 deltaLog 或明确报错。
7. NVD 最后优化，先记录全局变更页数与各产品查询的成本，不能只为少几个请求下载全球无关数据。

预计常态无变化、单页情况下，GHSA 23→约4，OSV 23→1（有变化另加详情请求）；保留 NVD 与项目逐产品查询时基础请求约90→49。不是性能承诺，取决于分组游标、分页与查询大小。ETag 304 省正文而不是省请求。协议普遍只能提供“变化公告的当前完整记录”，无法承诺严格只传上次以来的字段级差量。

## 官方资料

- https://docs.github.com/en/rest/security-advisories/global-advisories
- https://docs.github.com/en/rest/security-advisories/repository-advisories
- https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api
- https://google.github.io/osv.dev/post-v1-querybatch/
- https://google.github.io/osv.dev/post-v1-query/
- https://nvd.nist.gov/developers/vulnerabilities
- https://github.com/CVEProject/cvelistV5#how-to-download-the-cve-list

## 实施中补充验证

- GHSA affects 的重复同名参数编码（affects=uv&affects=ruff）实测只匹配最后一项；实现改用官方示例的逗号分隔 affects=uv,ruff，实测完整历史返回8条并正确映射到uv。
- OSV querybatch modified 可能6位小数，详情同一时间为9位；缓存比较统一到微秒，原始详情时间保留。
- uv+ruff 独立缓存实测：OSV 首轮12次请求、51,925解压后字节；热缓存轮1次请求、782字节、11次详情缓存命中。GHSA 两包同一窗口1次请求。数据量会随上游内容变化。
