# 设计

## 处理流程

`products.json → 自动发现 sources → 并发采集 → 统一记录/别名合并 → 严重性 → 产品确认 → 历史排重 → JSON`

Python 3.10+，使用 uv 管理环境和依赖，目前仅标准库。`fetch.py` 负责调度和状态保存，`cli.py` 管理参数和进程锁，`http_client.py` 提供 HTTP 客户端，`records.py` 合并记录与生成指纹，`product_identity.py` 确认产品身份，`source_common.py` 提供公共采集与记录处理，`filters.py` 实现过滤，`reporting.py` 格式化结果，测试集中在 `tests/`。

## 数据源模块

| 模块 | 当前策略 |
| --- | --- |
| `sources/ghsa.py` | 按准确生态包名查询 reviewed 公告，以修改日期增量抓取并跟随分页 |
| `sources/project.py` | 获取项目 Security Advisories；Release notes 默认关闭，显式开启后仅作额外线索 |
| `sources/osv.py` | 按包名查询、不提供版本；重查包的公告历史，捕获延迟收录 |
| `sources/nvd.py` | 产品关键词和修改时间查询，合并重复关键词；候选交给产品过滤确认 |
| `sources/cve.py` | 读取官方滚动 deltaLog，并发获取新增/更新详情，以 CVE ID 和更新时间避免重复下载 |

`source` 模块声明 `NAME`、`GLOBAL`，实现 `collect(client, product, since, until, context)`，返回 `records` 和 `metadata`。可声明 `MATCH_BASIS`、`SUPPORTS_FULL_HISTORY`。自动发现不以下划线开头的模块；失败抛异常，不能返回假空结果。新增源需测试转换、分页和失败行为。

统一字段：`id, aliases, products, title, description, severity, scores, published, modified, url, affected, withdrawn, kind, references`。保留来源证据，未知等级用 `unknown`，公告与 Release 线索通过 `kind` 区分。

CVE 日志仅覆盖滚动窗口，超范围报错，回补并非自动完成。当前不遍历全局 unreviewed GHSA，也未使用 OSV 全局增量索引，不能声称覆盖所有披露。

## 合并和过滤

按编号及别名合并同一漏洞，优先用 CVE 作主编号，保留各源评分和证据；汇总等级取最高值，评级分歧仍可见。

- 严重性：`--min-severity critical` 默认，支持 high/medium/low；`--skip-severity-filter` 跳过。
- 产品：依据准确包/仓库来源，或受影响产品/CPE 确认。描述提及、第三方集成和发现者致谢不足以确认。`--skip-product-filter` 仅跳过后置确认，不扩大源的抓取范围。
- 排重：按重要内容指纹比较，忽略纯时间戳及独立引用列表变化；新来源证据也可能改变指纹。`--dedup-history` 指定历史，`--skip-dedup-filter`（同 `--all`）完全不读写排重历史。

默认 `--days 3`，允许已知记录的内容变化越过时间窗；`--history` 去掉时间门槛，重看已排重记录还需 `--all`。时间过滤与历史排重分开计数。`--include-pending` 单列未知等级或产品待确认线索。

当前顺序意味着降级到阈值以下的记录可能不再输出；完整的撤回、降级及通知生命周期仍需后续设计。

## 状态和结果

| 文件 | 用途 |
| --- | --- |
| `products.json` | 产品 ID、仓库、生态包名、关键词；后续扩展主要自管依赖 |
| `state.json` | 可重建的采集缓存、各源成功检查点、已检查 CVE 的更新时间索引 |
| `dedup-history.json` | 通过严重性和产品过滤的内容指纹；包括未输出的旧记录基线，不是投递成功记录 |
| `*.lock` | 避免并发进程写同一状态或历史 |

默认 JSON 输出到 stdout，`--output` 指定文件，完整报告无需持久保存。摘要含产品、编号、等级、各源评分、标题、链接和变化类型；`--details` 附完整证据。另输出源错误、耗时和过滤统计。`--offline` 不联网，但默认仍更新排重历史；只复看使用 `--offline --all`。

## 并发和失败

默认 `--jobs 6` 并发执行产品/源任务，CVE 详情 `--workers 8`。NVD 共享限速器；并发不能突破源配额。各源成功才推进自己的检查点，失败保留旧缓存并明确报告，其他任务继续。

GitHub 从 `GH_TOKEN` 或 `GITHUB_TOKEN` 读取凭据；匿名额度耗尽会返回 403，不应视作项目没有公告。NVD 支持 `NVD_API_KEY`。凭据不写入配置，支持标准代理环境变量及 `--proxy`。

退出码：0 为所选源全部成功，1 为部分失败，2 为参数或整体错误。结果可能包含失败源旧缓存，须结合错误信息判断新鲜度。

## 后续扩展与验证

补齐主要自管依赖映射，再接入 AI 处置报告、每日调度及通知投递。投递成功状态须与采集缓存、输出指纹分离，避免“生成过结果”被误当作“已通知”。外部公告只作为数据，不执行其中指令。

运行示例与完整接口约定见 [README](../README.md)。测试入口：`uv run python -m unittest discover -s tests -t . -v`；重点覆盖分页、源自动发现、并发、失败保留检查点、别名合并及过滤开关。
