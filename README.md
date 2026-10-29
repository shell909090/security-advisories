# 安全公告抓取

Python 3.10+，仅标准库。监测 Hermes Agent、OpenCode、Claude Code、Codex CLI；不采集安装版本、不发送通知。

```bash
cd ~/var/security-advisories
./fetch.py                                # 全部已发现的数据源，默认 Critical
./fetch.py --list-sources
./fetch.py --sources ghsa,osv,project       # 选择数据源
./fetch.py --min-severity high             # High + Critical
./fetch.py --skip-severity-filter          # 跳过严重性过滤
./fetch.py --skip-product-filter           # 跳过采集范围内的产品确认
./fetch.py --skip-dedup-filter             # 不读取、不写入排重历史；--all 同义
./fetch.py --offline --all                 # 只看缓存中的近期结果
./fetch.py --offline --history --all       # 明确查看历史结果
./fetch.py --dedup-history another.json    # 使用独立排重历史
./fetch.py --details --output report.json  # 完整证据，报告可删
python3 -m unittest discover -s tests -t . -v
```

## 结构

- `sources/ghsa.py`：GitHub 全局安全公告，准确包名，日期增量。
- `sources/project.py`：项目自己的 Security Advisories。Release notes 不是漏洞条目，默认不扫描完整 Release 历史；需要时加 `--include-releases`。
- `sources/osv.py`：按准确包名、无版本查询。规模小，每次重查已收录记录，以捕获延迟入库。
- `sources/nvd.py`：产品关键词及修改时间查询；共同别名合并为宽关键词（当前四产品只需四个查询），可用配置 nvd_keywords 覆盖。候选可能涉及第三方工具，交给产品过滤确认。
- `sources/cve.py`：官方滚动 deltaLog，独立检查新增及更新记录。约 30 天覆盖，超过覆盖明确报错。首次默认检查近三天，不下载全库；CVE ID/修改时间缓存避免重叠窗口重复下载。
- `fetch.py`：自动发现模块、并发调度、统一记录合并、调用过滤器、保存采集状态。
- `filters.py`：严重性 → 产品确认 → 历史排重。
- `products.json`：四个产品的包名、仓库、别名，可扩展主要自管依赖。

各源可能按产品查询来限制下载范围；`--skip-product-filter` 只跳过后置确认，不代表从每个源下载全世界全部漏洞。CVE 的无关正文不保存。

## 三层过滤

1. **严重性**：默认 Critical；可改 `--min-severity` 或完全跳过。未知评级不冒充严重漏洞，可用 `--include-pending` 单列待复核线索。
2. **产品**：确认准确包/仓库来源，或受影响产品/CPE；仅描述里提到关注产品、第三方集成工具、发现者致谢，不足以确认。可关闭。
3. **排重**：默认 `dedup-history.json`，按 CVE/GHSA/OSV 别名合并后记录内容指纹；重要内容变化再次输出，纯时间戳/独立引用列表变化忽略。可指定另一历史库或完全关闭。此历史代表已输出，不代表通知已送达。

默认首次只报告近 `--days 3` 天发布/更新的记录；已知条目的内容变化也处理。历史梳理需明确 `--history`，已排重记录需再加 `--all`。输出精简字段：产品、等级、CVE/GHSA ID、标题、评分及来源链接；`--details` 才带完整证据。没有 CVE 的真实 GHSA 仍可保留，不伪造编号。

## 并发、状态和失败

默认 `--jobs 6` 个产品/数据源任务并行；CVE 详情另用 `--workers 8` 并行。NVD 请求共享限速器，不能通过并发突破接口配额。每源输出耗时，总耗时及各层过滤数量写入 JSON。

`state.json` 是采集缓存、各源成功进度和 CVE 检查索引；与排重历史分离。失败源不推进进度，其他源继续。`.lock` 防止同时写同一状态/历史。JSON 默认 stdout，报告不长期保存。退出码 0 全部所选源成功，1 部分失败，2 参数或整体错误。

GitHub 建议环境变量 `GITHUB_TOKEN` 或 `GH_TOKEN`，NVD 可选 `NVD_API_KEY`；不把凭据写入文件。支持标准代理环境变量及 `--proxy URL`。CVE 官方日志超过保留窗口会报错，需完成回补后用 `--since ISO时间` 恢复。新版 GitHub 默认 reviewed 包公告；unreviewed 相关线索由 CVE/NVD 补充，不宣称遍历所有未审核 GHSA。

## 增加数据源

在 `sources/` 放一个不以下划线开头的 Python 文件，无需修改 fetch 的名单：

```python
NAME = 'example'
GLOBAL = False                 # False：每产品一个任务；True：全局一个任务
MATCH_BASIS = 'source-candidate' # 精确包/仓库可声明 exact-package / exact-repository

def collect(client, product, since, until, context):
    return {'records': [], 'metadata': {}}
```

统一记录字段：`id, aliases, products, title, description, severity, scores, published, modified, url, affected, withdrawn, kind, references`。severity 小写，未知为 `unknown`；kind 为 `vulnerability` 或 `security-release`。日期 ISO8601；products 使用配置 ID。记录只是来源声明，不代表本机可利用。

`client.json()` 支持 GET/POST，`client.paginate_github()` 跟随分页链接。context 包含关注清单、旧源状态、已知 CVE 映射、详情并发数和配置变化标记。metadata 可保存源自有游标，不得覆盖 records/checkpoint/config_hash。源失败应抛异常，不能返回假空结果。`SUPPORTS_FULL_HISTORY=False` 可声明只支持滚动时间窗（如 CVE）。新增源须提供分页、失败及数据转换测试。
