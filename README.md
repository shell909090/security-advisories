# 安全公告缓存与产品报告

Python 3.10+，uv 管理依赖，requests 复用 HTTP 连接。一个入口三个子命令：更新缓存、查看产品摘要、查看漏洞详情。应用代码在 `advisories/`，根目录仅保留入口 `main.py`。

```bash
uv sync

# 更新所有关注产品，收录 High + Critical；不修改展示历史
uv run python main.py update --min-severity high

# 只更新指定产品；默认最低级别为 High（包含 Critical）
uv run python main.py update --product chrome,uv --min-severity high --days 3

# 离线摘要：默认近 3 天、仅 Critical、仅未展示/内容有变化的条目
uv run python main.py summary
uv run python main.py summary --product chrome --min-severity critical --days 7

# 忽略展示历史且不更新历史；--history 取消时间窗口
uv run python main.py summary --all
uv run python main.py summary --history --all
uv run python main.py summary --shown     # 仅已展示，不修改历史

# 指定产品，默认 High + Critical、近3天，原始描述摘要 + 六列总结表
uv run python main.py detail --product cpython
uv run python main.py detail --product chrome --severity critical
uv run python main.py detail --product chrome --severity high --days 7
uv run python main.py detail --product chrome --severity high --history # 全部历史
uv run python main.py detail --product chrome --severity high --output /tmp/chrome-high.md

make check                               # 测试 + 所有质量门限
```

每个子命令支持 `--products 配置路径`、`--state 缓存路径`、`--output 输出路径`。产品筛选用 `--product 产品ID[,产品ID]`（可缩写为 `-p`）；detail 只能选择一个产品。详细参数用 `uv run python main.py 子命令 --help`。

## Summary

按产品展示 Critical/High 数量、受影响版本/组件、公告明确给出的修复版本，以及 RCE、Crash、UAF、Sandbox Escape 等证据标签，不在摘要堆叠漏洞 ID 和 CVSS。

- 数量指本次过滤后实际展示的活跃漏洞，重复编号/别名合并。
- summary 默认读取并更新 `history.json`；相同内容第二次运行 stdout 为空。
- 只在成功输出后标记实际展示的条目；被产品、级别或时间过滤的条目不标记已展示。
- 内容发生重要变化可再次展示，纯时间戳变化不重复展示。历史按产品和所有漏洞别名记录。
- `--all` 不读写历史，`--shown` 只读历史，`--dedup-history` 可指定独立历史文件。
- 版本分支、平台和组件信息尽量保留。不推断“最高版本修复全部漏洞”，缺少修复信息明确显示未知。
- 后果标签目前仅依据明确公告措辞，未经 AI 分析；UAF 是缺陷类型。没有匹配标签不等于无危害，标签也不代表本机可利用。

## 更新与收录范围

update 决定产品和最低收录级别，summary 只能二次收窄。降低 summary 门槛不会联网补抓，缓存门槛不足会在 stderr 提示重新 update。detail 默认包含 High + Critical；可选的 `--severity high` 精确匹配 High，不包含 Critical。详情先逐条展示漏洞原始描述，最后展示漏洞 ID、威胁级别、公告时间、受影响版本、后果和原始链接的总结表；不输出评分、JSON 或证据明细。

`--days` 可缩写为 `-d`，默认 3，控制首次或配置变化时的回溯；已有进度时从检查点向前重叠 `--overlap-days 2` 天抓取。`--since` 显式指定开始时间。`--history` 回补支持历史查询的数据源，CVE 官方滚动日志超过覆盖窗口会明确报错，不能自动回补全库。

更新所选产品不会删除其他产品。`state.json` 的同步证据用于合并别名、等级变化和撤回，可能包含未达收录门槛的原始记录；`catalog` 才是 summary/detail 可读取的按产品、级别收录目录。旧格式缓存仍可供 update 增量使用，但需要先运行一次 update 建立目录，显示命令不会擅自导入旧数据。旧版输出历史不等于新版摘要展示历史，首次 summary 会重建其版本。

来源：

- GHSA：按生态和时间窗口批量查询准确包名，reviewed、日期增量；返回公告按包名分配产品。
- 项目公告：GitHub 仓库 Security Advisories；与全局 GHSA 覆盖不完全相同，不默认扫描 release notes。
- OSV：querybatch 查询包的 ID/修改时间索引，无安装版本限制；仅对新 ID 或修改时间变化的 ID 下载详情，详情跨产品共享。
- NVD：关键词和修改时间；结构化产品信息再确认。
- CVE：全局滚动 deltaLog，下载变更详情后匹配关注产品。

使用 `--sources ghsa,osv,project,nvd,cve` 选择来源。默认 `--jobs 6`，CVE 详情 `--workers 8`（最大 32）。NVD 共享限速，不靠增加并发绕过配额。失败源保留旧缓存、不推进检查点，报告提示可能过期。

CVE 每 100 条将成功记录原子写入 `<state路径>.cve-progress.json`；部分失败也保存成功结果，下次相同配置跳过未变化的成功项。所选产品匹配范围变化会使批次缓存失效，级别变化不会；主状态写入成功后清理已完成批次。每线程独立 requests Session 复用连接，采集结束关闭。

GitHub 凭据读取 `GH_TOKEN` 或 `GITHUB_TOKEN`，NVD 可用 `NVD_API_KEY`，均不落盘。支持标准代理环境变量和 `--proxy`。退出码：0 成功、1 更新部分源失败、2 参数/整体错误。

## 文件与开发

- `products.json`：关注产品配置。`packages` 允许空数组，浏览器等依靠 CVE/NVD 或项目公告。
- `state.json`：同步缓存、成功进度、收录目录。
- `history.json`：摘要展示指纹，不是通知投递确认。
- `advisories/`：CLI、采集调度、过滤/展示、版本/后果提取及 `sources/` 插件。
- `tests/`：回归测试；`scripts/check_quality.py`：静态门禁。

JSON、运行时 lock、Python 缓存和 `.venv/` 按仓库约定忽略；配置需在新检出时自行准备，uv.lock 纳入版本控制。产品结构：

```json
[{"id":"uv","label":"uv / uvx","repositories":["astral-sh/uv"],"packages":[{"ecosystem":"PyPI","name":"uv"}],"keywords":["uv","uvx","astral-sh/uv"],"nvd_keywords":["astral uv"]}]
```

本地清单包含 Hermes Agent、OpenCode、Claude Code、Codex CLI、goimports、golangci-lint、govulncheck、inb、migrate、Trivy、ttyd、Zellij、LiteLLM、Pi、Playwright、Ruff、uv/uvx、Uvicorn、yt-dlp、Chrome、Brave、Firefox。uvx 与 uv 合并；inb 为 yuzu-hub/inb，migrate 为 golang-migrate/migrate。Pi 同时查询迁移前后的 npm 包名。浏览器厂商公告暂无独立采集器，不自动推断 Chromium 漏洞影响 Brave。

```bash
make sync          # uv 同步开发依赖
make test          # 单元测试
make complexity    # 每函数 McCabe <= 10、认知复杂度 <= 15
make mi            # 每文件 MI >= 30
make quality       # 所有静态指标
make check         # 测试 + 静态指标（默认目标）
```

检查覆盖源码、测试和检查脚本，排除隐藏目录和 Python 缓存。超限以非零状态退出，不对存量代码豁免。需求和实现设计见 `docs/req.md`、`docs/design.md`。

## 增量状态与统计

普通来源检查点按产品和相关配置隔离；CVE 保存每产品覆盖时间与匹配配置。切换更新产品子集或最低等级，不再重置无关产品的同步进度。首次从旧 collection_hash 缺失的缓存迁移，会按回溯窗口重新建立检查点一次。

CVE 已检查索引保存 modified、checked_at、products；清理依据本地成功检查时间，避免延迟入库的旧公告反复下载。OSV 共享索引/原始详情缓存位于 `state.json.source_caches.osv`。

每轮 stderr 输出每源 requests、response_bytes、retries、http_errors、cache_hits、not_modified、new/changed/unchanged/removed，并保存到 `state.json.last_update`。response_bytes 为解压后的 HTTP 正文字节，不是线路流量；cache_hits 是省略详情请求的次数，不是连接池复用。记录变化数按来源产品记录计，共享 ID 的 HTTP 请求只计实际次数。HTTP 条件缓存的304单独计入 not_modified。

全部本地格式及兼容规则见 [设计文档](docs/design.md)。

日志统一通过 logging 默认写 stderr，stdout 保留命令结果，便于管道处理。摘要在同一产品、同一组件/平台内合并受影响范围和公告修复版本，保留空隙及无法解释的表达式；不跨组件合并，也不推断最高修复版本能解决全部漏洞。

Chrome 的组件名忽略大小写，同一组件/平台的数字修复版本按稳定版本累计修复策略汇总为最高升级目标。该策略当前仅用于 Chrome，不自动推广到其他产品；缺失修复信息仍保留提示。


## 通道与增量加速

CVE 优先启动，详情默认8并发；GHSA+项目公告共用串行通道，NVD和OSV各自串行，通道之间并行。--jobs限制外层并发，--workers控制CVE详情并发。限流响应按服务等待，不阻塞其他服务。

GHSA/项目公告及CVE日志支持持久化ETag条件请求；项目公告按更新时间倒序早停，每7天完整核对。CVE大批量时尝试当天压缩增量包，缺失或版本不符的记录回退单条下载；可用 --cve-bundle off 禁用。压缩包不会绕过日志历史覆盖限制。剩余优化及验收条件见 docs/tasks.md。

NVD 对已有记录每7天按 CVE ID 批量复核（每批最多100条），不依赖产品关键词。本轮已查询到的记录不重复抓取；失败或缺项保留旧缓存并报告可能过期。新检出或旧缓存迁移后的首次更新可能多出复核请求。

HTTP 条件缓存独立保存在 `<state所在目录>/http-cache.json.gz`，仅 update 读取；缺失或损坏会重新获取。旧 state.json 内嵌缓存在下次 update 保存时自动迁移。CVE 检查进度在磁盘上共享产品配置映射，兼容旧数据；summary/detail 不需要读取压缩 HTTP 缓存。备份业务状态时保留 state.json 和未完成的 `.cve-progress.json`，HTTP 旁文件可选。

同一状态目录的所有命令共用 `advisories.lock`，冲突时立即报错退出。该锁不影响 update 内部的通道并发；不同目录独立运行时，不要交叉共享展示历史等业务文件。

## 最低版本门限

在 products.json 的产品对象中添加 `"min_version": "1.106.6"`（例如 LiteLLM）。该值由你汇总多台机器的最低版本，必须为数字点分字符串；不填写或设为 null 表示关闭。仅 summary 隐藏能确认全部受影响版本均低于门限的漏洞；高版本重新引入的漏洞、未知或无法比较的范围仍显示。update 和 detail 不受影响，无需重新 update。`--all` 只绕过展示历史，不绕过版本门限；被过滤条目不会记为已展示。临时跳过版本门限可用 `uv run main.py summary --all --days 10 --ignore-min-version`，无需修改配置。

## KEV 数据源

默认 update 包含 CISA KEV，也可使用 `uv run python main.py update --sources kev`。每次下载官方目录并筛选最近两个自然月的 dateAdded；通用时间参数不改变此窗口。旧证据保留。KEV 未提供等级和版本时保持未知，KEV 一律按 Critical 优先级收录和筛选，保留原始评分。摘要单列 KEV，Critical/High 不重复统计 KEV；detail --severity critical 包含 KEV 并说明优先级。时间、最低版本和展示历史规则仍适用，新加入 KEV 会再次展示。最低版本配置不影响 update。

更新等待时每30秒显示未完成任务。按一次 Ctrl-C 会取消后续请求，等待在途请求结束后保存已完成来源并以130退出；请等待保存完成，重复 Ctrl-C 或强杀仍可能跳过保存。

summary --list 提供窄屏列表：每个软件依次输出名称、KEV/Critical/High 个数、受影响版本、公告修复版本、后果，共五行加一个空行。软件名前加 `## `，其余四行前加 `- `。长行自然折行，内容换行折叠为空格。复用产品分组、版本汇总和中文后果映射；缺失后果显示未知。筛选和展示历史规则不变，查看已展示内容可加 --all。

### SQLite 状态存储

需要 Python 所链接的 SQLite >= 3.45（支持 JSONB）。转换保留原文件、不联网，目标必须不存在且与源文件在同一目录：

```bash
uv run main.py migrate-state --state state.json --output state.sqlite
uv run main.py summary --state state.sqlite --list --all
uv run main.py update --state state.sqlite
```

后续命令需继续指定 `--state state.sqlite`；默认仍使用旧 `state.json`。SQLite 按文档增量写入，显示命令只加载选中产品的 catalog；这一版 update 仍加载完整运行时状态。展示历史和 HTTP 缓存沿用同目录原文件，CVE 续传进度在迁移时复制到新状态对应路径。请勿交替更新新旧状态，以免两份缓存逐渐分叉。

SQLite 在每次状态保存后自动执行 VACUUM 回收空间；summary/detail 不写数据库。若空间回收失败会输出警告，已经提交的更新仍然保留。

### NVD 部分更新

update 默认每次更新选中 NVD 产品的三分之一（向上取整）。缺失、配置变化或满72小时未检查的产品必选，允许超额；不足时按上次成功更新的 UTC 日期从旧到新补选，同一天内随机抽取。空结果也算成功检查，跳过不推进检查点。每次运行都有独立配额，同日多次运行不扣除已更新数量。

```bash
# 默认部分更新
uv run main.py update --state state.sqlite
# 本次强制检查所有选中的 NVD 产品
uv run main.py update --state state.sqlite --nvd-full
```

--nvd-full 不改变时间窗口，也不下载整个 NVD 数据库；--since/--history 显式回补时同样不抽样。其他来源不受影响，日志会显示 NVD 选中/跳过数量。
