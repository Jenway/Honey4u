# 论文正式实验执行清单

## 目的

这份清单用于把 Honey4u 当前已经具备的 benchmark 工具链，整理成一套适合毕业论文正文引用的正式实验流程。目标不是继续探索新协议，而是冻结一版可复现、可追溯、可直接对应论文表格和结论的结果集。

## 任务书完成度判断

- 一句话判断：
  - 任务书的协议实现与实验主线可视为已完成，当前剩余工作主要是论文终稿收口、图表附录整理与最小跨机复现。

| 条件 | 当前判断 | 说明 |
| --- | --- | --- |
| 跨轮次复用模块实现 | 已完成 | Python/Rust 双侧的提案编码、复用池、引用与 fetch 边界都已落地 |
| 安全性与活性不退化 | 当前范围内已验证 | 现有 runtime/integration/benchmark 检查未观察到已支持场景下的一致性或活性回归，但最终定稿仍应以冻结版本重跑留档 |
| 高负载吞吐提升至少 10% | 已完成 | `paper-final-highload-20260421T182250Z` 中 Python 路径约 `+38%` 至 `+43%`，Rust FIN 风格路径约 `+21%` 至 `+28%` |
| 稳定系统、完整文档与论文 | 部分完成 | 代码与最小正式实验包基本齐备，剩余工作是论文终稿、图表回填与措辞收口 |

按当前仓库状态看，任务书的核心代码目标已经基本完成。真正还没有封口的是“最终论文成稿”和结果整合，而不是协议核心缺功能或最小正式实验缺口。

### 任务书可视为全部完成的判据

同时满足以下四项时，可以把当前课题视为完成交付：

1. `paper/main-codex-refer.typ` 已收敛为终稿级正文，表格、图注、附录位置与有效性威胁表述都已定稿。
2. 至少完成一次最小跨机器趋势复现，并保留结果目录、配置文件与运行元信息。
3. 论文封面人工信息已经填写完整，终稿 PDF 可以稳定编译导出。
4. 最终论文口径已经统一：
   - `fixed-delay` 只作为附录级压力测试
   - `fetch` 只作为边界观察
   - 不把结果扩张为任意 ACS 黑盒、真实 WAN 验证或一般 Byzantine 鲁棒性结论

换句话说，当前真正缺的不是协议功能，而是最终交付材料的封版动作。

按当前交付视角，剩余阻塞项也可以直接压缩为三类：

1. 论文主稿正文、图表、附录与最终口径收口。
2. 最小跨机器趋势复现实验。
3. 论文封面个人信息填写与最终 PDF 导出。

另外，最后的封版动作里有两项并不能通过继续修改仓库源码自动完成：

1. 最小跨机器趋势复现需要另一台机器或另一套外部环境执行。
2. 论文封面信息需要人工填写真实个人信息。

## 当前建议优先级

### P0：封版必需

- 将 `paper-final-highload-20260421T182250Z`、`paper-final-grace-python-20260421T191900Z` 与
  `paper-final-boundary-20260421T180132Z` 回填进论文图表与正文论证
- 收紧论文措辞，明确哪些结论来自已归档结果，哪些只是增强项或未来工作

当前最小正式实验包已经齐备：`highload_n12`、`grace_python_n12_micro`、`slow_honest_n12`、
`byzantine_silent_n12` 与 `byzantine_invalid_fetch_response_n12` 都已有归档结果。现在真正的 P0
已经从“继续补冻结实验”转成“把现有结果准确、克制地写进论文”。没有必要在这些工作之前继续扩协议版图或网络系统复杂度。

### P1：交付前应完成

- 一次跨机器最小复现
- 基于冻结结果补论文图表和“恶意行为计数”摘要表
- 把已归档的 `network_fixed_delay_n12` 整理成附录级压力测试说明

其中，跨机器最小复现同时属于最终交付判据；后两项更接近论文说明力增强，但仍建议在终稿前一并完成。

### 当前建议执行顺序

1. 先把现有五组正式归档结果完整回填到正文与附录。
2. 再做一次最小跨机器趋势复现，而不是额外扩展实验矩阵。
3. 最后填写封面信息、检查图注/交叉引用并导出终稿 PDF。

### P2：有余力再考虑

- `invalid_reference_proposal` 一类更贴近复用边界的恶意行为
- 更高重复次数与误差条

### 当前不建议优先投入

- 独立 WAN 代理/完整网络模拟器
- 新协议家族、新 ACS 黑盒
- 通用化 Byzantine 攻击框架
- 与论文主线关系不强的大规模工程重构

这些方向都可能有研究价值，但在论文结果与终稿没有锁定之前，它们只会增加工作面，而不会提高当前任务书的完成度。

## 当前可直接引用的已归档结果

- 高负载主结果正式归档：
  `benchmarks/results/paper-final-highload-20260421T182250Z/`
- Python Grace 微实验正式归档：
  `benchmarks/results/paper-final-grace-python-20260421T191900Z/`
- 随机抖动正式归档：
  `benchmarks/results/paper-final-network-jitter-20260422T000021Z/`
- 固定延迟压力测试正式归档：
  `benchmarks/results/paper-final-network-fixed-delay-20260422T020028Z/`
- 边界场景 focused rerun：
  `benchmarks/results/paper-final-boundary-20260421T180132Z/`
- 大规模 reuse sweep：
  `benchmarks/results/dumbo_reuse_sweep_20260408_large/`
- Python vs Rust FIN-style 后端比较：
  `benchmarks/results/dumbo-backend-reuse-20260410T093234Z/`

这些结果已经足够支撑当前论文主稿的主结论。正式定稿前，应以这五组正式归档目录为主更新正文与附录，把更早的历史结果仅作为补充趋势材料引用。

当前状态补充：

- `paper/main-codex-refer.typ` 已经按高负载、Grace、边界、jitter 与 fixed-delay 正式目录完成一轮正文回填
- `typst compile paper/main-codex-refer.typ /tmp/honey4u-paper-check.pdf` 已通过
- 论文中的内部写作计划/样稿式附录文字已移除，当前剩余工作重点是图表导出、图注/威胁分析补强、跨机器最小复现、封面信息填写与措辞收口，而不是继续补最小正式实验包

## 当前最新的统一重跑结果

- 高负载主结果正式归档：
  `benchmarks/results/paper-final-highload-20260421T182250Z/`
- Python Grace 微实验正式归档：
  `benchmarks/results/paper-final-grace-python-20260421T191900Z/`
- 随机抖动正式归档：
  `benchmarks/results/paper-final-network-jitter-20260422T000021Z/`
- 固定延迟压力测试正式归档：
  `benchmarks/results/paper-final-network-fixed-delay-20260422T020028Z/`
- 边界场景正式归档：
  `benchmarks/results/paper-final-boundary-20260421T180132Z/`

这五次归档当前都可以按正式材料看待，原因是：

1. 四个目录的 `manifest.json` 都满足 `planned_runs == executed_runs`
2. 四次运行的 `git.status_short` 都只包含文档或论文文件改动
3. `paper-final-highload-20260421T182250Z` 中，Python 与 `rust_fin` 的全部已测批大小均保持正吞吐增益
4. `paper-final-grace-python-20260421T191900Z` 中，`50/100/200 ms` 三组接近，而 `400 ms` 明显退化
5. `paper-final-network-jitter-20260422T000021Z` 中，`none/jitter10/jitter25` 三个标签下复用均保持正收益
6. `paper-final-network-fixed-delay-20260422T020028Z` 中，`none/fixed10/fixed25` 三个标签下复用均保持正收益
7. `paper-final-boundary-20260421T180132Z` 中，`slow_honest_n12` 三个标签均保持正收益，且两组最小拜占庭场景均完成归档

因此，当前真正还缺的已经不是最小正式冻结实验，而是把这些结果稳妥地回填进论文，并补跨机器最小复现与固定延迟附录整理。

## 当前仍只适合趋势核对的预备网络结果

- 网络扰动 smoke：
  `benchmarks/results/paper-network-smoke-20260416T000002Z/`
- 固定延迟 quick：
  `benchmarks/results/paper-network-fixed-delay-n12-quick-20260416T000001Z/`

这些结果说明网络扰动链路已经打通，且相关字段已经进入 `summaries.csv`、`reuse_deltas.csv` 与 `dumbo_paper_suite.json`。但它们仍属于预备性质数据，主要原因有三点。

1. 运行时工作树并非冻结状态。
2. 部分网络 quick 结果只有单次重复。
3. 其中固定延迟 quick 已被正式归档的 `paper-final-network-fixed-delay-20260422T020028Z/` 覆盖；若正文或附录需要引用固定延迟结果，应优先使用正式目录，而不是 quick 目录。

因此，这些目录适合用于当前论文主稿的趋势核对与实验方向确认，不应直接作为终稿正式图表来源。

## 当前最小拜占庭正式结果与边界

当前已经有一组最小节点级恶意行为正式归档结果：

- `benchmarks/results/paper-final-boundary-20260421T180132Z/`
  - `byzantine_silent_n12`
  - `byzantine_invalid_fetch_response_n12`

当前工作树已经具备两类最小节点级恶意行为注入能力：

- `silent`
- `invalid_fetch_response`

对应的配置入口已经接入：

- `benchmarks/configs/paper/dumbo_smoke.toml`
  - `smoke_byzantine_silent`
- `benchmarks/configs/paper/dumbo_comprehensive.toml`
  - `byzantine_silent_n12`
  - `byzantine_invalid_fetch_response_n12`

这些结果的定位应当是“最小边界验证”和“论文增强结果”，而不是“已系统验证一般拜占庭鲁棒性”。论文正文里可以据此写明：

1. 当前系统已经覆盖最小的节点级静默与损坏 fetch 响应场景
2. 这两种场景下复用仍保持正收益
3. 但这不等于已经系统覆盖更广义的拜占庭攻击空间

## 冻结规则

正式实验开始前，先满足以下条件。

1. 代码工作树应当干净，或者只允许存在不会影响结果的论文文稿改动。
2. 记录当前提交哈希：
   `git rev-parse HEAD`
3. 保存当前工作树摘要：
   `git status --short`
4. 将提交哈希、运行机器信息和输出目录写入实验笔记。

如果做不到第 1 条，就不要把该次结果作为论文终稿的正式图表来源。

## 预检查

从仓库根目录运行：

```bash
uv sync --dev --locked
cargo build --release -p honey-node -p honey-bench
typst compile paper/main-codex-refer.typ /tmp/honey4u-paper-check.pdf
```

建议在正式跑实验前，再执行一次轻量 dry-run：

```bash
target/release/honey-bench suite \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --list-experiments
```

## 推荐运行顺序

### 阶段 A：正文必需结果

这一阶段的结果已经具备正式归档目录。以下命令保留为“如需重新执行或在另一台机器复现时使用”的标准流程。

#### 1. 高负载主结果

用途：对应论文“高负载主结果”表格和主结论。

配置文件：
`benchmarks/configs/paper/dumbo_comprehensive.toml`

命令：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
target/release/honey-bench suite \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --experiments highload_n12 \
  --output-dir benchmarks/results/paper-final-highload-${RUN_TAG}
```

需要核查的输出文件：

- `dumbo_paper_suite.json`
- `summaries.csv`
- `reuse_deltas.csv`
- `backend_deltas.csv`
- `manifest.json`

#### 2. Python Grace 微实验

用途：对应论文“Grace 窗口敏感性”表格。

配置文件：
`benchmarks/configs/paper/dumbo_grace_python_micro.toml`

命令：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
target/release/honey-bench suite \
  --suite-config benchmarks/configs/paper/dumbo_grace_python_micro.toml \
  --output-dir benchmarks/results/paper-final-grace-python-${RUN_TAG}
```

#### 3. 慢诚实节点正式实验

用途：对应任务书中“诚实但迟到”场景下的增强实验；优先级高于固定延迟压力测试。

配置文件：
`benchmarks/configs/paper/dumbo_comprehensive.toml`

建议只抽取 `slow_honest_n12`：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
target/release/honey-bench suite \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --experiments slow_honest_n12 \
  --output-dir benchmarks/results/paper-final-slow-honest-${RUN_TAG}
```

建议至少检查：

- `summaries.csv` 中 `network_fault_label in {none, slow80p11, slow150p11}`
- `reuse_deltas.csv` 中复用开启相对基线的提升是否仍为正
- `manifest.json` 中 `executed_runs == planned_runs`

### 阶段 B：正文增强结果

这一阶段不是最小可交付集合，也不阻塞当前任务书封版，但强烈建议跑，因为它们能增强“规模趋势”和“后端收益”的说服力。

#### 3. 大规模 reuse sweep

用途：支撑“中大规模、高负载区间稳定受益”的叙述。

当前仓库已有历史结果：
`benchmarks/results/dumbo_reuse_sweep_20260408_large/`

如果需要在冻结版本上重跑，使用：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
uv run python benchmarks/cli/dumbo_reuse_sweep.py \
  --nodes 4,8,12,16 \
  --batches 1,2,4,8,16,32 \
  --rounds 4 \
  --repeats 2 \
  --global-timeout 180 \
  --output-dir benchmarks/results/paper-final-reuse-sweep-${RUN_TAG}
```

如果 CLI 参数后续有调整，应以 `--help` 的当前输出为准，但结果目录结构仍应保持可追溯。

#### 4. Python vs Rust FIN-style 后端比较

用途：对应论文“后端比较结果”部分。

当前仓库已有历史结果：
`benchmarks/results/dumbo-backend-reuse-20260410T093234Z/`

如果需要在冻结版本上重跑，使用：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
uv run python benchmarks/cli/tps.py \
  --backends python,rust_fin \
  --nodes 4,8,12 \
  --batch-size 32 \
  --rounds 4 \
  --repeats 2 \
  --global-timeout 180 \
  --pool-grace-ms 100 \
  --output-dir benchmarks/results/paper-final-backend-compare-${RUN_TAG}
```

#### 5. 随机抖动实验

用途：把网络实验从“单个慢诚实节点”扩展到“受控随机扰动”，增强实验部分的完整性。

配置文件：
`benchmarks/configs/paper/dumbo_comprehensive.toml`

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
target/release/honey-bench suite \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --experiments network_jitter_n12 \
  --output-dir benchmarks/results/paper-final-network-jitter-${RUN_TAG}
```

这一组的优先级低于 `slow_honest_n12`，高于 `fixed_delay_n12`。

#### 6. 固定延迟压力测试

用途：作为网络部分的压力测试补充，而不是正文最贴题的主证据。

配置文件：
`benchmarks/configs/paper/dumbo_comprehensive.toml`

当前已存在正式归档目录：
`benchmarks/results/paper-final-network-fixed-delay-20260422T020028Z/`

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
target/release/honey-bench suite \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --experiments network_fixed_delay_n12 \
  --output-dir benchmarks/results/paper-final-network-fixed-delay-${RUN_TAG}
```

#### 7. 最小拜占庭节点实验

用途：作为运行时边界与机制正确性补充验证，优先放在实验章节后半部分或附录，不取代高负载主结果。

配置文件：
`benchmarks/configs/paper/dumbo_comprehensive.toml`

建议先合并执行两组最小场景：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
target/release/honey-bench suite \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --experiments byzantine_silent_n12,byzantine_invalid_fetch_response_n12 \
  --output-dir benchmarks/results/paper-final-boundary-${RUN_TAG}
```

建议至少检查：

- `manifest.json` 中 `executed_runs == planned_runs`
- `summaries.csv` 中 `byzantine_label in {silent-p11, invalid_fetch_response-p11}`
- `summaries.csv` / `dumbo_paper_suite.json` 中链摘要仍一致
- 拜占庭动作计数非零，说明注入确实生效

建议额外导出一张摘要表，至少包含：

- `byzantine_invalid_fetch_responses_sent_total`
- `byzantine_fetch_requests_ignored_total`
- `byzantine_share_broadcast_suppressed_total`
- `byzantine_empty_proposal_rounds_total`

### 阶段 C：统一综合套件

这一阶段用于把前面分散的正式结果整合成一套统一归档。它适合作为最终封版动作，但不应先于阶段 A。

配置文件：
`benchmarks/configs/paper/dumbo_comprehensive.toml`

先 dry-run：

```bash
target/release/honey-bench suite \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --dry-run
```

如果时间有限，建议分批执行，而不是一次性全跑：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
target/release/honey-bench suite \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --experiments reuse_scale,highload_n12,backend_compare \
  --output-dir benchmarks/results/paper-final-core-suite-${RUN_TAG}
```

Rust 敏感性相关实验应在 fetch 相关叙事收口后单独执行：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
target/release/honey-bench suite \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --experiments sensitivity_grace_n12,sensitivity_reuse_limit_n12,sensitivity_expire_n12,sensitivity_mempool_n12 \
  --output-dir benchmarks/results/paper-final-rust-sensitivity-${RUN_TAG}
```

### 阶段 D：跨机器最小复现

这一阶段不要求把所有实验都重新跑一遍，而是要求确认“同一配置、同一提交、另一台机器上结果趋势仍一致”。

建议最小集合：

- `highload_n12`
- `slow_honest_n12`

建议记录：

- 机器型号与 CPU 信息
- 操作系统版本
- Python 版本
- Rust 版本
- 提交哈希
- 结果目录

论文中应把这一部分表述为“趋势级复现”，不要写成“跨机器数值完全一致复现”。

## 结果与论文映射

| 实验 | 建议数据源 | 对应论文部分 | 当前建议 |
| --- | --- | --- | --- |
| 高负载主结果 | `dumbo_comprehensive.toml` 中 `highload_n12` | 高负载主结果表 | 必跑 |
| Grace 窗口敏感性 | `dumbo_grace_python_micro.toml` | Grace 窗口敏感性表 | 已归档 |
| 慢诚实节点实验 | `dumbo_comprehensive.toml` 中 `slow_honest_n12` | “诚实但迟到”增强实验 | 已归档 |
| reuse_scale | `dumbo_comprehensive.toml` 中 `reuse_scale` | 规模趋势补充分析 | 建议跑，非阻塞 |
| backend_compare | `dumbo_comprehensive.toml` 中 `backend_compare` 或专用 compare CLI | 后端比较结果 | 建议跑，非阻塞 |
| network_jitter_n12 | `dumbo_comprehensive.toml` 中 `network_jitter_n12` | 网络扰动补充分析 | 已归档 |
| network_fixed_delay_n12 | `dumbo_comprehensive.toml` 中 `network_fixed_delay_n12` | 压力测试/附录 | 已归档 |
| byzantine_silent_n12 | `dumbo_comprehensive.toml` 中 `byzantine_silent_n12` | 运行时边界/鲁棒性补充 | 已归档 |
| byzantine_invalid_fetch_response_n12 | `dumbo_comprehensive.toml` 中 `byzantine_invalid_fetch_response_n12` | 运行时边界/鲁棒性补充 | 已归档 |
| Rust 参数敏感性 | `dumbo_comprehensive.toml` 中 `sensitivity_*` | 仅在 fetch 叙事稳定后考虑入正文 | 条件执行 |
| 跨机器最小复现 | 复用已冻结配置与命令 | 可复现性补充说明 | 交付前应完成 |

## 本轮不要直接写进正文的内容

在以下条件未满足前，不建议把相关数据写成论文主结果。

1. Rust fetch 指标尚未在冻结版本的正式 benchmark 中形成稳定、可复现的非零观测。
2. `rust_dumbo` 尚未形成与 `python`、`rust_fin` 同等成熟的已归档正式结果。
3. 当前 smoke/quick 网络结果来自未冻结工作树，不能直接写成正式图表。
4. 固定延迟更适合作为压力测试，不应替代“诚实但迟到”主场景。
5. 拜占庭节点注入当前仍处于最小能力阶段；虽然已有 `paper-final-boundary-20260421T180132Z/`，但仍不应写成“已全面验证拜占庭鲁棒性”。

## 每次正式运行后的验收清单

1. 确认 `manifest.json` 中 `executed_runs == planned_runs`。
2. 确认输出目录下存在 `dumbo_paper_suite.json` 或对应主 JSON。
3. 记录输出目录、提交哈希、运行日期和机器信息。
4. 从 CSV/JSON 中抽取将要写入论文的表格数值，不手工凭记忆转述。
5. 如果本次运行结果将进入正文图表，则把对应输出目录加入论文写作备注。

## 论文写作时的口径约束

1. 对通信成本统一使用“追踪通信成本”或“driver tracked bytes”，不要写成底层链路抓包总字节。
2. 对复用适用范围统一强调“被复用对象已具备强可用性保证”，不要扩张成“任意 ACS 黑盒”。
3. 对结果统一写成“中大规模、高负载区间稳定受益”，不要写成“所有参数点全面提升”。
4. 对网络实验统一区分“正式冻结结果”和“quick 预备结果”，不要混写。

## 建议提交边界

如果近期要把当前工作树整理成可审阅的提交，建议按下面顺序拆开，而不是把运行时、benchmark、论文和结果目录混成一个大提交。

### 1. 运行时与网络扰动能力

建议提交内容：

- `honey-node/src/transport/`
- `honey-node/src/driver_node/`
- `benchmarks/honey-bench/src/drive_dumbo.rs`
- `tests/runtime/test_network_local_nodes.py`

按当前工作树，可直接归入这一提交的文件包括：

- `benchmarks/honey-bench/src/drive_dumbo.rs`
- `honey-node/src/driver_node/mod.rs`
- `honey-node/src/driver_node/config/mod.rs`
- `honey-node/src/driver_node/output.rs`
- `honey-node/src/driver_node/round/loop.rs`
- `honey-node/src/driver_node/round/state.rs`
- `honey-node/src/driver_node/wire/fetch.rs`
- `honey-node/src/transport/local_tcp.rs`
- `honey-node/src/transport/mod.rs`
- `tests/runtime/test_network_local_nodes.py`

建议提交说明：

```text
feat(runtime): add controlled network fault injection and transport telemetry
```

### 2. benchmark/paper suite 链路

建议提交内容：

- `benchmarks/cli/tps.py`
- `benchmarks/honey-bench`
- `benchmarks/configs/paper/`
- `benchmarks/support/runners/`
- `tests/benchmarks/test_tps_cli.py`
- `tests/benchmarks/test_tps_cli.py`

按当前工作树，可直接归入这一提交的文件包括：

- `benchmarks/cli/__init__.py`
- `benchmarks/cli/tps.py`
- `benchmarks/cli/dumbo_reuse_sweep.py`
- `benchmarks/honey-bench`
- `benchmarks/cli/tps.py`
- `benchmarks/configs/paper/dumbo_comprehensive.toml`
- `benchmarks/configs/paper/dumbo_grace_python_micro.toml`
- `benchmarks/configs/paper/dumbo_grace_python_pilot.toml`
- `benchmarks/configs/paper/dumbo_smoke.toml`
- `benchmarks/support/runners/__init__.py`
- `benchmarks/support/runners/_core.py`
- `benchmarks/support/runners/results.py`
- `tests/benchmarks/test_tps_cli.py`
- `tests/benchmarks/test_tps_cli.py`

建议提交说明：

```text
feat(bench): add paper suite support for network perturbation experiments
```

### 3. 论文与实验文档

建议提交内容：

- `paper/main-codex-refer.typ`
- `paper/experiment-checklist.md`
- `AGENTS.md`
- `TODO.md`

按当前工作树，可直接归入这一提交的文件包括：

- `AGENTS.md`
- `TARGET.md`
- `TODO.md`
- `mid-term.md`
- `paper/main-codex-refer.typ`
- `paper/experiment-checklist.md`

建议提交说明：

```text
docs(thesis): expand implementation and experiment plan for final writeup
```

默认不要把 `benchmarks/results/` 一起提交，除非明确决定把某次运行作为仓库内的参考快照保留。
