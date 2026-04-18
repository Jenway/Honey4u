# 论文正式实验执行清单

## 目的

这份清单用于把 Honey4u 当前已经具备的 benchmark 工具链，整理成一套适合毕业论文正文引用的正式实验流程。目标不是继续探索新协议，而是冻结一版可复现、可追溯、可直接对应论文表格和结论的结果集。

## 当前可直接引用的已归档结果

- 高负载主结果：
  `benchmarks/results/dumbo-paper-suite-20260411T134114Z/`
- Python Grace 微实验：
  `benchmarks/results/dumbo-paper-suite-20260412T030807Z/`
- 大规模 reuse sweep：
  `benchmarks/results/dumbo_reuse_sweep_20260408_large/`
- Python vs Rust FIN-style 后端比较：
  `benchmarks/results/dumbo-backend-reuse-20260410T093234Z/`

这些结果已经足够支撑当前论文草稿的主结论，但它们来自不同次运行。正式定稿前，应在冻结代码版本上重新组织并执行一次统一流程。

## 当前最新的统一重跑结果

- 高负载主结果重跑：
  `benchmarks/results/paper-final-highload-20260415T182439Z/`
- Python Grace 微实验重跑：
  `benchmarks/results/paper-final-grace-python-20260415T183425Z/`

这两次运行已经更贴近论文当前表格所引用的数据口径，但对应 `manifest.json` 中的 `git.status_short` 仍然非空。它们适合用于当前草稿更新与数值核对，不应直接当作最终冻结版图表来源。

## 当前新增但尚未冻结的网络实验结果

- 网络扰动 smoke：
  `benchmarks/results/paper-network-smoke-20260416T000002Z/`
- 固定延迟 quick：
  `benchmarks/results/paper-network-fixed-delay-n12-quick-20260416T000001Z/`
- 慢诚实节点 quick：
  `benchmarks/results/paper-slow-honest-n12-quick-20260416T000001Z/`

这些结果说明网络扰动链路已经打通，且相关字段已经进入 `summaries.csv`、`reuse_deltas.csv` 与 `dumbo_paper_suite.json`。但它们仍属于预备性质数据，主要原因有三点。

1. 运行时工作树并非冻结状态。
2. 部分网络 quick 结果只有单次重复。
3. 其中固定延迟更像压力测试，慢诚实节点才真正对应任务书中的“诚实但迟到”。

因此，这些目录适合用于当前论文草稿的趋势核对与实验方向确认，不应直接作为终稿正式图表来源。

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
cargo build --manifest-path native/Cargo.toml --release --bin honey-node
typst compile paper/main-codex-refer.typ /tmp/honey4u-paper-check.pdf
```

建议在正式跑实验前，再执行一次轻量 dry-run：

```bash
uv run python benchmarks/cli/dumbo_paper_suite.py \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --list-experiments
```

## 推荐运行顺序

### 阶段 A：正文必需结果

这一阶段的结果应优先冻结，因为它们直接对应论文当前正文中的表格和核心结论。

#### 1. 高负载主结果

用途：对应论文“高负载主结果”表格和主结论。

配置文件：
`benchmarks/configs/paper/dumbo_highload_pilot.toml`

命令：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
uv run python benchmarks/cli/dumbo_paper_suite.py \
  --suite-config benchmarks/configs/paper/dumbo_highload_pilot.toml \
  --all \
  --binary native/target/release/honey-node \
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
uv run python benchmarks/cli/dumbo_paper_suite.py \
  --suite-config benchmarks/configs/paper/dumbo_grace_python_micro.toml \
  --all \
  --binary native/target/release/honey-node \
  --output-dir benchmarks/results/paper-final-grace-python-${RUN_TAG}
```

#### 3. 慢诚实节点正式实验

用途：对应任务书中“诚实但迟到”场景下的增强实验；优先级高于固定延迟压力测试。

配置文件：
`benchmarks/configs/paper/dumbo_comprehensive.toml`

建议只抽取 `slow_honest_n12`：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
uv run python benchmarks/cli/dumbo_paper_suite.py \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --experiments slow_honest_n12 \
  --binary native/target/release/honey-node \
  --output-dir benchmarks/results/paper-final-slow-honest-${RUN_TAG}
```

建议至少检查：

- `summaries.csv` 中 `network_fault_label in {none, slow80p11, slow150p11}`
- `reuse_deltas.csv` 中复用开启相对基线的提升是否仍为正
- `manifest.json` 中 `executed_runs == planned_runs`

### 阶段 B：正文增强结果

这一阶段不是最小可交付集合，但强烈建议跑，因为它们能增强“规模趋势”和“后端收益”的说服力。

#### 3. 大规模 reuse sweep

用途：支撑“中大规模、高负载区间稳定受益”的叙述。

当前仓库已有历史结果：
`benchmarks/results/dumbo_reuse_sweep_20260408_large/`

如果需要在冻结版本上重跑，使用：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
uv run python benchmarks/cli/dumbo_reuse_sweep.py \
  --binary native/target/release/honey-node \
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
uv run python benchmarks/cli/dumbo_backend_reuse_compare.py \
  --binary native/target/release/honey-node \
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
uv run python benchmarks/cli/dumbo_paper_suite.py \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --experiments network_jitter_n12 \
  --binary native/target/release/honey-node \
  --output-dir benchmarks/results/paper-final-network-jitter-${RUN_TAG}
```

这一组的优先级低于 `slow_honest_n12`，高于 `fixed_delay_n12`。

#### 6. 固定延迟压力测试

用途：作为网络部分的压力测试补充，而不是正文最贴题的主证据。

配置文件：
`benchmarks/configs/paper/dumbo_comprehensive.toml`

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
uv run python benchmarks/cli/dumbo_paper_suite.py \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --experiments network_fixed_delay_n12 \
  --binary native/target/release/honey-node \
  --output-dir benchmarks/results/paper-final-network-fixed-delay-${RUN_TAG}
```

### 阶段 C：统一综合套件

这一阶段用于把前面分散的正式结果整合成一套统一归档。它适合作为最终封版动作，但不应先于阶段 A。

配置文件：
`benchmarks/configs/paper/dumbo_comprehensive.toml`

先 dry-run：

```bash
uv run python benchmarks/cli/dumbo_paper_suite.py \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --all \
  --dry-run
```

如果时间有限，建议分批执行，而不是一次性全跑：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
uv run python benchmarks/cli/dumbo_paper_suite.py \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --experiments reuse_scale,highload_n12,backend_compare \
  --binary native/target/release/honey-node \
  --output-dir benchmarks/results/paper-final-core-suite-${RUN_TAG}
```

Rust 敏感性相关实验应在 fetch 相关叙事收口后单独执行：

```bash
RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)
uv run python benchmarks/cli/dumbo_paper_suite.py \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --experiments sensitivity_grace_n12,sensitivity_reuse_limit_n12,sensitivity_expire_n12,sensitivity_mempool_n12 \
  --binary native/target/release/honey-node \
  --output-dir benchmarks/results/paper-final-rust-sensitivity-${RUN_TAG}
```

## 结果与论文映射

| 实验 | 建议数据源 | 对应论文部分 | 当前建议 |
| --- | --- | --- | --- |
| 高负载主结果 | `dumbo_highload_pilot.toml` | 高负载主结果表 | 必跑 |
| Grace 窗口敏感性 | `dumbo_grace_python_micro.toml` | Grace 窗口敏感性表 | 必跑 |
| 慢诚实节点实验 | `dumbo_comprehensive.toml` 中 `slow_honest_n12` | “诚实但迟到”增强实验 | 强烈建议跑 |
| reuse_scale | `dumbo_comprehensive.toml` 中 `reuse_scale` | 规模趋势补充分析 | 建议跑 |
| backend_compare | `dumbo_comprehensive.toml` 中 `backend_compare` 或专用 compare CLI | 后端比较结果 | 建议跑 |
| network_jitter_n12 | `dumbo_comprehensive.toml` 中 `network_jitter_n12` | 网络扰动补充分析 | 建议跑 |
| network_fixed_delay_n12 | `dumbo_comprehensive.toml` 中 `network_fixed_delay_n12` | 压力测试/附录 | 条件执行 |
| Rust 参数敏感性 | `dumbo_comprehensive.toml` 中 `sensitivity_*` | 仅在 fetch 叙事稳定后考虑入正文 | 条件执行 |

## 本轮不要直接写进正文的内容

在以下条件未满足前，不建议把相关数据写成论文主结果。

1. Rust fetch 指标尚未在冻结版本的正式 benchmark 中形成稳定、可复现的非零观测。
2. `rust_dumbo` 尚未形成与 `python`、`rust_fin` 同等成熟的已归档正式结果。
3. 当前 quick 网络结果来自未冻结工作树，不能直接写成正式图表。
4. 固定延迟更适合作为压力测试，不应替代“诚实但迟到”主场景。

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

- `native/honey-node/src/transport/`
- `native/honey-node/src/network_driver/`
- `native/honey-node/src/drive_dumbo.rs`
- `tests/runtime/test_network_local_nodes.py`

按当前工作树，可直接归入这一提交的文件包括：

- `native/honey-node/src/drive_dumbo.rs`
- `native/honey-node/src/network_driver.rs`
- `native/honey-node/src/network_driver/config.rs`
- `native/honey-node/src/network_driver/result.rs`
- `native/honey-node/src/network_driver/round.rs`
- `native/honey-node/src/network_driver/types.rs`
- `native/honey-node/src/pool_wire.rs`
- `native/honey-node/src/transport/local_tcp.rs`
- `native/honey-node/src/transport/mod.rs`
- `tests/runtime/test_network_local_nodes.py`

建议提交说明：

```text
feat(runtime): add controlled network fault injection and transport telemetry
```

### 2. benchmark/paper suite 链路

建议提交内容：

- `benchmarks/cli/tps.py`
- `benchmarks/cli/dumbo_paper_suite.py`
- `benchmarks/configs/paper/`
- `benchmarks/support/runners/`
- `tests/benchmarks/test_tps_cli.py`
- `tests/benchmarks/test_dumbo_paper_suite.py`

按当前工作树，可直接归入这一提交的文件包括：

- `benchmarks/cli/__init__.py`
- `benchmarks/cli/dumbo_backend_reuse_compare.py`
- `benchmarks/cli/dumbo_reuse_sweep.py`
- `benchmarks/cli/dumbo_paper_suite.py`
- `benchmarks/cli/tps.py`
- `benchmarks/configs/paper/dumbo_comprehensive.toml`
- `benchmarks/configs/paper/dumbo_grace_python_micro.toml`
- `benchmarks/configs/paper/dumbo_grace_python_pilot.toml`
- `benchmarks/configs/paper/dumbo_highload_pilot.toml`
- `benchmarks/configs/paper/dumbo_smoke.toml`
- `benchmarks/support/runners/__init__.py`
- `benchmarks/support/runners/_core.py`
- `benchmarks/support/runners/results.py`
- `tests/benchmarks/test_tps_cli.py`
- `tests/benchmarks/test_dumbo_paper_suite.py`

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
