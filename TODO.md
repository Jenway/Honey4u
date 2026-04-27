# TODO

## 当前用途

本文件当前主要用于记录 Honey4u 的终稿封版状态、剩余交付动作与历史工程计划。

其中需要区分两层含义：

1. 当前立即相关的是论文终稿、跨机复现与最终交付口径。
2. 本文件后半部分保留的网络扰动 / 拜占庭注入方案与 Phase 计划，主要作为历史工程记录与可追溯设计说明，而不再表示“下一步还必须补完的协议功能”。

当前仓库已经具备受控网络扰动实验与最小拜占庭节点注入能力，且已有正式归档结果；因此本文档不再把这些能力视为待实现目标，而是把它们作为已完成背景，服务于论文收尾与结果解释。

当前仓库结构重构也已完成：核心 Rust crate 已展平到仓库根目录的 `honey-crypto/`、`honey-wire/`、`honey-acs/`、`honey-node/`，Python ACS 包已迁入 `honey-acs/packages/honey-acs/`，PyO3 扩展已迁入 `honey-acs/honey-native/`，旧的根目录 `packages/` 和 `native/` 前缀不再作为源码位置使用。

## 当前现状

- 一句话判断：
  - 任务书的核心实现与实验主线可视为已完成，当前主要剩余工作是论文终稿、附录整合与最小跨机复现。
- 当前没有剩余的仓库内协议阻塞项；未封口内容主要是论文终稿与仓库外收尾动作。
- 按当前交付视角，剩余阻塞项可以压缩为三类：
  - 论文主稿正文、图表、附录与最终口径收口
  - 最小跨机器趋势复现实验
  - 论文封面个人信息填写与最终 PDF 导出

- 对照任务书的当前判断：
  - 复用机制实现：已完成
  - 安全性/活性工程验证：已完成当前范围内验证；现有正式归档结果与测试链路已足以支撑当前论文口径
  - 高负载吞吐提升 10% 以上：已完成
  - 稳定系统、完整文档与论文：代码与最小正式实验包已基本就绪，剩余主要是论文定稿
- 已完成的实验主线：
  - reuse on/off sweep
  - Python vs Rust FIN-style backend compare
  - N=12 高负载主结果正式归档
  - Python Grace 参数敏感性正式归档
  - `network_jitter_n12` 正式归档结果
  - `network_fixed_delay_n12` 正式归档结果
  - `slow_honest_n12` 正式归档结果
  - 最小拜占庭节点正式归档结果：`byzantine_silent_n12`、`byzantine_invalid_fetch_response_n12`
- 已完成的实验能力：
  - 受控网络扰动注入
  - `slow_honest` 场景 quick result
  - 初步拜占庭节点模拟：`silent`、`invalid_fetch_response`
- 已接入但尚未形成正式主结果的内容：
  - fetch request/response 统计
  - `rust_dumbo` backend compare 入口
- 尚未完成的内容：
  - 论文终稿收口与图表回填
  - 已归档固定延迟压力测试的附录化整合
  - 另一台机器上的最小复现实验
  - 论文封面个人信息填写：`author`、`school_id`、`grade`、`supervisor`
  - 论文最终排版、图表导出与答辩用精简表达

- 当前无法仅靠继续修改仓库源码来自动完成的两项：
  - 跨机器最小复现实验：需要另一台机器或另一套环境执行
  - 论文封面个人信息：需要人工填写真实信息

## 新增正式结果

已新增归档目录：

- `benchmarks/results/paper-final-highload-20260421T182250Z`
- `benchmarks/results/paper-final-grace-python-20260421T191900Z`
- `benchmarks/results/paper-final-boundary-20260421T180132Z`
- `benchmarks/results/paper-final-network-jitter-20260422T000021Z`
- `benchmarks/results/paper-final-network-fixed-delay-20260422T020028Z`

当前可直接利用的新增结论：

- `highload_n12` 全部已测 Python / `rust_fin` 批大小上，复用开启后吞吐提升均保持为正，继续满足任务书 `10%` 目标
- `grace_python_n12_micro` 中，`50/100/200 ms` 三组相近，`400 ms` 出现明显退化，可直接支持 Grace 敏感性分析
- `network_jitter_n12` 中，`none/jitter10/jitter25` 三个标签下复用均保持正收益，且较强 jitter 下相对收益进一步放大
- `network_fixed_delay_n12` 中，`none/fixed10/fixed25` 三个标签下复用均保持正收益，且较大固定延迟下相对收益进一步放大
- `slow_honest_n12` 三个场景下，复用开启相对基线均保持正收益
- `byzantine_silent_n12` 下，复用仍保持正收益，且出现了非零 fetch 观测
- `byzantine_invalid_fetch_response_n12` 下，复用仍保持正收益，系统未因损坏 fetch 响应而失稳
- `paper/main-codex-refer.typ` 已经按高负载、Grace、边界、jitter 与 fixed-delay 正式归档结果回填，并通过 `typst compile`

## 任务书收尾重点

当前最关键的缺口已经不是协议核心功能，而是把现有实现收敛成一套能交付、能复查、能写进论文终稿的冻结材料。具体优先级如下。

1. 用现有已归档结果回填论文正文、表格、图注与有效性威胁分析。
2. 在另一台机器上补一次最小复现实验，增强可复现性表述。
3. 把已归档的 `network_fixed_delay_n12` 整理为附录级压力测试说明，而不是继续把它当作待补实验。
4. 把论文终稿与答辩材料压缩成一套口径统一的最终版本。

### 当前建议立即执行顺序

1. 在 `paper/main-codex-refer.typ` 中完成最终表格、图注、附录定位与威胁分析收口。
2. 在另一台机器上补最小趋势复现：
   - `highload_n12`
   - `slow_honest_n12`
3. 填写论文封面信息：
   - `author`
   - `school_id`
   - `grade`
   - `supervisor`
4. 导出最终 PDF 前，统一检查摘要、结论、附录和答辩三点贡献总结的口径。

### 任务书可视为全部完成的判据

同时满足以下四项即可视为当前课题已完成交付：

1. `paper/main-codex-refer.typ` 已完成终稿级正文、表格、图注、附录与有效性威胁收口。
2. 最小跨机器趋势复现实验已完成，并保存结果目录与运行信息。
3. 论文封面个人信息已填写完整，终稿 PDF 可稳定编译导出。
4. 最终文稿口径已统一：
   - `fixed-delay` 仅作附录级压力测试
   - `fetch` 仅作边界观察
   - 不扩张为任意 ACS 黑盒、真实 WAN 或一般 Byzantine 鲁棒性结论

## 优先级分层

### P0：必须先完成

- 把已冻结结果整理成论文正文所需内容：
  - 表格
  - 图表
  - 指标说明
  - 有效性威胁
- 完成终稿层面的收口：
  - 图表编号与交叉引用
  - 摘要与结论一致性
  - 答辩可复述的三点贡献总结
- 收紧论文措辞，明确区分：
  - 已实现并已归档验证的结论
  - 仅作为增强项或未来工作的方向

已完成的 P0 子项：

- `highload_n12`
- `grace_python_n12_micro`
- `slow_honest_n12`
- `byzantine_silent_n12`
- `byzantine_invalid_fetch_response_n12`

### P1：交付前应完成

- 在另一台机器上做一次最小复现实验：
  - 同一 commit
  - 同一 TOML
  - 同一命令
  - 只比较趋势，不要求数值完全一致
  - 说明：这项同时属于“任务书可视为全部完成的判据”，不是可选增强项
- 将已归档的附录级网络压力测试整理进论文补充：
  - `network_fixed_delay_n12`
- 论文实验部分补一张“恶意行为计数/拒绝情况”小表

### P2：有余力再做

- 继续补一种与复用机制关系最直接的恶意行为：
  - `invalid_reference_proposal`
- 提高正式实验重复次数：
  - 每组 `repeats = 3`
  - 给均值和简单误差条

### 当前不建议继续扩张的方向

- 独立 WAN 代理或完整网络中间件
- 新协议家族、新 ACS 黑盒或新的 MVBA 路线
- 通用化的复杂 Byzantine 攻击框架
- 仅为“更好看”而做的大规模代码重构

## 交稿前人工检查项

- 填写论文封面个人信息：
  - `author`
  - `school_id`
  - `grade`
  - `supervisor`
- 检查摘要、中英文关键词、结论三处表述是否一致
- 检查所有表格编号、图注、交叉引用是否完整
- 检查固定延迟结果是否只出现在附录级压力测试语境，不与慢诚实主证据混写
- 检查 `fetch` 统计是否仍保持“边界观察”口径，而未被写成主结论
- 导出最终 PDF 前再执行一次：
  - `typst compile paper/main-codex-refer.typ`
  - 最小跨机复现实验完成后的结果核对

## 设计原则

说明：从本节开始，以下内容主要保留为历史工程方案、实现边界与执行记录，便于论文写作和结果追溯；除非与上面的“当前现状 / 任务书收尾重点 / 当前直接实施起点”冲突，否则不应再将其理解为当前第一优先级待办。

- 先做最小可用版本，不一开始追求“通用网络模拟器”。
- 网络扰动和拜占庭行为都必须可配置、可复现、可记录到结果 JSON。
- 所有实验都必须保留随机种子或明确的静态参数。
- 优先从外层 driver 和 transport 边界注入行为，不优先侵入 ACS 核心逻辑。
- 论文主结果只纳入稳定、可复现、不会频繁超时的场景。

## 总体方案

### A. 网络扰动能力

优先在 `honey-node/src/transport/local_tcp.rs` 的发送路径加入受控扰动，而不是单独再起一个 TCP 代理程序。

原因：

- 当前本地 benchmark 已经稳定依赖 `LocalTcpTransport`。
- `LocalTcpTransport` 的 sender loop 天然掌握 `(sender_pid, recipient_pid, payload)` 这三个关键信息。
- 在发送侧做延迟、抖动、丢弃更容易保持实现简单，也更容易在 telemetry 里计数。
- 对论文来说，“固定延迟 / 抖动 / 慢诚实节点”已经足够回答主要问题，不必先做全功能网络中间件。

### B. 拜占庭节点注入能力

优先在 `rust-driver` / `honey-node/src/node_runtime/` 的外层 driver/transport 边界注入恶意行为，而不是修改 Python/Rust ACS host 内核。

原因：

- 当前 `honey-node` 已经是多进程节点外壳，适合把“某个 pid 是否恶意”作为节点级配置处理。
- 这样可以保持 ACS backend 本身更干净，也更容易对比同一 backend 在不同节点行为下的表现。
- 对复用机制最有意义的恶意行为，主要集中在“引用、fetch、发送时机”这几个边界，而不是所有协议细节。

## 配置扩展设计

继续沿用 `bench-driver` 的 TOML 文件，在 `[config]` 下扩展嵌套字段，最终经 `config_json` 传入 `run-driver-node`。

建议新增两组配置：

### 1. 网络扰动配置

```toml
[config.network_faults]
enabled = true
seed = 20260416
fixed_delay_ms = 0
jitter_ms = 0
drop_rate = 0.0

[config.network_faults.slow_honest]
pids = [11]
extra_delay_ms = 150
```

第一阶段只要求支持：

- `fixed_delay_ms`
- `jitter_ms`
- `slow_honest.pids`
- `slow_honest.extra_delay_ms`

第二阶段再考虑：

- `drop_rate`
- link-specific delay
- frame duplication
- reordering

### 2. 拜占庭节点配置

```toml
[[config.byzantine_nodes]]
pid = 11
behavior = "silent"

[[config.byzantine_nodes]]
pid = 10
behavior = "invalid_fetch_response"
```

当前已实现的第一阶段行为：

- `silent`
  - 节点保持进程存活，但不发送 ACS 外发流量或不提交有效提案
- `invalid_fetch_response`
  - 收到 fetch request 时返回格式正确但验证失败的响应

暂缓但可选扩展：

- `invalid_reference_proposal`
  - 节点主动发出带伪造引用或不可验证引用的提案

延后行为：

- `equivocate`
- `spam`
- `corrupt_random_wire`
- `adaptive_drop`

## 代码落点

### 1. 配置解析

文件：

- `honey-node/src/node_runtime/config.rs`
- `honey-node/src/cli.rs`

任务：

- 新增 `NetworkFaultConfig`
- 新增 `SlowHonestConfig`
- 新增 `ByzantineNodeConfig`
- 解析 `config_json` 中的网络扰动和拜占庭配置
- 在配置为空时保持完全向后兼容

### 2. 传输层扰动

文件：

- `honey-node/src/transport/local_tcp.rs`
- `honey-node/src/node_runtime/mod.rs`

任务：

- 给 `LocalTcpTransport::new(...)` 追加网络扰动配置入口
- 在 sender loop 注入：
  - 固定延迟
  - 抖动
  - 慢诚实节点的额外发送延迟
- 为 drop 行为预留接口，但第一阶段可只做 `delay/jitter/slow honest`
- 保证每个 sender loop 使用确定性 seed

### 3. Driver 级拜占庭行为

文件：

- `honey-node/src/node_runtime/round/driver.rs`
- `honey-node/src/node_runtime/types.rs`
- `honey-node/src/node_runtime/result.rs`

任务：

- 在每个节点启动时识别自己是否为恶意 pid
- 在外发 ACS wire / fetch response / 本地提案准备阶段插入行为分支
- 对恶意行为做显式 telemetry 计数
- 保证诚实节点最终结果仍可用于判断 safety/liveness

### 4. Python benchmark 汇总链路

文件：

- `benchmarks/support/runners/_core.py`
- `benchmarks/cli/tps.py`
- `benchmarks/honey-bench/src/suite.rs`

任务：

- 接收并解析新的 runtime 结果字段
- 在 benchmark summary 中输出：
  - injected delay stats
  - dropped frame stats
  - byzantine action counters
  - run seed
- 让 suite 配置支持新的维度展开

### 5. 论文实验配置

文件：

- `benchmarks/configs/paper/dumbo_comprehensive.toml`
- 新增若干 paper config

当时建议新增实验组：

- `network_fixed_delay_n12`
- `network_jitter_n12`
- `slow_honest_n12`
- `byzantine_silent_n12`
- `byzantine_invalid_fetch_n12`
- `byzantine_invalid_reference_n12`

## 分阶段执行计划

说明：

- 本节主要保留工程推进过程中的阶段化记录。
- 若本节与前文“当前现状 / 新增正式结果 / 任务书收尾重点”冲突，以上方最新状态为准。

### Phase 0: 基线冻结与结果口径准备（已完成）

目标：

- 在引入新实验前先稳定当前 benchmark 基线

任务：

- 整理 benchmark/paper 相关未提交文件
- 确认 `paper-final-highload-*` 与 `paper-final-grace-python-*` 的口径
- 保持 `TODO.md`、论文主稿和 benchmark config 同步

完成标准：

- 当前正式实验入口和结果目录结构不再频繁变动

### Phase 1: 最小网络扰动能力（已完成）

目标：

- 做出可复现的“固定延迟 + 抖动 + 慢诚实节点”实验能力

任务：

- 在 transport sender loop 上加入可配置延迟注入
- 加入 deterministic seed
- 把扰动统计写入 node result JSON
- 给 `tps.py` 和 runner dataclass 补齐新字段

建议先支持的场景：

- 全局固定延迟：`50ms / 100ms / 200ms`
- 全局随机抖动：`uniform[0, 50]ms`、`uniform[0, 100]ms`
- 单个慢诚实节点：`pid=11, extra_delay=150ms`

当前进展：

- 已在 `LocalTcpTransport` sender loop 接入 `fixed_delay_ms`、`jitter_ms`、`slow_honest.extra_delay_ms`
- 已支持 deterministic seed，并把扰动统计写入 node result JSON
- `benchmarks/support/runners/_core.py`、`benchmarks/cli/tps.py` 已能携带和输出 `network_faults` 配置与注入统计
- runtime smoke test 已覆盖固定延迟与慢诚实节点两类场景

完成标准：

- 本地 TCP benchmark 在这些场景下仍能稳定完成
- 同一个 seed 的重复运行结果趋势一致
- 输出 JSON 中能看到注入统计

### Phase 2: 网络扰动实验接入论文 suite（已完成，正式结果已归档）

目标：

- 让网络扰动变成真正可批量执行的论文实验

任务：

- 扩展 `honey-bench suite` 的维度定义
- 新增网络扰动实验配置文件
- 输出单独的 summary/delta 表

建议实验矩阵：

- backend:
  - `python`
  - `rust_fin`
- reuse:
  - `off`
  - `on`
- scenario:
  - fixed delay
  - jitter
  - slow honest
- batch:
  - 32
- nodes:
  - 12

当前进展：

- `honey-bench suite` 已支持 `network_faults` 维度展开和可读标签分组
- `benchmarks/configs/paper/dumbo_smoke.toml` 与 `benchmarks/configs/paper/dumbo_comprehensive.toml` 已补入固定延迟、抖动、慢诚实节点实验条目
- 已形成正式网络结果目录：
  - `paper-final-network-jitter-20260422T000021Z`
  - `paper-final-network-fixed-delay-20260422T020028Z`
- 与任务书最直接对应的 `slow_honest_n12` 结果已并入 `paper-final-boundary-20260421T180132Z`

完成标准：

- 能形成一套 `paper-final-network-*` 目录
- 能回答“复杂网络下复用是否仍有效”

### Phase 3: 最小拜占庭节点注入能力（第一阶段已完成）

目标：

- 做出与当前复用机制最相关的最小节点级恶意行为

任务：

- `silent`
- `invalid_fetch_response`
- `invalid_reference_proposal`（后续可选扩展，不阻塞论文主线）

实现建议：

- `silent`
  - 在 driver 外发路径丢弃本节点 ACS/driver payload
- `invalid_fetch_response`
  - 在处理 fetch request 时构造可解码但校验失败的响应
- `invalid_reference_proposal`
  - 在构造提案时塞入错误 `item_id` 或错误证明绑定

关键要求：

- 恶意行为必须可定位到具体 pid
- 诚实节点必须显式记录“拒绝了多少恶意输入”
- 不允许恶意实现直接把进程打崩，除非该行为本身就是 crash-only 模式

完成标准：

- 在 `f` 范围内，诚实节点仍能完成轮次并保持 chain digest 一致
- 统计结果能区分“协议失败”和“恶意输入被成功过滤”

当前进展：

- `silent` 已实现：
  - 节点提交空提案
  - 抑制外层 `HbBatch` 广播
  - 抑制 `HbShareBundle` 广播
  - 忽略 fetch 服务
- `invalid_fetch_response` 已实现：
  - 节点在 fetch 响应路径返回可解码但校验失败的损坏 payload
- `invalid_reference_proposal` 尚未实现：
  - 该行为更容易侵入提案构造与引用验证边界，当前不作为任务书收尾的必需项

当前判断：

- 第一阶段最小拜占庭节点注入能力已达成
- 对应的最小正式 benchmark 结果也已完成归档
- 当前真正的下一步已不再是补 Byzantine 场景，而是把这些结果整合进论文终稿与答辩材料

### Phase 4: 拜占庭实验接入论文 suite（最小正式结果已完成）

目标：

- 把拜占庭场景纳入正式 benchmark 链路

任务：

- 增加专门的 byzantine config
- 在 summary 中记录：
  - 完成率
  - chain digest agreement
  - 被拒绝的恶意输入计数
  - throughput/latency/bytes per tx

建议场景：

- `1` 个 silent node
- `1` 个 invalid fetch responder
- `1` 个 invalid reference proposer

建议先固定：

- `N=12, f=3`
- backend:
  - `python`
  - `rust_fin`
- batch:
  - `32`
- reuse:
  - `on`
  - `off`

完成标准：

- 形成最小边界故障正式结果目录，例如 `paper-final-boundary-*`
- 论文可保守表述“在简单恶意行为下观察到机制仍保持正确性边界内运行”

当前结果：

- 已形成 `paper-final-boundary-20260421T180132Z`
- 已覆盖：
  - `byzantine_silent_n12`
  - `byzantine_invalid_fetch_response_n12`
- `invalid_reference_proposal` 仍未实现，也不属于任务书收尾必需项

### Phase 5: 正式封版实验与论文回填（核心结果已完成，论文终稿仍在收口）

目标：

- 在干净工作树上重跑最终需要写进正文的结果

任务：

- 已完成：
  - 高负载主结果正式归档
  - Grace 微实验正式归档
  - 网络扰动核心结果正式归档
  - 最小拜占庭核心结果正式归档
  - `paper/main-codex-refer.typ` 一轮回填与编译检查
- 剩余：
  - 论文终稿图表/图注/附录整合
  - 跨机器最小复现
  - 答辩口径压缩与最终校对

完成标准：

- `manifest.json` 中 `executed_runs == planned_runs`
- `git status --short` 干净或只剩论文文稿
- 论文中的每个表格都能回溯到对应结果目录

## 测试计划

### 单元测试

新增或扩展：

- `tests/benchmarks/test_tps_cli.py`
  - 新字段解析
  - 新 summary 输出
- `honey-node` Rust tests
  - 网络扰动配置解析
  - 慢诚实节点延迟注入
  - 恶意 fetch response 被拒绝
  - 恶意 reference 被拒绝

### 运行时集成测试

新增：

- `tests/runtime/test_network_local_nodes.py`
  - fixed delay 场景仍能完成
  - jitter 场景仍能完成
  - slow honest 场景仍能完成
- 新建或扩展 Dumbo runtime tests
  - silent node 场景
  - invalid fetch response 场景
  - invalid reference proposal 场景

### Benchmark 验证

至少形成以下 smoke cases：

- `N=4, f=1, fixed_delay_ms=50`
- `N=4, f=1, jitter_ms=50`
- `N=4, f=1, slow_honest pid=3`
- `N=4, f=1, byzantine pid=3 behavior=silent`
- `N=4, f=1, byzantine pid=3 behavior=invalid_fetch_response`

## 结果指标扩展

建议新增统计字段：

- 网络扰动：
  - `injected_delay_ms_total`
  - `delayed_frames`
  - `dropped_frames`
  - `network_fault_seed`
- 拜占庭行为：
  - `byzantine_actions_sent`
  - `invalid_fetch_responses_rejected`
  - `invalid_references_rejected`
  - `silent_nodes_configured`
- 稳定性：
  - `run_completed`
  - `chain_digest_agreement`
  - `rounds_completed`

## 论文可用的最小实验包

当前判断：下列最小集合已经全部具备正式或可直接引用的归档结果。

如果时间有限，最小可交付集合应是：

1. `N=12` 下固定延迟场景
2. `N=12` 下抖动场景
3. `N=12` 下单慢诚实节点场景
4. `N=12` 下单 silent 恶意节点场景
5. `N=12` 下单 invalid fetch response 恶意节点场景

对应目录：

- `paper-final-network-fixed-delay-20260422T020028Z`
- `paper-final-network-jitter-20260422T000021Z`
- `paper-final-boundary-20260421T180132Z`

不建议在论文正式版里优先写入以下内容，除非实现和结果已经稳定：

- `drop_rate > 0` 的大量丢包场景
- frame reorder
- 多种恶意行为混合
- `rust_dumbo` 与 `python`/`rust_fin` 同等规模的正式比较

## 风险与约束

- 网络扰动会放大 timeout 风险，因此相关实验必须同步调整 `global_timeout`。
- 若在 transport 层实现 drop，需要严格区分“受控实验性丢弃”和“真实连接错误”。
- 拜占庭行为若直接修改 ACS host 核心消息，容易导致进程崩溃，第一阶段不建议这么做。
- 对论文口径必须保持保守：
  - 只能写“已做受控网络扰动/简单恶意行为实验”
  - 不能写“已全面验证真实 WAN 和通用拜占庭鲁棒性”

## 建议执行顺序

说明：以下顺序是历史工程推进顺序，当前不再表示“下一步立即执行”。

1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5

## 当前直接实施起点

按目前完成度，最应该立刻做的具体任务已经不再是补协议或补最小正式实验，而是：

1. 在另一台机器上补一次最小趋势复现：
   - `highload_n12`
   - `slow_honest_n12`
2. 把正式归档结果完全整理进论文终稿：
   - 高负载主表
   - Grace 表
   - 边界场景表
   - 抖动与固定延迟的正文/附录定位
3. 收紧最终论文与答辩口径：
   - fetch 统计只作边界观察，不升格为主结论
   - 固定延迟只作附录级压力测试
   - 不把本地受控实验扩张表述为真实 WAN 或一般拜占庭鲁棒性
