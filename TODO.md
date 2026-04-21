# TODO

## 目标

为 `Honey4u` 增加一套完整、可复现、可写入论文的增强实验能力，重点覆盖两类当前缺失的系统级场景：

1. 受控网络扰动实验
2. 拜占庭节点注入实验

本计划默认基于当前 `rust-driver` 架构推进，不引入额外外部代理进程，也不重新设计新的运行时。优先复用已有的 `bench-driver --config <toml>`、`config_json`、`LocalTcpTransport`、`network_driver` 结果汇总链路。

## 当前现状

- 对照任务书的当前判断：
  - 复用机制实现：已完成
  - 安全性/活性工程验证：已完成当前范围内验证，但仍需在冻结版本上补正式留档
  - 高负载吞吐提升 10% 以上：已完成
  - 稳定系统、完整文档与论文：代码和实验链路基本就绪，正式冻结结果与论文定稿未完成
- 已完成的实验主线：
  - reuse on/off sweep
  - Python vs Rust FIN-style backend compare
  - N=12 高负载主结果
  - Python Grace 参数敏感性
- 已完成的实验能力：
  - 受控网络扰动注入
  - `slow_honest` 场景 quick result
  - 初步拜占庭节点模拟：`silent`、`invalid_fetch_response`
- 已接入但尚未形成正式主结果的内容：
  - fetch request/response 统计
  - `rust_dumbo` backend compare 入口
  - 网络扰动正式冻结结果
  - 拜占庭节点正式 benchmark 结果
- 尚未完成的内容：
  - 干净工作树上的正式重跑与结果冻结
  - `paper-final-network-*` 与 `paper-final-byzantine-*` 目录
  - 论文终稿收口与图表回填

## 任务书收尾重点

当前最关键的缺口已经不是协议核心功能，而是把现有实现收敛成一套能交付、能复查、能写进论文终稿的冻结材料。具体优先级如下。

1. 在干净工作树上重跑高负载主结果、Grace 微实验和慢诚实节点实验。
2. 跑出第一组正式的 `paper-final-byzantine-*` 结果，至少覆盖 `silent` 和 `invalid_fetch_response`。
3. 用冻结结果回填论文表格、图注和实验威胁分析。

## 设计原则

- 先做最小可用版本，不一开始追求“通用网络模拟器”。
- 网络扰动和拜占庭行为都必须可配置、可复现、可记录到结果 JSON。
- 所有实验都必须保留随机种子或明确的静态参数。
- 优先从外层 driver 和 transport 边界注入行为，不优先侵入 ACS 核心逻辑。
- 论文主结果只纳入稳定、可复现、不会频繁超时的场景。

## 总体方案

### A. 网络扰动能力

优先在 `native/honey-node/src/transport/local_tcp.rs` 的发送路径加入受控扰动，而不是单独再起一个 TCP 代理程序。

原因：

- 当前本地 benchmark 已经稳定依赖 `LocalTcpTransport`。
- `LocalTcpTransport` 的 sender loop 天然掌握 `(sender_pid, recipient_pid, payload)` 这三个关键信息。
- 在发送侧做延迟、抖动、丢弃更容易保持实现简单，也更容易在 telemetry 里计数。
- 对论文来说，“固定延迟 / 抖动 / 慢诚实节点”已经足够回答主要问题，不必先做全功能网络中间件。

### B. 拜占庭节点注入能力

优先在 `network_driver` 的外层 driver/transport 边界注入恶意行为，而不是修改 Python/Rust ACS host 内核。

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

- `native/honey-node/src/network_driver/config.rs`
- `native/honey-node/src/cli.rs`

任务：

- 新增 `NetworkFaultConfig`
- 新增 `SlowHonestConfig`
- 新增 `ByzantineNodeConfig`
- 解析 `config_json` 中的网络扰动和拜占庭配置
- 在配置为空时保持完全向后兼容

### 2. 传输层扰动

文件：

- `native/honey-node/src/transport/local_tcp.rs`
- `native/honey-node/src/network_driver.rs`

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

- `native/honey-node/src/network_driver/round.rs`
- `native/honey-node/src/network_driver/types.rs`
- `native/honey-node/src/network_driver/result.rs`

任务：

- 在每个节点启动时识别自己是否为恶意 pid
- 在外发 ACS wire / fetch response / 本地提案准备阶段插入行为分支
- 对恶意行为做显式 telemetry 计数
- 保证诚实节点最终结果仍可用于判断 safety/liveness

### 4. Python benchmark 汇总链路

文件：

- `benchmarks/support/runners/_core.py`
- `benchmarks/cli/tps.py`
- `benchmarks/cli/dumbo_paper_suite.py`

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

建议新增实验组：

- `network_fixed_delay_n12`
- `network_jitter_n12`
- `slow_honest_n12`
- `byzantine_silent_n12`
- `byzantine_invalid_fetch_n12`
- `byzantine_invalid_reference_n12`

## 分阶段执行计划

### Phase 0: 基线冻结与结果口径准备

目标：

- 在引入新实验前先稳定当前 benchmark 基线

任务：

- 整理 benchmark/paper 相关未提交文件
- 确认 `paper-final-highload-*` 与 `paper-final-grace-python-*` 的口径
- 保持 `TODO.md`、论文草稿和 benchmark config 同步

完成标准：

- 当前正式实验入口和结果目录结构不再频繁变动

### Phase 1: 最小网络扰动能力

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

### Phase 2: 网络扰动实验接入论文 suite（能力已完成，正式结果待冻结）

目标：

- 让网络扰动变成真正可批量执行的论文实验

任务：

- 扩展 `dumbo_paper_suite.py` 的维度定义
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

- `dumbo_paper_suite.py` 已支持 `network_faults` 维度展开和可读标签分组
- `benchmarks/configs/paper/dumbo_smoke.toml` 与 `benchmarks/configs/paper/dumbo_comprehensive.toml` 已补入固定延迟、抖动、慢诚实节点实验条目
- 目前仍未产出正式 `paper-final-network-*` 结果目录，下一步应开始实际跑数并整理 summary/delta 表

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
- 下一步应转入 Phase 4，补正式 benchmark 结果，而不是继续扩张恶意行为种类

### Phase 4: 拜占庭实验接入论文 suite

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

- 形成 `paper-final-byzantine-*` 目录
- 论文可保守表述“在简单恶意行为下观察到机制仍保持正确性边界内运行”

### Phase 5: 正式封版实验与论文回填

目标：

- 在干净工作树上重跑最终需要写进正文的结果

任务：

- 重新跑高负载主结果
- 重新跑 Grace 微实验
- 跑一组网络扰动核心结果
- 跑一组最小拜占庭核心结果
- 更新 `paper/main-codex-refer.typ`

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
- `native/honey-node` Rust tests
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

如果时间有限，最小可交付集合应是：

1. `N=12` 下固定延迟场景
2. `N=12` 下抖动场景
3. `N=12` 下单慢诚实节点场景
4. `N=12` 下单 silent 恶意节点场景
5. `N=12` 下单 invalid fetch response 恶意节点场景

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

1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5

## 当前直接实施起点

按目前完成度，最应该立刻做的具体任务是：

1. 在干净工作树上重跑：
   - `highload_n12`
   - `grace_python_n12_micro`
   - `slow_honest_n12`
2. 运行第一组正式的拜占庭实验：
   - `byzantine_silent_n12`
   - `byzantine_invalid_fetch_response_n12`
3. 把冻结结果写回 `paper/main-codex-refer.typ` 和实验清单，收紧最终论文口径
