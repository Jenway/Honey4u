# 执行计划: `drain_outbound_events` 重构

> 对应提案: `PROPOSAL_drain_outbound_events.md`

## 涉及文件总览 (18个文件, 4个包)

| 包 | 文件数 | 层级 |
|----|-------|------|
| `honey-acs` (Rust) | 11 | trait + 3后端 + threaded + harness + 3 state + python.rs |
| `honey-acs` (Python) | 1 | host.py |
| `honey-node` (Rust) | 2 | acs_io.rs + output.rs |
| `honey-bench` (Rust) | 2 | drive_hb.rs + drive_dumbo.rs |
| `benchmarks` (Python) | 1 | _core.py |
| `tests` (Python) | 1 | test_acs_host.py |

---

## Phase 1 — trait 加默认方法 (1 文件，零破坏)

**目标**: 新增方法，保留旧方法，全部后端自动获得默认实现。此 phase 后可编译通过，无行为变更。

| # | 文件 | 操作 |
|---|------|------|
| 1.1 | `honey-acs/src/lib.rs` | trait 新增 `fn drain_outbound_events(&self, limit: usize) -> Result<Vec<AcsEvent>, String>`，默认实现: `{ self.begin_pull_outbound_wire_batch(limit)?; self.finish_pull_outbound_wire_batch() }` |

**验证**: `cargo build -p honey-acs`

---

## Phase 2 — 后端实现新方法 (7 文件)

**目标**: 各后端用自己的高效路径覆盖默认方法

| # | 文件 | 操作 |
|---|------|------|
| 2.1 | `honey-acs/src/backends/rust_fin/mod.rs` | 新增 `drain_outbound_events`：锁 state → `round.outbound.drain(..limit.min(round.outbound.len())).collect()`，更新命令计数和条目计数。等效替代当前 begin(存 pending_pull_limit) + finish(取并 drain) 逻辑 |
| 2.2 | `honey-acs/src/backends/rust_dumbo/mod.rs` | 同上 |
| 2.3 | `honey-acs/src/backends/rust_hb/mod.rs` | 同上 |
| 2.4 | `honey-acs/packages/honey-acs/src/honey_acs/host.py` | 新增 `def drain_outbound_events(self, limit):` — 快速路径: `_outbound_ready.is_set()` 为 False 返回 `[]`；慢路径: `future = self._submit_async_command("pull_outbound_wire_batch", limit)` + `return cast(list, future.result())`。GIL 在 `Future.result()` 内部 `Condition.wait()` 时释放，不阻塞事件循环线程 |
| 2.5 | `honey-acs/src/backends/python.rs` | 新增 `drain_outbound_events`：单次 `Python::attach` 调 Python `host.drain_outbound_events(limit)`，解码 PyList 为 `Vec<AcsEvent>` |
| 2.6 | `honey-acs/src/threaded.rs` | (a) `WorkerCommand` 枚举新增 `DrainOutboundEvents { limit: usize, response: Sender<Result<Vec<AcsEvent>, String>> }` (b) `ThreadedAcsBackend` 实现 `drain_outbound_events` 发送此命令 (c) worker_loop 新增分发 arm: `inner.drain_outbound_events(limit)` |

**验证**: `cargo build -p honey-acs && cargo nextest run -p honey-acs`

---

## Phase 3 — 迁移调用方 (3 文件)

**目标**: 所有消费端使用新 API

| # | 文件 | 操作 |
|---|------|------|
| 3.1 | `honey-node/src/driver/round/acs_io.rs` | 替换 `outbound_ready` + `begin_pull_outbound_wire_batch` + `finish_pull_outbound_wire_batch` 三调用为单次 `drain_outbound_events(DRIVER_NETWORK_BATCH_LIMIT)`。**无条件 drain**——空 Vec 表示无事件 |
| 3.2 | `honey-acs/src/harness.rs` | 3 处替换（主循环 begin_pull l.316 + finish_pull l.320、settle 循环 begin_pull l.411 + finish_pull l.415）为单次 `drain_outbound_events(ACS_PULL_BATCH_LIMIT)` |
| 3.3 | `tests/runtime/test_acs_host.py` | 替换 begin + finish 调用为 `drain_outbound_events` |

**验证**: `cargo build --workspace`

---

## Phase 4 — 删除旧方法 (11 文件)

**目标**: 移除所有旧 API 痕迹

| # | 文件 | 操作 |
|---|------|------|
| 4.1 | `honey-acs/src/lib.rs` | trait 删除 `outbound_ready`、`begin_pull_outbound_wire_batch`、`finish_pull_outbound_wire_batch` 声明及 `Box<T>` 代理实现 |
| 4.2 | `honey-acs/src/backends/rust_fin/mod.rs` | 删除 `outbound_ready()` (l.327-337)、`begin_pull_outbound_wire_batch()` (l.339-353)、`finish_pull_outbound_wire_batch()` (l.355-380) 三个方法 |
| 4.3 | `honey-acs/src/backends/rust_dumbo/mod.rs` | 同上 (l.483-530) |
| 4.4 | `honey-acs/src/backends/rust_hb/mod.rs` | 同上 (l.354-401) |
| 4.5 | `honey-acs/src/backends/python.rs` | 删除 `outbound_ready()` (l.819)、`begin_pull_outbound_wire_batch()` (l.829)、`finish_pull_outbound_wire_batch()` (l.844) 及其 trait impl 委托 |
| 4.6 | `honey-acs/packages/honey-acs/src/honey_acs/host.py` | 删除 `outbound_ready()` (l.381)、`begin_pull_outbound_wire_batch()` (l.338)、`finish_pull_outbound_decoded_batch()` (l.344)。保留 `_mark_outbound_ready`、`_drain_service_events`、`_outbound_ready` Event（`drain_outbound_events` 直接使用它们） |
| 4.7 | `honey-acs/src/threaded.rs` | 删除 `WorkerCommand::OutboundReady` (l.26-28) 和 `PullOutboundWireBatch` (l.22-25) 变体 + worker_loop 中对应的分发 arm (l.327-338) + `ThreadedAcsBackend` 中对应的发送端代码 (l.193-239) |
| 4.8 | `honey-acs/src/backends/rust_fin/state.rs` | 删除 `pending_pull_limit: Option<usize>` 字段 (l.224) + start_round 中的重置 (l.272) + shutdown 中的重置 (l.419) + begin_pull 中的幂等检查 (已随方法删除) |
| 4.9 | `honey-acs/src/backends/rust_dumbo/state.rs` | 同上 (l.250, l.423, l.574) |
| 4.10 | `honey-acs/src/backends/rust_hb/state.rs` | 同上 (l.162, l.284, l.446) |
| 4.11 | `honey-acs/packages/honey-acs/src/honey_acs/host.py` | 删除 `_pending_pull` 字段 (l.93) — 新 `drain_outbound_events` 方法内部使用局部变量持有 Future，不再需要实例字段 |

**验证**: `cargo build --workspace`

---

## Phase 5 — 统计字段重命名（可选）

仅改名，不改变量语义：

| 当前字段 | 新字段 |
|---------|--------|
| `pull_outbound_wire_batch_calls` | `drain_outbound_calls` |
| `pull_outbound_wire_batch_items` | `drain_outbound_items` |

涉及文件 (~10 个): `state.rs` (3个), `threaded.rs`, `python.rs`, `output.rs`, `drive_hb.rs`, `drive_dumbo.rs`, `_core.py`, `test_*`.py。

**向后兼容性**: 如果现有 benchmark result JSON 依赖这些 key 名，此 phase 需同步更新解析侧或推迟。

**验证**: `cargo build --workspace && uv run pytest tests/runtime/ tests/benchmarks/`

---

## 依赖关系图

```
Phase 1 (trait 默认方法，零破坏)
  │
  └── Phase 2 (各后端用高效实现覆盖默认方法)
        │
        └── Phase 3 (迁移所有调用方到新 API)
              │
              └── Phase 4 (删除旧方法 + 清理 pending_pull_limit)
                    │
                    └── Phase 5 (统计字段重命名，可选)
```

每个 phase 均独立可编译 + 可测试，bisect 友好。

---

## 风险缓解

| 风险 | 缓解 |
|------|------|
| GIL 死锁 | Python `drain_outbound_events` 沿用 `Future.result()`，`Condition.wait()` 在 CPython C 层释放 GIL（与当前 `finish_pull` 行为一致，见提案 §4.2） |
| Driver 正确性 | Phase 3 无条件 drain 消除原 `outbound_ready()` gate 导致的内部事件延迟问题（见提案 §5.4） |
| 旧 API 遗漏调用方 | Phase 1 保留旧方法为默认实现；Phase 4 删除时编译器报错精准定位遗漏 |
| Benchmark 数据格式 | Phase 5 仅重命名；可推迟到此重构的后续独立 PR |
