### 第一层 (L1)：传输与分帧层 (Transport & Framing)

**核心组件：** `PeerConnection`, `NetworkService`, `WireHeader`

**设计职责：**
1.  **物理连接管理**：维护 TCP Socket 的生命周期与断线重连。
2.  **二进制分帧 (Framing)**：TCP 是流式协议，必须定义边界。强制所有数据包前置定长的 `WireHeader`（包含 `payload_len`、`Tag`、`session_id`、`instance_id`）。
3.  **内存安全边界 (OOM 防御)**：在读取 payload 之前，严格校验 `payload_len <= MAX_PAYLOAD_SIZE`。超限直接阻断连接，这是 BFT 抵御拜占庭节点恶意发包的第一道防线。
4.  **并发写安全**：为每个 `PeerConnection` 引入一个 **MPSC（多生产者单消费者）队列**。所有出站包投入队列，由单一的后台写协程（Write Loop）串行发送。

**数据流转形态：** 纯二进制流 (`std::vector<std::byte>`)。此层对任何共识协议细节一无所知。

---

### 第二层 (L2)：多路复用与路由层 (Multiplexing & Routing)

**核心组件：** `Multiplexer`
**取代目标：** 原有的 `MessageBus`, `pending_` 队列。

**设计职责：**
1.  **精确路由**：BFT 协议存在极其密集的并发实例。`Multiplexer` 维护一张由 `[Tag, SessionID, InstanceID]` 映射到 **挂起接收器 (Suspended Receiver)** 的路由表。
2.  **控制流转移 (Inversion of Control)**：这是与旧版 `Channel` 最大的区别。当 L1 解析出完整的 payload 时，将其交由 L2。L2 查找路由表，如果找到匹配的接收器，**直接在当前线程上下文中调用 `set_value`**，唤醒对应的上层协议协程，实现零拷贝数据投递。
3.  **确定性缓冲 (Bounded Buffering)**：如果消息比协议层的接收请求（`receive_next`）先到达，L2 负责暂存。但必须设置**硬性容量上限**（如每个 RouteKey 最多 50 条）。超出上限则丢弃，依赖协议层自身的容错机制（如重传或容忍部分丢包），绝不允许内存无限膨胀。

---

### 第三层 (L3)：协议适配层 (Protocol Endpoint)

**核心组件：** `IEndpoint<Msg>`, `ProtocolEndpoint<Msg, Tag>`
**取代目标：** 原有的 `Transport`, `TypedReceiver`, `protocol_codecs.hpp`。

**设计职责：**
1.  **类型擦除与强类型转换**：向上对共识协议暴露强类型的 C++ 结构体（如 `RBCMessage`），向下对 L2 暴露二进制字节流。在这一层调用高效的二进制序列化库（取代低效的 JSON/Hex）。
2.  **提供 Stdexec Sender 语义**：暴露基于 P2300 的异步操作接口。
    *   `broadcast()`: 序列化业务数据并拼接 `WireHeader`，打包成共享指针（`shared_ptr`）传递给 L1 的所有连接，实现**零拷贝广播**。
    *   `receive_next()`: 不再是一个持续的流，而是一个**单次异步操作**。调用时，将自身包装为一个 Receiver 注册到 L2 的 `Multiplexer` 中。
3.  **生命周期与取消传播**：当外层作用域（如 `exec::async_scope`）触发取消时，底层的 `StopToken` 立即触发回调，将自己从 `Multiplexer` 的路由表中注销。保证协程取消时不会留下悬空指针。

---

### 架构控制流全景 (Data Flow Control)

为更清晰地理解，我们走一遍数据进出的全流程：

#### 1. 入站数据流 (Inbound Pipeline)
1. **L1 Read Loop:** `asio::async_read` 读取 16 字节 `WireHeader`。
2. **L1 Validation:** 检查 `payload_len`。正常则读取载荷。
3. **L1 -> L2:** 将 `WireHeader` 和 `payload` (shared_ptr) 传递给 `Multiplexer::route()`。
4. **L2 Routing:** 查找路由表。
    * 若找到对应的挂起态协程，执行 `set_value(payload)`。
    * 若未找到，存入长度受限的 LRU Cache。
5. **L3 Deserialization:** L3 被唤醒，将 payload 反序列化为强类型 `Msg`，传递给共识协议层（L4）。

#### 2. 出站数据流 (Outbound Pipeline)
1. **L4 -> L3:** 协议层调用 `endpoint.broadcast(msg)`。
2. **L3 Serialization:** L3 将 `msg` 序列化为二进制，并预分配连续内存，将 `WireHeader` 和 `payload` 合并为一个 `shared_ptr` 包。
3. **L3 -> L1:** 调用 `NetworkService::broadcast_raw()`。
4. **L1 Enqueue:** 将该指针同时压入所有目标 `PeerConnection` 的 MPSC 队列中（引用计数增加，数据不拷贝）。
5. **L1 Write Loop:** 各连接的后台写协程从队列中取出指针，调用单一的 `asio::async_write` 将数据刷入内核态 TCP 缓冲区。

---

### 为什么必须采用这套架构？（解决的心智负担）

你之所以觉得之前的网络层代码心智负担重，是因为**职责纠缠不清**。在原版代码中：
* `NetworkService` 既管连接，又管序列化格式（JSON）。
* `MessageBus` 既管路由分发，又管无限缓存。
* 协议层既要处理算法，又要自己过滤 `instance_id`。

**重构后的架构实现了绝对的职责单一：**
* **底层网络 (L1+L2)** 彻底变成了一个“强安全、支持多路复用、抗并发崩溃的二进制数据导向器”。
* **协议层 (L4)** 变成了纯粹的数学状态机。它拿到的 `IEndpoint` 已经为其滤除了所有无关的流量（非本 Session、非本 Instance 的数据绝对不会进入它的上下文）。

**关于 `stdexec` 的引入：**
这并不是为了炫技。BFT 协议中充满了并行的子任务（如同时跑 N 个 RBC），一旦达成共识目标，必须立即且安全地终止剩余任务。传统的 `Channel` 模型无法自动清理挂起的网络接收请求，而基于 `stdexec` 状态机（`OperationState`）的 `StopToken` 取消树，能保证协议层取消时，所有的底层注册映射被确定性地（Deterministically）清理干净，从而实现**结构化并发 (Structured Concurrency)**。


### 使用示例：如何将 L3 注入协议层

现在，你的协议层代码（比如 `ReliableBroadcast.hpp`）会变得非常干净：

```cpp
// 你的协议层不需要 include network_service.hpp，只需要 include endpoint.hpp
#include "service/network/endpoint.hpp"

namespace Honey::BFT::RBC {

struct RBCMessage {
    // ... 你的消息定义 ...
    // std::vector<std::byte> serialize() const { ... }
    // bool deserialize(const std::vector<std::byte>&) { ... }
};

class ReliableBroadcast {
    // 依赖注入：只依赖抽象接口
    Network::IEndpoint<RBCMessage>& net_;

public:
    ReliableBroadcast(Network::IEndpoint<RBCMessage>& net)
        : net_(net) {}

    exec::task<Output> run(Input input) {
        // 发送
        RBCMessage val_msg = ...;
        co_await net_.broadcast(val_msg);

        // 接收
        while (true) {
            // 这里拿到的 msg 已经是反序列化好的、校验过 Header 的、属于本实例的
            RBCMessage msg = co_await net_.receive();

            // ... 业务逻辑 ...
            if (finished) co_return output;
        }
    }
};

}
```

### 并在主程序中这样组装：

```cpp
// main.cpp

// 1. 启动底层网络 (L1 + L2)
auto router = Multiplexer{};
auto net_service = std::make_shared<NetworkService>(my_id, port, peers, router);
net_service->start();

// 2. 启动 N 个 RBC 实例 (L3 + L4)
exec::async_scope scope;

for (int i = 0; i < N; ++i) {
    // 为每个实例创建专属信箱 (L3)
    // Key: Tag=RBC, Session=0, Instance=i
    auto endpoint = std::make_unique<NetworkEndpoint<RBCMessage, ProtocolTag::Rbc>>(
        *net_service, 0, i
    );

    // 创建协议实例 (L4)
    auto rbc = std::make_shared<ReliableBroadcast>(*endpoint);

    // 跑起来
    scope.spawn(rbc->run(input));
}

// ... 等待结果 ...
```
