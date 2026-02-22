隔壁大 C 老师又给出了架构上的新建议：网络层应当分为四个明确分离的层次，每一层只承担单一职责，并通过 sender/receiver 或消息通道连接。

第一层是 I/O 适配层。
职责是和具体网络库交互，例如基于 Boost.Asio 或原生 socket。它只做：

* 连接管理（connect / accept / reconnect）
* 字节流读写
* framing（长度前缀、分包重组）
* 错误转换

这一层只处理 `std::span<std::byte>` 或 `std::vector<std::byte>`，绝不涉及协议 tag、instance_id 或任何 BFT 语义。
对外暴露：

* `sender<void>` send_bytes(...)
* `sender<std::vector<std::byte>>` receive_bytes()

第二层是传输总线（Transport Bus）。
职责是把“字节帧”提升为“Frame”。

这里完成：

* 解包为 Frame { tag, target, payload }
* 广播 / 单播路由
* 本地 fan-out
* backpressure

它不理解 RBC / BA / PRBC，只理解 `ProtocolTag`。
这一层通常实现为一个多生产者多消费者 channel（推荐用 sender/receiver 模型，而不是手写 blocking queue）。

第三层是协议适配层（Protocol Adapter）。
职责是类型安全地把 Frame 映射为具体协议消息。

这里应该使用 traits，而不是为每个协议写一个 Transport 类。

例如：

* ProtocolTraits<Msg>::tag
* ProtocolTraits<Msg>::encode(...)
* ProtocolTraits<Msg>::decode(...)

然后提供：

* `sender<void> send<Msg>(...)`
* `sender<Msg> subscribe<Msg>(...)`

协议层永远不接触 Frame，不接触 tag，只看到自己的强类型消息。

第四层是协议执行层（RBC / BA / HoneyBadger 等）。
它们：

* 不知道 socket
* 不知道 tag
* 不知道网络线程
* 只依赖一个泛型 Transport 接口（基于 sender）

它们的输入输出都是 typed message stream。

设计原则如下。

一，单向依赖。
协议层只依赖抽象 Transport；Transport 依赖 Bus；Bus 依赖 IO；IO 不依赖上层。

二，所有异步都使用 sender/receiver。
不要在中间层混入 `co_await` + 自己实现的 channel。
统一模型，否则执行语义会混乱。

三，生命周期与线程模型明确。
IO 运行在 asio executor。
Bus 运行在自己的 strand 或单线程执行器。
协议运行在计算 executor。
跨层必须显式 schedule。

四，Frame 设计为共享所有权。
使用 `std::shared_ptr<Frame>` 或类似结构，避免 fan-out 复制大 payload。

五，显式 backpressure。
不要允许 pending 队列无限增长。
sender 链应当能表达“下游阻塞时上游停止发送”。

六，连接管理与协议逻辑彻底分离。
重连、断开、peer 管理在 IO 层完成。
协议层只看到“某节点发来某消息”或“发送失败”。

如果按照这个分层，你现在的系统结构会变成：

IO (asio)
→ ByteStreamSender
→ FrameBus
→ TypedTransport<Msg>
→ RBC / PRBC / BA / Coin
→ HoneyBadger

这样扩展新协议时只需新增 ProtocolTraits，而不需要新增 transport 类。

当前最大结构问题不是代码重复，而是“协议语义”和“传输机制”耦合。
只要把 typed protocol 与 untyped frame 分离，整个系统会清晰很多。


你怎么看？
