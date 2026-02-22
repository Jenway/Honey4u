#pragma once

#include "binary_codec.hpp"
#include "network_service.hpp"
#include <concepts>
#include <exec/task.hpp> // 需要 stdexec 的 task 支持

namespace Honey::BFT::Network {

// =========================================================================
// 1. 协议层接口 (IEndpoint)
// 作用：依赖倒置。让算法层依赖这个接口，方便编写 Mock 测试（不启动真 TCP）。
// =========================================================================
template <typename Msg>
class IEndpoint {
public:
    virtual ~IEndpoint() = default;

    // 广播：返回一个 task，等待发送放入队列即完成
    virtual exec::task<void> broadcast(const Msg& msg) = 0;

    // 单播
    virtual exec::task<void> unicast(int32_t target, const Msg& msg) = 0;

    // 接收：返回一个 task，当收到下一个合法消息时返回
    // 注意：这里返回的是值对象 Msg，而不是 optional。
    // 实现层会自动过滤非法包，直到读到一个合法的。
    virtual exec::task<Msg> receive() = 0;
};

// =========================================================================
// 2. 真实网络实现 (NetworkEndpoint)
// 作用：将 L1/L2 的能力包装成 IEndpoint
// =========================================================================
template <typename Msg, ProtocolTag Tag>
class NetworkEndpoint : public IEndpoint<Msg> {
private:
    NetworkService& net_;
    Multiplexer& router_;
    RouteKey key_; // 固定的路由键 (Tag, Session, Instance)

    // 内部帮手：组装二进制包 (WireHeader + Payload)
    // 这里的关键是：分配一块连续内存，避免 syscall 的多次调用
    SharedPacket make_packet(const Msg& msg)
    {
        // 1. 序列化业务数据
        std::vector<std::byte> payload = BinaryCodec::encode(msg);

        // 2. 计算总大小
        size_t total_len = sizeof(WireHeader) + payload.size();

        // 3. 分配连续内存 (shared_ptr 管理)
        // 注意：这里拷贝了一次 payload。如果追求极致，BinaryCodec 应直接向预留了 Header 空间的 buffer 写入。
        auto buffer = std::make_shared<std::vector<std::byte>>(total_len);

        // 4. 填充 Header
        WireHeader header {
            .payload_len = htonl(static_cast<uint32_t>(payload.size())),
            .tag = static_cast<uint8_t>(Tag),
            .session_id = htonl(key_.session_id),
            .instance_id = htonl(key_.instance_id),
            .sender_id = htonl(net_.get_my_id())
        };

        // 5. 内存拷贝
        std::memcpy(buffer->data(), &header, sizeof(WireHeader));
        if (!payload.empty()) {
            std::memcpy(buffer->data() + sizeof(WireHeader), payload.data(), payload.size());
        }

        return buffer;
    }

public:
    /**
     * @brief 构造一个专属信箱
     * @param net 网络服务
     * @param session_id 共识轮次 ID
     * @param instance_id 实例 ID (如 RBC Leader ID)
     */
    NetworkEndpoint(NetworkService& net, int32_t session_id, int32_t instance_id)
        : net_(net)
        , router_(net.get_router()) // 从 net 获取 router 引用
        , key_ { Tag, session_id, instance_id }
    {
    }

    // 析构时，通常不需要显式注销，因为 OperationState 的 StopToken 会处理挂起的协程。
    // 但如果 Endpoint 生命周期结束了，理论上不应该再有协程挂在上面。

    exec::task<void> broadcast(const Msg& msg) override
    {
        auto packet = make_packet(msg);
        net_.broadcast_raw(std::move(packet)); // 零拷贝分发
        co_return;
    }

    exec::task<void> unicast(int32_t target, const Msg& msg) override
    {
        auto packet = make_packet(msg);
        net_.unicast_raw(target, std::move(packet));
        co_return;
    }

    // 🌟 核心：拉取逻辑
    exec::task<Msg> receive() override
    {
        while (true) {
            // 1. 构造 L2 的 Sender (ReceiveNextSender)
            // 2. co_await 它，挂起当前协程，直到 Multiplexer 唤醒我们
            auto [payload, sender_id] = co_await ReceiveNextSender { &router_, key_ };

            // 3. 唤醒后，反序列化
            if (auto msg_opt = BinaryCodec::decode<Msg>(*payload)) {
                Msg& msg = *msg_opt;

                // 4. [安全关键] 强制注入物理发送方 ID
                // 防止恶意节点在 payload 内部伪造 msg.sender
                // 假设 Msg 结构体有一个 set_sender 或者 sender 字段
                // msg.sender = sender_id;

                co_return std::move(msg);
            }

            // 如果反序列化失败（数据损坏或攻击），循环继续，自动丢弃该包，等待下一个。
            spdlog::warn("Deserialization failed for Tag={}, Sender={}", (int)Tag, sender_id);
        }
    }
};

} // namespace Honey::BFT::Network
