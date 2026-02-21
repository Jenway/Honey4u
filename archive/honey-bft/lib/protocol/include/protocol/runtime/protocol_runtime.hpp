#pragma once

#include "protocol/concepts.hpp"
#include "service/network/blocking_queue.hpp"
#include "service/network/message_bus.hpp"
#include <exec/async_scope.hpp>
#include <exec/task.hpp>
#include <map>
#include <memory>
#include <stdexec/execution.hpp>
#include <variant>

namespace Honey::BFT::Runtime {

using Byte = std::byte;
using Network::BlockingQueueStream;
using Network::MessageBus;
using Network::ProtocolTag;

/**
 * @brief 协议实例唯一标识符
 *
 * 由协议类型和 session_id 组成
 * 例如: RBC instance (tag=Rbc, session=0, instance=5) 表示第 5 个 RBC
 */
struct InstanceId {
    ProtocolTag tag;
    int session_id; // 会话ID（例如 epoch）
    int instance_id; // 实例ID（例如 node_id）

    auto operator<=>(const InstanceId&) const = default;
};

/**
 * @brief 协议实例的消息包装
 */
struct ProtocolMessage {
    int sender_id; // 发送方节点ID
    std::vector<Byte> payload; // 原始消息载荷
};

/**
 * @brief 协议实例的输出事件
 */
template <typename OutputT>
struct ProtocolOutput {
    InstanceId instance;
    OutputT value;
};

/**
 * @brief 协议实例容器
 *
 * 每个实例是一个独立的 actor，有自己的：
 * - inbox: 接收消息的队列
 * - task: 运行协议逻辑的 coroutine
 * - output_stream: 输出结果的流
 */
struct ProtocolInstance {
    InstanceId id;
    BlockingQueueStream<ProtocolMessage> inbox;
    std::unique_ptr<BlockingQueueStream<std::vector<Byte>>> output_stream;
    // Task 会被 async_scope 管理，这里不需要存储
};

/**
 * @brief 协议运行时 - Actor 模型的核心
 *
 * 职责：
 * 1. 管理所有协议实例的生命周期
 * 2. 提供统一的消息路由
 * 3. 处理协议实例的创建和销毁
 */
class ProtocolRuntime {
public:
    ProtocolRuntime(int my_node_id, MessageBus& message_bus)
        : my_node_id_(my_node_id)
        , message_bus_(message_bus)
    {
    }

    ~ProtocolRuntime()
    {
        // 等待所有协议实例完成
        stdexec::sync_wait(scope_.on_empty());
    }

    /**
     * @brief 创建并启动一个协议实例
     *
     * @tparam Protocol 协议类型（如 ReliableBroadcast）
     * @param instance_id 实例标识符
     * @param protocol_factory 协议工厂函数，接收 inbox 返回协议对象
     * @return 实例的输出流
     */
    template <typename Protocol, typename... Args>
    auto spawn_protocol(InstanceId instance_id, Args&&... args)
        -> BlockingQueueStream<std::vector<Byte>>&
    {
        // 创建实例
        auto& instance = instances_[instance_id];
        instance.id = instance_id;
        instance.output_stream = std::make_unique<BlockingQueueStream<std::vector<Byte>>>();

        auto& output_ref = *instance.output_stream;

        // 在 async_scope 中启动协议
        auto task = run_protocol_instance<Protocol>(
            instance_id,
            instance.inbox,
            output_ref,
            std::forward<Args>(args)...);

        scope_.spawn(std::move(task));

        return output_ref;
    }

    /**
     * @brief 路由消息到指定协议实例
     *
     * @param instance_id 目标实例ID
     * @param sender_id 发送方节点ID
     * @param payload 消息载荷
     */
    void route_message(InstanceId instance_id, int sender_id, std::vector<Byte> payload)
    {
        auto it = instances_.find(instance_id);
        if (it != instances_.end()) {
            it->second.inbox.push(ProtocolMessage {
                .sender_id = sender_id,
                .payload = std::move(payload) });
        }
        // 如果实例不存在，消息会被丢弃（可以改为缓存）
    }

    /**
     * @brief 关闭协议实例的输入队列
     */
    void close_protocol(InstanceId instance_id)
    {
        auto it = instances_.find(instance_id);
        if (it != instances_.end()) {
            it->second.inbox.close();
        }
    }

    /**
     * @brief 获取节点ID
     */
    [[nodiscard]] int node_id() const { return my_node_id_; }

    /**
     * @brief 获取消息总线引用
     */
    [[nodiscard]] MessageBus& message_bus() { return message_bus_; }

private:
    /**
     * @brief 协议实例的运行包装器
     *
     * 负责：
     * 1. 将 ProtocolMessage 转换为协议特定的消息类型
     * 2. 运行协议逻辑
     * 3. 将输出推送到 output_stream
     */
    template <typename Protocol, typename... Args>
    auto run_protocol_instance(
        InstanceId instance_id,
        BlockingQueueStream<ProtocolMessage>& inbox,
        BlockingQueueStream<std::vector<Byte>>& output_stream,
        Args&&... args) -> exec::task<void>
    {
        try {
            // 这里需要根据具体协议类型实现适配器
            // 暂时留空，后续实现
            co_return;
        } catch (...) {
            // 错误处理
            output_stream.close();
        }
    }

    int my_node_id_;
    MessageBus& message_bus_;
    exec::async_scope scope_;
    std::map<InstanceId, ProtocolInstance> instances_;
};

} // namespace Honey::BFT::Runtime
