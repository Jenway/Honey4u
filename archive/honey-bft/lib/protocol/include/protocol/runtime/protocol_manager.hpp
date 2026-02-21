#pragma once

#include "core/ba/messages.hpp"
#include "core/common.hpp"
#include "core/rbc/messages.hpp"
#include "protocol/runtime/protocol_runtime.hpp"
#include <exec/task.hpp>
#include <functional>
#include <set>

namespace Honey::BFT::Runtime {

/**
 * @brief 协议管理器 - 为 ACS/HoneyBadger 等提供便捷接口
 *
 * 封装 ProtocolRuntime，提供：
 * 1. RBC/BA 实例的创建和管理
 * 2. 消息派发的类型安全接口
 * 3. 输出事件的订阅
 */
class ProtocolManager {
public:
    ProtocolManager(SystemContext sys_ctx, int my_node_id, MessageBus& message_bus)
        : sys_ctx_(sys_ctx)
        , runtime_(my_node_id, message_bus)
    {
    }

    /**
     * @brief 创建 RBC 实例
     *
     * @param session_id 会话ID（通常是 epoch）
     * @param instance_id RBC 实例ID（通常是 leader node_id）
     * @param input 如果是 leader，提供输入数据
     * @return RBC 输出流
     */
    auto create_rbc(int session_id, int instance_id, std::optional<std::vector<Byte>> input = std::nullopt)
        -> BlockingQueueStream<std::vector<Byte>>&
    {
        InstanceId id {
            .tag = ProtocolTag::Rbc,
            .session_id = session_id,
            .instance_id = instance_id
        };

        // 记录实例
        rbc_instances_.insert({ session_id, instance_id });

        // TODO: 这里需要实际创建 ReliableBroadcast 实例
        // 现在先返回一个占位符
        return runtime_.spawn_protocol<void>(id);
    }

    /**
     * @brief 创建 BA 实例
     *
     * @param session_id 会话ID
     * @param instance_id BA 实例ID
     * @return BA 决策结果流（输出 0 或 1）
     */
    auto create_ba(int session_id, int instance_id)
        -> BlockingQueueStream<std::vector<Byte>>&
    {
        InstanceId id {
            .tag = ProtocolTag::Ba,
            .session_id = session_id,
            .instance_id = instance_id
        };

        ba_instances_.insert({ session_id, instance_id });

        return runtime_.spawn_protocol<void>(id);
    }

    /**
     * @brief 发送输入到 BA 实例
     *
     * @param session_id 会话ID
     * @param instance_id BA 实例ID
     * @param value 输入值（0 或 1）
     */
    void input_to_ba(int session_id, int instance_id, int value)
    {
        InstanceId id {
            .tag = ProtocolTag::Ba,
            .session_id = session_id,
            .instance_id = instance_id
        };

        // 构造一个特殊的"输入"消息
        // TODO: 需要定义内部控制消息格式
        std::vector<Byte> payload;
        payload.push_back(static_cast<Byte>(value));

        runtime_.route_message(id, runtime_.node_id(), std::move(payload));
    }

    /**
     * @brief 派发 RBC 消息到指定实例
     */
    void dispatch_rbc_message(int session_id, int instance_id, int sender_id, std::vector<Byte> payload)
    {
        InstanceId id {
            .tag = ProtocolTag::Rbc,
            .session_id = session_id,
            .instance_id = instance_id
        };

        runtime_.route_message(id, sender_id, std::move(payload));
    }

    /**
     * @brief 派发 BA 消息到指定实例
     */
    void dispatch_ba_message(int session_id, int instance_id, int sender_id, std::vector<Byte> payload)
    {
        InstanceId id {
            .tag = ProtocolTag::Ba,
            .session_id = session_id,
            .instance_id = instance_id
        };

        runtime_.route_message(id, sender_id, std::move(payload));
    }

    /**
     * @brief 获取系统上下文
     */
    [[nodiscard]] const SystemContext& system_context() const { return sys_ctx_; }

    /**
     * @brief 获取节点ID
     */
    [[nodiscard]] int node_id() const { return runtime_.node_id(); }

private:
    SystemContext sys_ctx_;
    ProtocolRuntime runtime_;

    // 跟踪已创建的实例（用于调试和清理）
    std::set<std::pair<int, int>> rbc_instances_; // (session_id, instance_id)
    std::set<std::pair<int, int>> ba_instances_;
};

} // namespace Honey::BFT::Runtime
