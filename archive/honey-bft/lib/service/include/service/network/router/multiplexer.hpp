#pragma once

#include "wire_format.hpp"
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <spdlog/spdlog.h>
#include <stdexec/execution.hpp>
#include <unordered_map>

namespace Honey::BFT::Network {

using SharedPayload = std::shared_ptr<const std::vector<std::byte>>;

// =========================================================================
// 1. 类型擦除接口 (IWaitNode)
// 作用：Multiplexer 不需要知道具体的 Receiver 类型，只需知道如何唤醒它。
// =========================================================================
struct IWaitNode {
    virtual ~IWaitNode() = default;
    virtual void on_data(SharedPayload payload, int32_t sender_id) = 0;
};

// =========================================================================
// 2. 核心路由器 (Multiplexer)
// =========================================================================
class Multiplexer {
private:
    std::mutex mutex_;

    // 当前正在挂起等待的接收器 (RouteKey -> WaitNode)
    std::unordered_map<RouteKey, IWaitNode*> waiters_;

    // 防御性缓存：应对消息比协议层的 co_await receive_next() 先到达的情况
    std::unordered_map<RouteKey, std::deque<std::pair<SharedPayload, int32_t>>> early_buffers_;

    // 💥 内存安全硬上限：每个信箱最多暂存 50 条消息。超载直接丢弃。
    static constexpr size_t MAX_EARLY_BUFFER = 50;

public:
    // 由 L1 (PeerConnection) 的读循环调用
    void route(const WireHeader& header, SharedPayload payload)
    {
        RouteKey key { static_cast<ProtocolTag>(header.tag), header.session_id, header.instance_id };
        IWaitNode* target_node = nullptr;

        {
            std::lock_guard lock(mutex_);
            if (auto it = waiters_.find(key); it != waiters_.end()) {
                // 命中等待的协程，将其摘除
                target_node = it->second;
                waiters_.erase(it);
            } else {
                // 没有协程在等，放入暂存区
                auto& q = early_buffers_[key];
                if (q.size() < MAX_EARLY_BUFFER) {
                    q.emplace_back(std::move(payload), header.sender_id);
                } else {
                    spdlog::warn("[Network L2] Dropping early packet for Tag={}, Session={}, Instance={} (Buffer full)",
                        (int)key.tag, key.session_id, key.instance_id);
                }
            }
        } // 离开锁作用域

        // 在锁外调用 on_data，防止接收器被唤醒后立刻发起下一个请求导致死锁
        if (target_node) {
            target_node->on_data(std::move(payload), header.sender_id);
        }
    }

    // 由 L3 挂起协程时调用：尝试获取缓存，如果没有则注册自己
    bool try_pull_or_register(const RouteKey& key, IWaitNode* node, std::pair<SharedPayload, int32_t>& out_data)
    {
        std::lock_guard lock(mutex_);
        auto it = early_buffers_.find(key);
        if (it != early_buffers_.end() && !it->second.empty()) {
            // 缓存命中！取出数据
            out_data = std::move(it->second.front());
            it->second.pop_front();
            return true;
        }
        // 没命中，挂起等待
        waiters_[key] = node;
        return false;
    }

    // 取消挂起（如协程被外层 StopToken 中断时调用）
    void deregister(const RouteKey& key, IWaitNode* node)
    {
        std::lock_guard lock(mutex_);
        auto it = waiters_.find(key);
        if (it != waiters_.end() && it->second == node) {
            waiters_.erase(it);
        }
    }
};

// =========================================================================
// 3. stdexec 适配层：让 ReceiveNext 成为一个标准的 Sender
// =========================================================================

struct ReceiveNextSender {
    using is_sender = void;
    // 声明这个 Sender 成功时会传递 [SharedPayload, int32_t]，被取消时会 stopped
    using completion_signatures = stdexec::completion_signatures<
        stdexec::set_value_t(SharedPayload, int32_t),
        stdexec::set_stopped_t()>;

    Multiplexer* router_;
    RouteKey key_;

    template <typename Receiver>
    class OperationState : public IWaitNode {
        Multiplexer* router_;
        RouteKey key_;
        Receiver rx_;

        // 用于监听取消信号的类型魔法
        using StopToken = stdexec::stop_token_of_t<stdexec::env_of_t<Receiver>>;
        struct OnStop {
            OperationState* op_;
            void operator()() noexcept { op_->on_stop(); }
        };
        using StopCallback = typename StopToken::template callback_type<OnStop>;
        std::optional<StopCallback> stop_cb_;

    public:
        OperationState(Multiplexer* router, RouteKey key, Receiver rx)
            : router_(router)
            , key_(key)
            , rx_(std::move(rx))
        {
        }

        // 当网络数据到达时被 Multiplexer 调用
        void on_data(SharedPayload payload, int32_t sender_id) override
        {
            stop_cb_.reset(); // 注销 Stop 监听
            stdexec::set_value(std::move(rx_), std::move(payload), sender_id);
        }

        // 当协程被外层作用域（如 async_scope）取消时触发
        void on_stop() noexcept
        {
            router_->deregister(key_, this);
            stdexec::set_stopped(std::move(rx_));
        }

        // 启动这个 Sender (即 co_await 开始执行的一瞬间)
        friend void tag_invoke(stdexec::start_t, OperationState& self) noexcept
        {
            std::pair<SharedPayload, int32_t> cached_data;

            // 1. 先尝试命中缓存
            if (self.router_->try_pull_or_register(self.key_, &self, cached_data)) {
                // 命中！直接同步唤醒协程
                stdexec::set_value(std::move(self.rx_), std::move(cached_data.first), cached_data.second);
                return;
            }

            // 2. 没命中，当前处于等待状态。检查是否已经被取消
            auto st = stdexec::get_stop_token(stdexec::get_env(self.rx_));
            if (st.stop_requested()) {
                self.router_->deregister(self.key_, &self);
                stdexec::set_stopped(std::move(self.rx_));
            } else {
                // 3. 挂载监听器，如果中途被取消，会触发 OnStop
                self.stop_cb_.emplace(st, OnStop { &self });
            }
        }
    };

    // 绑定 Sender 和 Receiver，生成状态机
    template <typename Receiver>
    friend auto tag_invoke(stdexec::connect_t, const ReceiveNextSender& self, Receiver rx)
    {
        return OperationState<Receiver>(self.router_, self.key_, std::move(rx));
    }
};

} // namespace Honey::BFT::Network
