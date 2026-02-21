#pragma once

#include <coroutine>
#include <deque>
#include <exec/task.hpp>
#include <mutex>
#include <optional>
#include <vector>

namespace Honey::BFT::Network {

template <typename T>
class BlockingQueueStream {
private:
    /**
     * @brief 实现 co_await stream.next() 的 awaiter
     */
    struct [[nodiscard]] next_awaiter {
        BlockingQueueStream* queue_;

        /**
         * @brief 检查是否有数据可立即返回
         * @return true 如果有数据或队列已关闭，协程不挂起
         */
        bool await_ready() const
        {
            std::lock_guard lock(queue_->mutex_);
            return !queue_->items_.empty() || queue_->closed_;
        }

        /**
         * @brief 当没有数据时挂起协程
         * @param h 当前协程的句柄，保存用于后续恢复
         */
        void await_suspend(std::coroutine_handle<> h)
        {
            std::lock_guard lock(queue_->mutex_);
            // 再次检查（避免竞态）
            if (!queue_->items_.empty() || queue_->closed_) {
                // 有数据了，立即恢复
                h.resume();
            } else {
                // 保存协程句柄，等待 push() 唤醒
                queue_->waiters_.push_back(h);
            }
        }

        /**
         * @brief 协程恢复时执行，返回队列元素
         * @return std::optional<T> 队列元素，或 nullopt（队列已关闭且为空）
         */
        std::optional<T> await_resume()
        {
            std::lock_guard lock(queue_->mutex_);
            if (queue_->items_.empty()) {
                return std::nullopt; // 队列已关闭
            }
            auto item = std::move(queue_->items_.front());
            queue_->items_.pop_front();
            return item;
        }
    };

public:
    /**
     * @brief 向队列推送元素，如果有等待的消费者则唤醒
     * @param value 要推送的元素
     */
    void push(T value)
    {
        std::coroutine_handle<> to_resume;
        {
            std::lock_guard lock(mutex_);
            items_.push_back(std::move(value));

            // 如果有等待的消费者，取出一个准备唤醒
            if (!waiters_.empty()) {
                to_resume = waiters_.front();
                waiters_.pop_front();
            }
        }

        // 在锁外恢复协程，避免死锁
        if (to_resume) {
            to_resume.resume();
        }
    }

    /**
     * @brief 关闭队列，唤醒所有等待的消费者
     */
    void close()
    {
        std::vector<std::coroutine_handle<>> to_resume;
        {
            std::lock_guard lock(mutex_);
            closed_ = true;
            // 移动所有等待者，准备唤醒
            to_resume.reserve(waiters_.size());
            for (auto h : waiters_) {
                to_resume.push_back(h);
            }
            waiters_.clear();
        }

        // 在锁外恢复所有协程
        for (auto h : to_resume) {
            h.resume();
        }
    }

    /**
     * @brief 异步获取下一个元素
     * @return awaiter 对象，可直接 co_await
     *
     * 使用示例：
     * @code
     * while (auto item = co_await stream.next()) {
     *     // 处理 *item
     * }
     * @endcode
     */
    auto next() -> next_awaiter
    {
        return next_awaiter { this };
    }

private:
    mutable std::mutex mutex_;
    std::deque<T> items_;
    std::deque<std::coroutine_handle<>> waiters_; // 等待数据的协程
    bool closed_ = false;
};

} // namespace Honey::BFT::Network
