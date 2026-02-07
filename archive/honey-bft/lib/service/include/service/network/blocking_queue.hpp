#pragma once

#include <condition_variable>
#include <deque>
#include <exec/task.hpp>
#include <mutex>
#include <optional>

namespace Honey::BFT::Network {

template <typename T>
class BlockingQueueStream {
public:
    void push(T value)
    {
        {
            std::lock_guard lock(mutex_);
            queue_.push_back(std::move(value));
        }
        cv_.notify_one();
    }

    void close()
    {
        {
            std::lock_guard lock(mutex_);
            closed_ = true;
        }
        cv_.notify_all();
    }

    auto next() -> exec::task<std::optional<T>>
    {
        std::unique_lock lock(mutex_);
        cv_.wait(lock, [&] { return closed_ || !queue_.empty(); });
        if (queue_.empty()) {
            co_return std::nullopt;
        }
        auto value = std::move(queue_.front());
        queue_.pop_front();
        co_return value;
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<T> queue_;
    bool closed_ = false;
};

} // namespace Honey::BFT::Network
