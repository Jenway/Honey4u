#pragma once

#include "service/network/blocking_queue.hpp"
#include <cstddef>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace Honey::BFT::Network {

enum class ProtocolTag : uint8_t {
    Rbc = 1,
    Prbc = 2,
    Ba = 3,
    Coin = 4,
    Acs = 5,
    HbDecShare = 6
};

enum class FrameDirection : uint8_t {
    Outbound = 0,
    Inbound = 1
};

struct Frame {
    ProtocolTag tag;
    int sender_id = -1; // 发送方节点ID（-1表示本地）
    int target = -1; // -1 broadcast, >=0 unicast
    std::vector<std::byte> payload;
    FrameDirection direction = FrameDirection::Outbound;
};

class MessageBus {
public:
    void push(Frame frame)
    {
        std::vector<BlockingQueueStream<Frame>*> streams;
        {
            std::lock_guard lock(mutex_);
            if (handlers_.contains(frame.tag)) {
                for (auto& handler : handlers_.at(frame.tag)) {
                    streams.push_back(handler.get());
                }
            } else {
                pending_[frame.tag].push_back(std::move(frame));
                return;
            }
        }
        for (size_t i = 0; i < streams.size(); ++i) {
            if (i + 1 == streams.size()) {
                streams[i]->push(std::move(frame));
            } else {
                streams[i]->push(frame);
            }
        }
    }

    BlockingQueueStream<Frame>& subscribe(ProtocolTag tag)
    {
        std::lock_guard lock(mutex_);
        auto stream = std::make_unique<BlockingQueueStream<Frame>>();
        if (pending_.contains(tag)) {
            for (auto& frame : pending_.at(tag)) {
                stream->push(frame);
            }
            pending_.erase(tag);
        }
        auto& ref = *stream;
        handlers_[tag].push_back(std::move(stream));
        return ref;
    }

private:
    std::mutex mutex_;
    std::unordered_map<ProtocolTag, std::vector<std::unique_ptr<BlockingQueueStream<Frame>>>> handlers_;
    std::unordered_map<ProtocolTag, std::vector<Frame>> pending_;
};

} // namespace Honey::BFT::Network
