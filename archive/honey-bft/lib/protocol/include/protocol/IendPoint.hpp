#pragma once
#include <exec/task.hpp>
#include <optional>
#include <stdexec/execution.hpp>

namespace Honey::BFT::Network {

template <typename Msg>
class IEndpoint {
public:
    virtual ~IEndpoint() = default;

    // 返回一个 Sender，当消息发送完毕时 complete
    virtual auto broadcast(const Msg& msg) -> stdexec::sender_of<stdexec::set_value_t()> = 0;

    // 返回一个 Sender，当成功收到【下一个】属于该 Endpoint 的消息时 complete
    // 注意：这不是一个 channel，而是一个单次拉取(Pull)的 Sender
    virtual auto receive_next() -> stdexec::sender_of<stdexec::set_value_t(Msg)> = 0;
};

}
