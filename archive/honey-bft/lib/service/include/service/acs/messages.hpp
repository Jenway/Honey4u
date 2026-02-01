#pragma once
#include "core/ba/messages.hpp"
#include "core/rbc/messages.hpp"
#include <variant>

namespace Honey::BFT::ACS {
using Byte = std::byte;

struct ACSPayload {
    int instance_id; // 对应 0..N-1，表示是第几个 RBC/BA 实例
    std::variant<RBC::RBCMessage, BA::Message> sub_msg; // 包装子协议消息
};

struct Message {
    int sender {};
    int session_id {};
    ACSPayload payload;
};

} // namespace Honey::BFT::ACS
