#pragma once
#include <variant>
#include <vector>

namespace Honey::BFT::ACS {
using Byte = std::byte;

struct NetworkMsgEvent {
    int sender;
    int instance_id;
    bool is_rbc; // true for RBC, false for BA
    std::vector<Byte> payload;
};

struct RbcDoneEvent {
    int instance_id;
    std::vector<Byte> data;
};

struct BaDoneEvent {
    int instance_id;
    int decision;
};

using ACSEvent = std::variant<NetworkMsgEvent, RbcDoneEvent, BaDoneEvent>;

} // namespace Honey::BFT::ACS
