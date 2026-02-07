#pragma once
#include "core/rbc/messages.hpp"
#include <vector>

namespace Honey::BFT::PRBC {

using Honey::BFT::NodeId;
using Honey::BFT::RBC::EchoPayload;
using Honey::BFT::RBC::Hash;
using Honey::BFT::RBC::ValPayload;

struct ReadyPayload {
    Hash root_hash;
    std::vector<std::byte> signature_share;
};

using PRBCPayload = std::variant<ValPayload, EchoPayload, ReadyPayload>;

struct PRBCMessage {
    enum class Type : uint8_t {
        Leader,
        Val,
        Echo,
        Ready
    } type {};
    NodeId sender {};
    int session_id {};
    PRBCPayload payload;
};

} // namespace Honey::BFT::PRBC
