#pragma once

#include <set>
#include <variant>

namespace Honey::BFT::BA {

/// VAL (Value) message payload
struct ValPayload {
    int round;
    int value; ///< Binary value: 0 or 1
};

/// AUX (Auxiliary) message payload
struct AuxPayload {
    int round;
    int value; ///< Binary value: 0 or 1
};

/// CONF (Confirmation) message payload
struct ConfPayload {
    int round;
    std::set<int> values; ///< Set of binary values
};

using Payload = std::variant<ValPayload, AuxPayload, ConfPayload>;

struct Message {
    int sender;
    int session_id;
    Payload payload;
};

} // namespace Honey::BFT::BA
