#pragma once
#include <variant>
#include <vector>

namespace Honey::BFT::HoneyBadger {

using Byte = std::byte;

// Event from network: received decryption share
struct DecShareReceivedEvent {
    int epoch;
    int ciphertext_index;
    int sender_id;
    std::vector<Byte> share_data;
};

// Event from ACS: ACS instance completed
struct ACSCompleteEvent {
    int epoch;
    std::vector<std::vector<Byte>> ciphertexts; // ACS output {v_j}
};

// Union of all HoneyBadger events
using HBEvent = std::variant<
    DecShareReceivedEvent,
    ACSCompleteEvent>;

} // namespace Honey::BFT::HoneyBadger
