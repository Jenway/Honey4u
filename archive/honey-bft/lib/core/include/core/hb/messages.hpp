#pragma once
#include <cstdint>
#include <vector>

namespace Honey::BFT::HoneyBadger {

using Byte = std::byte;

struct DecryptionShareMsg {
    int epoch; // Epoch number r
    int ciphertext_index; // Which ciphertext j (from ACS output)
    int sender_id; // Node id k
    std::vector<Byte> share_data; // Serialized DecryptionShare e_j,k
};

} // namespace Honey::BFT::HoneyBadger
