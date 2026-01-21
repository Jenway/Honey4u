#pragma once

#include "core/common.hpp"
#include "crypto/common.hpp"
#include "crypto/merkle_tree.hpp"
#include <map>
#include <variant>
#include <vector>

namespace Honey::BFT::RBC {

using Honey::Crypto::Byte;
using Honey::Crypto::BytesSpan;
using Honey::Crypto::MerkleTree::Hash;
using Honey::Crypto::MerkleTree::Proof;

struct ValPayload {
    Hash root_hash;
    Proof proof;
    std::vector<Byte> stripe;
};

struct EchoPayload {
    Hash root_hash;
    Proof proof;
    std::vector<Byte> stripe;
};

struct ReadyPayload {
    Hash root_hash;
};

using RBCPayload = std::variant<ValPayload, EchoPayload, ReadyPayload>;

struct RBCMessage {
    int sender;
    int session_id;
    RBCPayload payload;
};

struct RBCOutput {
    Hash root_hash;
    std::map<NodeId, std::vector<Byte>> shards;
};

} // namespace Honey::BFT::RBC
