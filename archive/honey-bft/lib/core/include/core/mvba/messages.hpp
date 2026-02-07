#pragma once
#include "core/common.hpp"
#include <map>
#include <optional>
#include <vector>

namespace Honey::BFT::MVBA {

using Byte = std::byte;

struct MVBAConfig {
    int session_id;
    int node_id;
    int total_nodes;
    int fault_tolerance;
};

// MVBA messages wrap PRBC messages
// In "Standard" MVBA, we also need messages for the election phase (Coin/BA)
// But typically Coin/BA are separate components.
// MVBA itself coordinates N PRBC instances.
// The only MVBA-specific message is the "Main Vote" message?
// Actually, standard MVBA (e.g. Dumbo) uses ACS or similar structure.
// Dumbo flow:
// 1. Run N PRBCs in parallel (each node acts as leader for one).
// 2. Wait for N-f PRBCs to finish.
// 3. Propose finished PRBC IDs to a Binary Agreement or Common Coin?
// Dumbo paper says:
// Run ACS on the vector of finished PRBCs? No.
// Dumbo replaces ACS with:
// 1. Run N PRBCs.
// 2. When PRBC[i] finishes, node j adds i to set S_j.
// 3. When |S_j| >= N-f, participate in electing a leader.
// Election usually involves a Common Coin.
// If Coin returns L, and L is in S_j, we output PRBC[L].
// If L not in S_j, we wait for PRBC[L] to finish (using Late Message Cache help).

// We need a message type to wrap PRBC messages to route them.
// And maybe messages for the election if it's not external.
// Let's assume election is external (CoinService).

struct MVBAMessage {
    enum class Type : uint8_t {
        PRBC,
        Vote // For leader election / main vote if needed
    } type;

    int sender;
    int session_id;

    // If PRBC message:
    int prbc_instance_id; // Which PRBC instance (0..N-1)
    std::vector<Byte> payload; // Serialized PRBCMessage

    // If Vote message:
    // ...
};

struct Proposal {
    std::vector<Byte> data;
};

struct Output {
    int leader_id; // Who won
    std::vector<Byte> data; // The data
    std::vector<Byte> proof; // PRBC proof
};

struct PrbcResult {
    std::vector<Byte> data;
    std::vector<Byte> proof;
};

struct Action {
    enum class Type : uint8_t {
        StartPrbc,
        StartBa,
        Output
    } type;

    int instance_id = -1;
    std::vector<Byte> prbc_input;

    int ba_round = 0;
    int ba_input = 0;

    Output output;
};

} // namespace Honey::BFT::MVBA
