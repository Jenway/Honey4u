#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace Honey::BFT::Coin {

using limb_t = uint64_t;
static constexpr size_t BYTE_LENGTH = 144;
static constexpr size_t LIMB_COUNT = BYTE_LENGTH / sizeof(limb_t);

using G1_Point = std::array<limb_t, LIMB_COUNT>; // 18 * 8 = 144 bytes
using Signature = G1_Point;
using SignatureShare = G1_Point;

struct PartialSignature {
    int player_id;
    SignatureShare value;
};

struct SharePayload {
    int round;
    SignatureShare sig;
};

struct Message {
    int sender;
    int session_id;
    SharePayload payload;
};

} // namespace Honey::BFT::Coin
