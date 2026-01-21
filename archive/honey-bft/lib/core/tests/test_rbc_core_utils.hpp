#include "core/rbc/messages.hpp"
#include "core/rbc/rbc_core.hpp"

#include <generator>
#include <utility>
#include <vector>

namespace Honey::BFT::RBC {

constexpr int kSessionId = 7;

inline Hash make_hash(uint8_t seed)
{
    Hash h {};
    h[0] = static_cast<Byte>(seed);
    return h;
}

inline std::vector<Byte> make_stripe(uint8_t value)
{
    return { static_cast<Byte>(value) };
}

inline Proof make_proof(size_t leaf_index)
{
    return Proof { .leaf_index = leaf_index, .siblings = {} };
}

inline RBCMessage make_val(int sender, const Hash& root, uint8_t stripe_value)
{
    return RBCMessage {
        .sender = sender,
        .session_id = kSessionId,
        .payload = ValPayload {
            .root_hash = root,
            .proof = make_proof(static_cast<size_t>(sender)),
            .stripe = make_stripe(stripe_value),
        },
    };
}

inline RBCMessage make_echo(int sender, const Hash& root, uint8_t stripe_value)
{
    return RBCMessage {
        .sender = sender,
        .session_id = kSessionId,
        .payload = EchoPayload {
            .root_hash = root,
            .proof = make_proof(static_cast<size_t>(sender)),
            .stripe = make_stripe(stripe_value),
        },
    };
}

inline RBCMessage make_ready(int sender, const Hash& root)
{
    return RBCMessage {
        .sender = sender,
        .session_id = kSessionId,
        .payload = ReadyPayload { .root_hash = root },
    };
}

inline std::vector<Effect> collect_effects(std::generator<Effect> gen)
{
    std::vector<Effect> effects;
    for (auto&& eff : gen) {
        effects.push_back(std::move(eff));
    }
    return effects;
}

} // namespace Honey::BFT::RBC
