#include "core/prbc/prbc_core.hpp"
#include <gtest/gtest.h>

namespace Honey::BFT::PRBC {

TEST(PRBCCoreTest, TriggersSignReadyOnEchoThreshold)
{
    RBCConfig cfg { .session_id = 1, .node_id = 0, .total_nodes = 4, .fault_tolerance = 1, .leader_id = 0 };
    Core core(cfg);

    // Simulate leader VAL to self
    ValPayload val {
        .root_hash = {},
        .proof_index = 0,
        .merkle_path = {},
        .stripe = { std::byte { 0x01 } }
    };
    PRBCMessage leader_msg {
        .type = PRBCMessage::Type::Leader,
        .sender = 0,
        .session_id = 1,
        .payload = val
    };

    for (auto action : core.on_msg(leader_msg)) {
        (void)action;
    }

    // Echo threshold for N=4,f=1 is 3; add two more ECHOs
    EchoPayload echo_p {
        .root_hash = {},
        .proof_index = 1,
        .merkle_path = {},
        .stripe = { std::byte { 0x02 } }
    };
    PRBCMessage echo_msg2 {
        .type = PRBCMessage::Type::Echo,
        .sender = 2,
        .session_id = 1,
        .payload = echo_p
    };
    PRBCMessage echo_msg3 {
        .type = PRBCMessage::Type::Echo,
        .sender = 3,
        .session_id = 1,
        .payload = echo_p
    };

    bool sign_ready = false;
    for (auto action : core.on_msg(echo_msg2)) {
        if (action.type == Action::Type::Signal && action.tag == 1) {
            sign_ready = true;
        }
    }
    for (auto action : core.on_msg(echo_msg3)) {
        if (action.type == Action::Type::Signal && action.tag == 1) {
            sign_ready = true;
        }
    }

    EXPECT_TRUE(sign_ready);
}

} // namespace Honey::BFT::PRBC
