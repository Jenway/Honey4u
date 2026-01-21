#include "core/common.hpp"
#include "core/rbc/reliable_broadcast.hpp"
#include "utils_simple_task.hpp"
#include <gtest/gtest.h>

#include <expected>
#include <optional>
#include <utility>
#include <variant>
#include <vector>

namespace Honey::BFT::RBC {
using Honey::Crypto::Byte;
using Honey::Crypto::MerkleTree::Hash;
using Honey::Crypto::MerkleTree::Tree;

namespace {

    struct TransportMock {
        struct UnicastRecord {
            int target;
            RBCMessage msg;
        };

        std::vector<UnicastRecord> unicasts;
        std::vector<RBCMessage> broadcasts;

        InlineTask<void> unicast(int target, const RBCMessage& msg)
        {
            unicasts.push_back({ target, msg });
            co_return;
        }

        InlineTask<void> broadcast(const RBCMessage& msg)
        {
            broadcasts.push_back(msg);
            co_return;
        }
    };

    struct CryptoMock {
        std::vector<std::vector<Byte>> stripes;
        Tree tree;

        InlineTask<Tree> async_build_merkle_tree(int, int, BytesSpan)
        {
            co_return tree;
        }

        InlineTask<bool> async_verify_merkle(BytesSpan, const Proof&, const Hash&)
        {
            co_return true;
        }

        InlineTask<std::expected<std::vector<Byte>, std::error_code>> async_decode(int, int, const std::map<NodeId, std::vector<Byte>>& shards)
        {
            // Return concatenated bytes to prove decode is invoked.
            std::vector<Byte> out;
            for (const auto& [_, stripe] : shards) {
                out.insert(out.end(), stripe.begin(), stripe.end());
            }
            co_return out;
        }
    };

    struct VectorStream {
        std::vector<RBCMessage> msgs;
        size_t idx = 0;

        InlineTask<std::optional<RBCMessage>> next()
        {
            if (idx >= msgs.size())
                co_return std::nullopt;
            co_return msgs[idx++];
        }
    };

    std::vector<Byte> byte_vec(uint8_t v)
    {
        return { static_cast<Byte>(v) };
    }

} // namespace

TEST(ReliableBroadcastTest, NonLeaderDeliversOnReadyQuorum)
{
    const int N = 4;
    const int f = 1;
    const int leader = 0;
    const int my_pid = 1;
    const int sid = 9;

    std::vector<std::vector<Byte>> stripes { byte_vec(0x10), byte_vec(0x11), byte_vec(0x12), byte_vec(0x13) };
    const Tree tree = Tree::build(std::vector<std::vector<Byte>>(stripes));
    const auto root = tree.root();

    TransportMock transport {};
    CryptoMock crypto { .stripes = stripes, .tree = tree };
    SystemContext sys_ctx { .N = N, .f = f };

    ReliableBroadcast<TransportMock, CryptoMock> rbc(sys_ctx, sid, my_pid, leader, transport, crypto);

    VectorStream stream;
    stream.msgs.push_back(RBCMessage {
        .sender = leader,
        .session_id = sid,
        .payload = ValPayload { .root_hash = root, .proof = *tree.prove(my_pid), .stripe = tree.leaf(my_pid) },
    });
    stream.msgs.push_back(RBCMessage {
        .sender = 2,
        .session_id = sid,
        .payload = EchoPayload { .root_hash = root, .proof = *tree.prove(2), .stripe = tree.leaf(2) },
    });
    stream.msgs.push_back(RBCMessage {
        .sender = 3,
        .session_id = sid,
        .payload = EchoPayload { .root_hash = root, .proof = *tree.prove(3), .stripe = tree.leaf(3) },
    });
    stream.msgs.push_back(RBCMessage { .sender = 2, .session_id = sid, .payload = ReadyPayload { root } });
    stream.msgs.push_back(RBCMessage { .sender = 3, .session_id = sid, .payload = ReadyPayload { root } });

    auto task = rbc.run<InlineTask>(std::nullopt, stream);
    const RBCOutput output = task.get();

    EXPECT_EQ(output.root_hash, root);
    ASSERT_GE(output.shards.size(), 3U);
    EXPECT_NE(output.shards.find(my_pid), output.shards.end());
    EXPECT_NE(output.shards.find(2), output.shards.end());
    EXPECT_NE(output.shards.find(3), output.shards.end());

    // Should have broadcast ECHO and READY once.
    ASSERT_EQ(transport.broadcasts.size(), 2U);
    EXPECT_TRUE(std::holds_alternative<EchoPayload>(transport.broadcasts[0].payload));
    EXPECT_TRUE(std::holds_alternative<ReadyPayload>(transport.broadcasts[1].payload));
}
} // namespace Honey::BFT::RBC
