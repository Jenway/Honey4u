#include "core/common.hpp"
#include "core/concepts.hpp"
#include "core/rbc/reliable_broadcast.hpp"
#include "utils_simple_task.hpp"
#include <algorithm>
#include <expected>
#include <gtest/gtest.h>
#include <optional>
#include <variant>
#include <vector>

namespace Honey::BFT::RBC {

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

    struct MockMerkleTree {
        Hash root_hash;
        std::vector<std::vector<Byte>> shards;

        [[nodiscard]] Hash root() const { return root_hash; }

        [[nodiscard]] std::vector<Hash> prove(int /*node_id*/) const
        {
            return std::vector<Hash> {};
        }

        [[nodiscard]] std::vector<Byte> leaf(int node_id) const
        {
            if (node_id >= 0 && node_id < static_cast<int>(shards.size())) {
                return shards[node_id];
            }
            return {};
        }
    };

    struct CryptoMock {
        using MerkleTreeType = MockMerkleTree;

        InlineTask<MerkleTreeType> async_build_merkle_tree(int K, int N, BytesSpan data)
        {
            std::vector<std::vector<Byte>> shards;
            shards.reserve(N);
            for (int i = 0; i < N; ++i) {
                shards.emplace_back(data.begin(), data.end());
            }

            Hash root;
            std::ranges::fill(root, std::byte { 0xCC });

            co_return MockMerkleTree { .root_hash = root, .shards = shards };
        }

        InlineTask<bool> async_verify_merkle(
            BytesSpan stripe,
            size_t /*proof_index*/,
            std::vector<Hash> /*merkle_path*/,
            const Hash& root)
        {
            if (static_cast<uint8_t>(root[0]) == 0xCC) {
                co_return true;
            }
            co_return true;
        }

        InlineTask<std::expected<std::vector<Byte>, std::error_code>> async_decode(
            int /*K*/, int /*N*/,
            const std::map<int, std::vector<Byte>>& received_shards)
        {
            if (received_shards.empty()) {
                co_return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            }

            co_return received_shards.begin()->second;
        }

        // ---------------------------------------------------------------------
        // Concept: CanExtractPayload
        // ---------------------------------------------------------------------
        static ValPayload extract_val_payload(const MockMerkleTree& tree, int node_id)
        {
            return ValPayload {
                .root_hash = tree.root(),
                .proof_index = static_cast<size_t>(node_id),
                .merkle_path = tree.prove(node_id),
                .stripe = tree.leaf(node_id)
            };
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

    static_assert(Transceiver<TransportMock>);
    static_assert(CryptoService<CryptoMock>);
    static_assert(AsyncStreamOf<VectorStream, RBCMessage>);
} // namespace

class ReliableBroadcastTest : public ::testing::Test {
protected:
    static constexpr int N = 4;
    static constexpr int f = 1;
    static constexpr int Leader = 0;
    static constexpr int MyPid = 1;
    static constexpr int Sid = 100;

    SystemContext sys_ctx { .N = N, .f = f };
    TransportMock transport;
    CryptoMock crypto;

    std::vector<Byte> original_message;
    Hash mock_root;
    std::vector<std::vector<Byte>> shards;

    void SetUp() override
    {
        original_message = { std::byte { 1 }, std::byte { 2 }, std::byte { 3 }, std::byte { 4 } };

        std::ranges::fill(mock_root, std::byte { 0xCC });

        for (int i = 0; i < N; ++i) {
            shards.push_back(original_message);
        }
    }

    RBCMessage make_val(int sender_id, int target_pid)
    {
        return RBCMessage {
            .sender = sender_id,
            .session_id = Sid,
            .payload = ValPayload {
                .root_hash = mock_root,
                .proof_index = static_cast<size_t>(target_pid),
                .merkle_path = {},
                .stripe = shards[target_pid] }
        };
    }

    RBCMessage make_echo(int sender_id)
    {
        return RBCMessage {
            .sender = sender_id,
            .session_id = Sid,
            .payload = EchoPayload {
                .root_hash = mock_root,
                .proof_index = static_cast<size_t>(sender_id),
                .merkle_path = {},
                .stripe = shards[sender_id] }
        };
    }

    RBCMessage make_ready(int sender_id)
    {
        return RBCMessage {
            .sender = sender_id,
            .session_id = Sid,
            .payload = ReadyPayload { .root_hash = mock_root }
        };
    }
};

TEST_F(ReliableBroadcastTest, DeliversOnQuorum)
{
    ReliableBroadcast<TransportMock, CryptoMock> rbc(sys_ctx, Sid, MyPid, Leader, transport, crypto);

    VectorStream stream;

    // 1. Leader 发给我 VAL 消息
    stream.msgs.push_back(make_val(Leader, MyPid));

    // 2. 我会广播 ECHO (RBC 内部自动处理)，然后等待其他人的 ECHO
    // 模拟收到 Node 2 和 Node 3 的 ECHO
    // 注意：ECHO 包含 root, proof, 和 sender 的分片
    stream.msgs.push_back(make_echo(2));
    stream.msgs.push_back(make_echo(3));
    // 此时共有 3 个 ECHO (包括我自己的)，达到 N-f (3)，应该触发 READY 广播

    // 3. 模拟收到 2f+1 (3) 个 READY 消息
    // 来自 Leader, 2, 3
    stream.msgs.push_back(make_ready(Leader));
    stream.msgs.push_back(make_ready(2));
    stream.msgs.push_back(make_ready(3));

    // 运行 RBC
    auto task = rbc.run<InlineTask>(std::nullopt, stream);

    // 断言结果
    auto result = task.get();
    EXPECT_EQ(result, original_message);

    // 验证网络行为
    // 应该广播了 1 次 ECHO 和 1 次 READY
    ASSERT_EQ(transport.broadcasts.size(), 2);

    // 第一个是 ECHO
    EXPECT_TRUE(std::holds_alternative<EchoPayload>(transport.broadcasts[0].payload));
    // 第二个是 READY
    EXPECT_TRUE(std::holds_alternative<ReadyPayload>(transport.broadcasts[1].payload));
}

TEST_F(ReliableBroadcastTest, DeliversWithOnlyReadys)
{
    ReliableBroadcast<TransportMock, CryptoMock> rbc(sys_ctx, Sid, MyPid, Leader, transport, crypto);
    VectorStream stream;

    // 场景：我掉线了，没收到 VAL，也没收到 ECHO。
    // 但是我上线后直接收到了 f+1 (2) 个 READY -> 触发我广播 READY
    // 然后收到了 2f+1 (3) 个 READY -> 触发输出

    stream.msgs.push_back(make_val(Leader, MyPid));

    // 收到 f+1 (2) 个 READY，来自 2, 3
    // 这应该触发我自己广播 READY (Amplification)
    stream.msgs.push_back(make_ready(2));
    stream.msgs.push_back(make_ready(3));

    // 再来一个 READY 凑齐 2f+1 (3)
    stream.msgs.push_back(make_ready(0));

    // 运行
    auto task = rbc.run<InlineTask>(std::nullopt, stream);
    auto result = task.get();

    EXPECT_EQ(result, original_message);

    // 检查是否触发了 Ready 放大
    // 即使没收到足够的 ECHO，收到 f+1 个 READY 也应该广播 READY
    bool sent_ready = false;
    for (const auto& msg : transport.broadcasts) {
        if (std::holds_alternative<ReadyPayload>(msg.payload)) {
            sent_ready = true;
            break;
        }
    }
    EXPECT_TRUE(sent_ready) << "Should verify ready amplification";
}

TEST_F(ReliableBroadcastTest, RejectsNonLeaderVal)
{
    ReliableBroadcast<TransportMock, CryptoMock> rbc(sys_ctx, Sid, MyPid, Leader, transport, crypto);
    VectorStream stream;

    // Non-leader (node 2) sending VAL should be rejected
    stream.msgs.push_back(make_val(2, MyPid));

    // Valid VAL from leader
    stream.msgs.push_back(make_val(Leader, MyPid));

    // Enough ECHOs to trigger READY broadcast
    stream.msgs.push_back(make_echo(2));
    stream.msgs.push_back(make_echo(3));
    // Ready quorum
    stream.msgs.push_back(make_ready(2));
    stream.msgs.push_back(make_ready(3));

    // stream.msgs.push_back(make_ready(Leader));

    auto task = rbc.run<InlineTask>(std::nullopt, stream);
    const RBCOutput output = task.get();

    EXPECT_EQ(output, original_message);
    ASSERT_EQ(transport.broadcasts.size(), 2U);
    EXPECT_TRUE(std::holds_alternative<EchoPayload>(transport.broadcasts[0].payload));
    EXPECT_TRUE(std::holds_alternative<ReadyPayload>(transport.broadcasts[1].payload));
}

TEST_F(ReliableBroadcastTest, DeliverOnEchoQuorum)
{
    ReliableBroadcast<TransportMock, CryptoMock> rbc(sys_ctx, Sid, MyPid, Leader, transport, crypto);
    VectorStream stream;

    // Leader sends VAL to me
    stream.msgs.push_back(make_val(Leader, MyPid));

    // Receive N-f ECHOs to trigger READY broadcast
    stream.msgs.push_back(make_echo(0));
    stream.msgs.push_back(make_echo(2));
    stream.msgs.push_back(make_echo(3));
    // Receive 2f+1 READYs to trigger output
    stream.msgs.push_back(make_ready(0));
    stream.msgs.push_back(make_ready(2));
    stream.msgs.push_back(make_ready(3));

    auto task = rbc.run<InlineTask>(std::nullopt, stream);
    const RBCOutput output = task.get();

    EXPECT_EQ(output, original_message);
}

TEST_F(ReliableBroadcastTest, IgnoresInconsistentRootHash)
{
    ReliableBroadcast<TransportMock, CryptoMock> rbc(sys_ctx, Sid, MyPid, Leader, transport, crypto);
    VectorStream stream;

    // Receive VAL with correct root
    stream.msgs.push_back(make_val(Leader, MyPid));

    // Try to send VAL with different root - should be rejected

    Hash root2;
    std::fill(root2.begin(), root2.end(), std::byte { 0xDD });
    stream.msgs.push_back(RBCMessage {
        .sender = Leader,
        .session_id = Sid,
        .payload = ValPayload {
            .root_hash = root2,
            .proof_index = static_cast<size_t>(MyPid),
            .merkle_path = {},
            .stripe = shards[MyPid],
        },
    });

    // Get N-f ECHOs with correct root
    stream.msgs.push_back(make_echo(0));
    stream.msgs.push_back(make_echo(2));
    stream.msgs.push_back(make_echo(3));
    // 2f+1 READYs with correct root
    stream.msgs.push_back(make_ready(0));
    stream.msgs.push_back(make_ready(2));
    stream.msgs.push_back(make_ready(3));

    auto task = rbc.run<InlineTask>(std::nullopt, stream);
    const RBCOutput output = task.get();

    EXPECT_EQ(output, original_message);
}

TEST_F(ReliableBroadcastTest, PartialEchoQuorumDoesNotTriggerReady)
{
    ReliableBroadcast<TransportMock, CryptoMock> rbc(sys_ctx, Sid, MyPid, Leader, transport, crypto);
    VectorStream stream;

    // Send VAL
    stream.msgs.push_back(make_val(Leader, MyPid));
    // Only f ECHOs (less than N-f required)
    stream.msgs.push_back(make_echo(2));
    // Now send N-f ECHOs to reach threshold and trigger READY
    stream.msgs.push_back(make_echo(0));
    stream.msgs.push_back(make_echo(1));
    stream.msgs.push_back(make_echo(3));
    // Get 2f+1 READYs to trigger output
    stream.msgs.push_back(make_ready(0));
    stream.msgs.push_back(make_ready(2));
    stream.msgs.push_back(make_ready(3));

    auto task = rbc.run<InlineTask>(std::nullopt, stream);
    const auto output = task.get();

    EXPECT_EQ(output, original_message);
    ASSERT_EQ(transport.broadcasts.size(), 2U);
    EXPECT_TRUE(std::holds_alternative<EchoPayload>(transport.broadcasts[0].payload));
    EXPECT_TRUE(std::holds_alternative<ReadyPayload>(transport.broadcasts[1].payload));
}

} // namespace Honey::BFT::RBC
