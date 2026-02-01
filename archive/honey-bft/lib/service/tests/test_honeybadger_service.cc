#include "service/hb/concepts.hpp"
#include "service/hb/events.hpp"
#include "service/hb/honeybadger.hpp"
#include <exec/static_thread_pool.hpp>
#include <gtest/gtest.h>
#include <queue>
#include <stdexec/execution.hpp>

namespace Honey::BFT::HoneyBadger {

using Byte = std::byte;

// ============================================================================
// Mock Services (满足 Concepts)
// ============================================================================

/**
 * @brief Mock TPKE Service - 纯密码学操作，不处理序列化
 */
class MockTPKEService {
public:
    auto async_encrypt(std::span<const Byte> plaintext) -> exec::task<Honey::Crypto::Tpke::HybridCiphertext>
    {
        // 简单"加密"：创建一个假的 HybridCiphertext
        Honey::Crypto::Tpke::HybridCiphertext hct {
            .key_ciphertext = {
                .u_component = Honey::Crypto::bls::P1::identity(),
                .v_component = std::vector<Byte>(plaintext.begin(), plaintext.end()),
                .w_component = Honey::Crypto::bls::P2::identity() },
            .data_ciphertext = std::vector<Byte>(plaintext.begin(), plaintext.end())
        };
        co_return hct;
    }

    auto async_decrypt_share(const Honey::Crypto::Tpke::Ciphertext& ciphertext)
        -> exec::task<Honey::Crypto::bls::P1>
    {
        // 返回 identity point 作为解密份额
        co_return Honey::Crypto::bls::P1::identity();
    }

    auto async_decrypt(
        const Honey::Crypto::Tpke::Ciphertext& ciphertext,
        std::span<const Honey::Crypto::Tpke::PartialDecryption> shares)
        -> exec::task<std::optional<std::vector<Byte>>>
    {
        // 检查份额数量
        if (shares.size() < 2) { // 需要 f+1 = 2 份额
            co_return std::nullopt;
        }

        // 简单"解密"：返回 v_component
        co_return ciphertext.v_component;
    }
};

/**
 * @brief Mock ACS Service
 */
class MockACSService {
public:
    auto start_acs(int epoch, std::vector<Byte> input) -> exec::task<void>
    {
        acs_calls.push({ epoch, input });
        co_return;
    }

    std::queue<std::pair<int, std::vector<Byte>>> acs_calls;
};

/**
 * @brief Mock Transceiver
 */
class MockTransceiver {
public:
    auto broadcast(DecShareMessage msg) -> exec::task<void>
    {
        broadcast_calls.push(msg);
        co_return;
    }

    std::queue<DecShareMessage> broadcast_calls;
};

/**
 * @brief Mock 消息流 - 实现 AsyncStreamOf<HBEvent>
 */
class MockEventStream {
public:
    void push_event(HBEvent event)
    {
        events_.push(std::move(event));
    }

    auto next() -> exec::task<std::optional<HBEvent>>
    {
        if (events_.empty()) {
            co_return std::nullopt;
        }
        auto event = std::move(events_.front());
        events_.pop();
        co_return event;
    }

private:
    std::queue<HBEvent> events_;
};

// ============================================================================
// Test Fixture
// ============================================================================

class HoneyBadgerServiceTest : public ::testing::Test {
protected:
    static constexpr int N = 4;
    static constexpr int f = 1;
    static constexpr int MyPid = 1;
    static constexpr int BatchSize = 100;

    HoneyBadgerConfig config {
        .node_id = MyPid,
        .total_nodes = N,
        .fault_tolerance = f,
        .batch_size = BatchSize
    };

    MockTransceiver transport;
    MockACSService acs_svc;
    MockTPKEService crypto_svc;
    exec::static_thread_pool pool { 4 };

    std::vector<Byte> make_data(const std::string& s)
    {
        std::vector<Byte> data;
        for (char c : s) {
            data.push_back(static_cast<Byte>(c));
        }
        return data;
    }
};

// ============================================================================
// Tests
// ============================================================================

TEST_F(HoneyBadgerServiceTest, ConstructionSucceeds)
{
    HoneyBadger<MockTransceiver, MockACSService, MockTPKEService> hb(
        config, transport, acs_svc, crypto_svc);

    EXPECT_EQ(hb.current_epoch(), 0);
    EXPECT_FALSE(hb.is_epoch_complete(0));
}

TEST_F(HoneyBadgerServiceTest, SubmitTransactionsStoresInBuffer)
{
    HoneyBadger hb(config, transport, acs_svc, crypto_svc);

    std::vector<std::vector<Byte>> txs;
    for (int i = 0; i < 10; ++i) {
        txs.push_back(make_data("tx" + std::to_string(i)));
    }
    hb.submit_transactions(std::move(txs));

    // Buffer should have transactions (can't check directly, but run() should work)
}

TEST_F(HoneyBadgerServiceTest, RunStartsFirstEpoch)
{
    HoneyBadger hb(config, transport, acs_svc, crypto_svc);

    // Submit transactions
    std::vector<std::vector<Byte>> txs;
    for (int i = 0; i < 5; ++i) {
        txs.push_back(make_data("tx" + std::to_string(i)));
    }
    hb.submit_transactions(std::move(txs));

    // Create empty event stream (will terminate immediately)
    MockEventStream stream;

    // Run until stream is empty
    auto run_task = hb.run(stream);
    auto blocks = stdexec::sync_wait(std::move(run_task));

    // Should have called ACS once for epoch 0
    ASSERT_FALSE(acs_svc.acs_calls.empty());
    auto [epoch, input] = acs_svc.acs_calls.front();
    EXPECT_EQ(epoch, 0);

    // Input should be encrypted (starts with "ENC:")
    ASSERT_GE(input.size(), 4);
    EXPECT_EQ(input[0], static_cast<Byte>('E'));
    EXPECT_EQ(input[1], static_cast<Byte>('N'));
    EXPECT_EQ(input[2], static_cast<Byte>('C'));
}

TEST_F(HoneyBadgerServiceTest, ACSCompleteTriggersDecryptionShares)
{
    HoneyBadger hb(config, transport, acs_svc, crypto_svc);

    hb.submit_transactions({ make_data("tx1"), make_data("tx2") });

    // Create event stream with ACS completion
    MockEventStream stream;
    stream.push_event(ACSCompleteEvent {
        .epoch = 0,
        .ciphertexts = {
            make_data("ENC:cipher0"),
            make_data("ENC:cipher1") } });

    auto run_task = hb.run(stream);
    auto blocks = stdexec::sync_wait(std::move(run_task));

    // Should broadcast decryption shares (2 ciphertexts)
    EXPECT_EQ(transport.broadcast_calls.size(), 2);

    auto msg1 = transport.broadcast_calls.front();
    EXPECT_EQ(msg1.epoch, 0);
    EXPECT_EQ(msg1.ciphertext_index, 0);
    transport.broadcast_calls.pop();

    auto msg2 = transport.broadcast_calls.front();
    EXPECT_EQ(msg2.epoch, 0);
    EXPECT_EQ(msg2.ciphertext_index, 1);
}

TEST_F(HoneyBadgerServiceTest, CollectSharesAndDecrypt)
{
    HoneyBadger hb(config, transport, acs_svc, crypto_svc);

    hb.submit_transactions({ make_data("tx1") });

    MockEventStream stream;

    // Step 1: ACS completes with 1 ciphertext
    stream.push_event(ACSCompleteEvent {
        .epoch = 0,
        .ciphertexts = { make_data("ENC:data") } });

    // Step 2: Receive f+1 = 2 decryption shares
    stream.push_event(DecShareReceivedEvent {
        .epoch = 0,
        .ciphertext_index = 0,
        .sender_id = 0,
        .share_data = make_data("share0") });

    stream.push_event(DecShareReceivedEvent {
        .epoch = 0,
        .ciphertext_index = 0,
        .sender_id = 1,
        .share_data = make_data("share1") });

    // Run
    auto run_task = hb.run(stream);
    auto result = stdexec::sync_wait(std::move(run_task));

    ASSERT_TRUE(result.has_value());
    auto& [blocks] = result.value();

    // Should have one block
    ASSERT_EQ(blocks.size(), 1);
    EXPECT_FALSE(blocks[0].empty());
}

TEST_F(HoneyBadgerServiceTest, MultipleEpochsSequential)
{
    HoneyBadger hb(config, transport, acs_svc, crypto_svc);

    hb.submit_transactions({ make_data("tx1"), make_data("tx2") });

    MockEventStream stream;

    // Epoch 0: ACS + decrypt
    stream.push_event(ACSCompleteEvent {
        .epoch = 0,
        .ciphertexts = { make_data("ENC:data0") } });
    stream.push_event(DecShareReceivedEvent {
        .epoch = 0, .ciphertext_index = 0, .sender_id = 0, .share_data = make_data("s0") });
    stream.push_event(DecShareReceivedEvent {
        .epoch = 0, .ciphertext_index = 0, .sender_id = 1, .share_data = make_data("s1") });

    // Epoch 1: ACS + decrypt
    stream.push_event(ACSCompleteEvent {
        .epoch = 1,
        .ciphertexts = { make_data("ENC:data1") } });
    stream.push_event(DecShareReceivedEvent {
        .epoch = 1, .ciphertext_index = 0, .sender_id = 0, .share_data = make_data("s0") });
    stream.push_event(DecShareReceivedEvent {
        .epoch = 1, .ciphertext_index = 0, .sender_id = 1, .share_data = make_data("s1") });

    auto run_task = hb.run(stream);
    auto result = stdexec::sync_wait(std::move(run_task));

    ASSERT_TRUE(result.has_value());
    auto& [blocks] = result.value();

    // Should have two blocks
    EXPECT_EQ(blocks.size(), 2);
}

TEST_F(HoneyBadgerServiceTest, InsufficientSharesDoesNotDecrypt)
{
    HoneyBadger hb(config, transport, acs_svc, crypto_svc);

    hb.submit_transactions({ make_data("tx1") });

    MockEventStream stream;

    stream.push_event(ACSCompleteEvent {
        .epoch = 0,
        .ciphertexts = { make_data("ENC:data") } });

    // Only 1 share (need 2)
    stream.push_event(DecShareReceivedEvent {
        .epoch = 0, .ciphertext_index = 0, .sender_id = 0, .share_data = make_data("s0") });

    auto run_task = hb.run(stream);
    auto result = stdexec::sync_wait(std::move(run_task));

    ASSERT_TRUE(result.has_value());
    auto& [blocks] = result.value();

    // No block output (insufficient shares)
    EXPECT_EQ(blocks.size(), 0);
}

TEST_F(HoneyBadgerServiceTest, DuplicateSharesIgnored)
{
    HoneyBadger hb(config, transport, acs_svc, crypto_svc);

    hb.submit_transactions({ make_data("tx1") });

    MockEventStream stream;

    stream.push_event(ACSCompleteEvent {
        .epoch = 0,
        .ciphertexts = { make_data("ENC:data") } });

    // Same sender twice
    stream.push_event(DecShareReceivedEvent {
        .epoch = 0, .ciphertext_index = 0, .sender_id = 0, .share_data = make_data("s0") });
    stream.push_event(DecShareReceivedEvent {
        .epoch = 0, .ciphertext_index = 0, .sender_id = 0, .share_data = make_data("s0_dup") });

    // Add another valid share
    stream.push_event(DecShareReceivedEvent {
        .epoch = 0, .ciphertext_index = 0, .sender_id = 1, .share_data = make_data("s1") });

    auto run_task = hb.run(stream);
    auto result = stdexec::sync_wait(std::move(run_task));

    ASSERT_TRUE(result.has_value());
    auto& [blocks] = result.value();

    // Should complete with 2 unique shares
    EXPECT_EQ(blocks.size(), 1);
}

} // namespace Honey::BFT::HoneyBadger
