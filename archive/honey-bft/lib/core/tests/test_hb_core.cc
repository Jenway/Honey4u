#include "core/hb/honeybadger_core.hpp"
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace Honey::BFT::HoneyBadger {

class HoneyBadgerCoreTest : public ::testing::Test {
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

    std::vector<Byte> make_data(const std::string& s)
    {
        std::vector<Byte> data;
        for (char c : s) {
            data.push_back(static_cast<Byte>(c));
        }
        return data;
    }

    std::vector<Action> collect_actions(std::generator<Action>&& gen)
    {
        std::vector<Action> result;
        for (auto action : gen) {
            result.push_back(std::move(action));
        }
        return result;
    }
};

TEST_F(HoneyBadgerCoreTest, StartEpochGeneratesACSAction)
{
    Core core(config);

    auto encrypted_proposal = make_data("encrypted_data");
    auto actions = collect_actions(core.start_epoch(0, encrypted_proposal));

    ASSERT_EQ(actions.size(), 1);
    EXPECT_EQ(actions[0].type, Action::Type::StartACS);
    EXPECT_EQ(actions[0].epoch, 0);
    EXPECT_EQ(actions[0].acs_input, encrypted_proposal);
}

TEST_F(HoneyBadgerCoreTest, DuplicateEpochStartIgnored)
{
    Core core(config);

    auto encrypted_proposal = make_data("encrypted_data");
    collect_actions(core.start_epoch(0, encrypted_proposal));

    // Try to start same epoch again
    auto actions = collect_actions(core.start_epoch(0, make_data("other_data")));

    EXPECT_EQ(actions.size(), 0);
}

TEST_F(HoneyBadgerCoreTest, ACSCompletionTransitionsToDecrypting)
{
    Core core(config);

    // Start epoch
    collect_actions(core.start_epoch(0, make_data("encrypted")));

    // ACS completes with 3 ciphertexts
    std::vector<std::vector<Byte>> ciphertexts = {
        make_data("cipher0"),
        make_data("cipher1"),
        make_data("cipher2")
    };

    auto actions = collect_actions(core.on_acs_complete(0, ciphertexts));

    // No actions generated (decryption shares are generated separately)
    EXPECT_EQ(actions.size(), 0);
}

TEST_F(HoneyBadgerCoreTest, DecryptionShareBroadcastAction)
{
    Core core(config);

    // Start epoch and complete ACS
    collect_actions(core.start_epoch(0, make_data("encrypted")));
    collect_actions(core.on_acs_complete(0, { make_data("cipher0") }));

    // Broadcast our decryption share for ciphertext 0
    auto share_data = make_data("my_share");
    auto actions = collect_actions(
        core.broadcast_decryption_share(0, 0, share_data));

    ASSERT_EQ(actions.size(), 1);
    EXPECT_EQ(actions[0].type, Action::Type::BroadcastDecShare);
    EXPECT_EQ(actions[0].dec_share_msg.epoch, 0);
    EXPECT_EQ(actions[0].dec_share_msg.ciphertext_index, 0);
    EXPECT_EQ(actions[0].dec_share_msg.sender_id, MyPid);
    EXPECT_EQ(actions[0].dec_share_msg.share_data, share_data);
}

TEST_F(HoneyBadgerCoreTest, CollectDecryptionSharesUntilThreshold)
{
    Core core(config);

    // Setup
    collect_actions(core.start_epoch(0, make_data("encrypted")));
    collect_actions(core.on_acs_complete(0, { make_data("cipher0") }));

    // Receive shares from different nodes
    DecryptionShareMsg msg0 { .epoch = 0, .ciphertext_index = 0, .sender_id = 0, .share_data = make_data("share0") };
    DecryptionShareMsg msg1 { .epoch = 0, .ciphertext_index = 0, .sender_id = 1, .share_data = make_data("share1") };
    DecryptionShareMsg msg2 { .epoch = 0, .ciphertext_index = 0, .sender_id = 2, .share_data = make_data("share2") };

    // First share
    EXPECT_TRUE(core.on_decryption_share(msg0));
    auto shares = core.get_shares_if_ready(0, 0);
    EXPECT_FALSE(shares.has_value()); // Need f+1 = 2 shares

    // Second share - reaches threshold (f+1 = 2)
    EXPECT_TRUE(core.on_decryption_share(msg1));
    shares = core.get_shares_if_ready(0, 0);
    ASSERT_TRUE(shares.has_value());
    EXPECT_EQ(shares->size(), 2); // Should have 2 shares
}

TEST_F(HoneyBadgerCoreTest, DuplicateSharesIgnored)
{
    Core core(config);

    collect_actions(core.start_epoch(0, make_data("encrypted")));
    collect_actions(core.on_acs_complete(0, { make_data("cipher0") }));

    DecryptionShareMsg msg { .epoch = 0, .ciphertext_index = 0, .sender_id = 0, .share_data = make_data("share0") };

    EXPECT_TRUE(core.on_decryption_share(msg));
    EXPECT_FALSE(core.on_decryption_share(msg)); // Duplicate
}

TEST_F(HoneyBadgerCoreTest, OutputWhenAllCiphertextsDecrypted)
{
    Core core(config);

    // Start epoch
    collect_actions(core.start_epoch(0, make_data("encrypted")));

    // ACS outputs 2 ciphertexts
    collect_actions(core.on_acs_complete(0, {
                                                make_data("cipher0"),
                                                make_data("cipher1"),
                                            }));

    // Decrypt first ciphertext
    core.on_decrypted(0, 0, make_data("plain0"));

    // Not ready yet
    auto actions = collect_actions(core.try_output(0));
    EXPECT_EQ(actions.size(), 0);

    // Decrypt second ciphertext
    core.on_decrypted(0, 1, make_data("plain1"));

    // Now should output
    actions = collect_actions(core.try_output(0));
    ASSERT_EQ(actions.size(), 1);
    EXPECT_EQ(actions[0].type, Action::Type::Output);
    EXPECT_EQ(actions[0].epoch, 0);
    EXPECT_EQ(actions[0].output_block.size(), 2);
}

TEST_F(HoneyBadgerCoreTest, EpochCompletionCheck)
{
    Core core(config);

    collect_actions(core.start_epoch(0, make_data("encrypted")));
    EXPECT_FALSE(core.is_epoch_complete(0));

    collect_actions(core.on_acs_complete(0, { make_data("cipher0") }));
    EXPECT_FALSE(core.is_epoch_complete(0));

    core.on_decrypted(0, 0, make_data("plain0"));
    collect_actions(core.try_output(0));
    EXPECT_TRUE(core.is_epoch_complete(0));
}

TEST_F(HoneyBadgerCoreTest, TransactionBufferManagement)
{
    Core core(config);

    // Submit transactions
    std::vector<std::vector<Byte>> txs;
    for (int i = 0; i < 50; ++i) {
        txs.push_back(make_data("tx" + std::to_string(i)));
    }
    core.submit_transactions(std::move(txs));

    EXPECT_EQ(core.buffer_size(), 50);

    // Get proposal (B/N = 100/4 = 25, but only 50 available)
    auto proposal = core.get_proposal_transactions();
    EXPECT_EQ(proposal.size(), 25); // B/N = 25

    // Buffer should remain unchanged (get_proposal doesn't remove)
    EXPECT_EQ(core.buffer_size(), 50);
}

TEST_F(HoneyBadgerCoreTest, MultipleEpochsIndependent)
{
    Core core(config);

    // Start epoch 0
    collect_actions(core.start_epoch(0, make_data("epoch0_encrypted")));

    // Start epoch 1
    collect_actions(core.start_epoch(1, make_data("epoch1_encrypted")));

    // Complete epoch 1 first
    collect_actions(core.on_acs_complete(1, { make_data("cipher1") }));
    core.on_decrypted(1, 0, make_data("plain1"));
    auto actions = collect_actions(core.try_output(1));
    ASSERT_EQ(actions.size(), 1);
    EXPECT_EQ(actions[0].epoch, 1);

    // Epoch 0 should still be pending
    EXPECT_FALSE(core.is_epoch_complete(0));

    // Complete epoch 0
    collect_actions(core.on_acs_complete(0, { make_data("cipher0") }));
    core.on_decrypted(0, 0, make_data("plain0"));
    actions = collect_actions(core.try_output(0));
    ASSERT_EQ(actions.size(), 1);
    EXPECT_EQ(actions[0].epoch, 0);
}

TEST_F(HoneyBadgerCoreTest, SharesForWrongEpochIgnored)
{
    Core core(config);

    collect_actions(core.start_epoch(0, make_data("encrypted")));
    collect_actions(core.on_acs_complete(0, { make_data("cipher0") }));

    // Share for non-existent epoch
    DecryptionShareMsg msg { .epoch = 99, .ciphertext_index = 0, .sender_id = 0, .share_data = make_data("share") };

    EXPECT_FALSE(core.on_decryption_share(msg));
}

TEST_F(HoneyBadgerCoreTest, GetCiphertextFromACSOutput)
{
    Core core(config);

    collect_actions(core.start_epoch(0, make_data("encrypted")));

    std::vector<std::vector<Byte>> ciphertexts = {
        make_data("cipher0"),
        make_data("cipher1"),
        make_data("cipher2")
    };

    collect_actions(core.on_acs_complete(0, ciphertexts));

    // Should be able to retrieve ciphertexts
    auto cipher0 = core.get_ciphertext(0, 0);
    ASSERT_TRUE(cipher0.has_value());
    EXPECT_EQ(*cipher0, ciphertexts[0]);

    auto cipher1 = core.get_ciphertext(0, 1);
    ASSERT_TRUE(cipher1.has_value());
    EXPECT_EQ(*cipher1, ciphertexts[1]);

    // Invalid index
    auto invalid = core.get_ciphertext(0, 99);
    EXPECT_FALSE(invalid.has_value());
}

} // namespace Honey::BFT::HoneyBadger
