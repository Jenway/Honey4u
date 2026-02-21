#include "core/coin/messages.hpp"
#include "core/common.hpp"
#include "protocol/coin/common_coin.hpp"
#include <chrono>
#include <deque>
#include <exec/static_thread_pool.hpp>
#include <exec/task.hpp>
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <optional>
#include <stdexec/execution.hpp>
#include <thread>

namespace Honey::BFT::Coin {

using Byte = std::byte;
using BytesSpan = std::span<const Byte>;

namespace {

    struct MockTransport {
        std::vector<Message> broadcasts;

        auto broadcast(Message msg)
        {
            broadcasts.push_back(msg);
            return stdexec::just();
        }

        auto unicast(int /*target*/, Message msg)
        {
            broadcasts.push_back(msg);
            return stdexec::just();
        }
    };

    struct MockCryptoSvc {
        auto async_combine_signatures(std::span<const PartialSignature> shares)
        {
            if (shares.empty()) {
                return stdexec::just(std::optional<Signature> {});
            }
            // Copy first share as combined result
            return stdexec::just(std::optional<Signature> { shares[0].value });
        }

        uint8_t hash_to_bit(const Signature& sig)
        {
            // Simple hash: LSB of first element
            return static_cast<uint8_t>(sig[0]) & 1;
        }

        auto async_sign_share(BytesSpan /*message*/)
        {
            std::array<limb_t, LIMB_COUNT> sig;
            std::ranges::fill(sig, 0xAA);
            return stdexec::just(sig);
        }

        auto async_verify_signature(const Signature&, BytesSpan)
        {
            return stdexec::just(true);
        }

        auto async_verify_share(const SignatureShare&, BytesSpan, int)
        {
            return stdexec::just(true);
        }
    };

    struct MockMessageStream {
        std::deque<Message> messages;

        auto next()
        {
            std::optional<Message> result;
            if (!messages.empty()) {
                result = messages.front();
                messages.pop_front();
            }
            return stdexec::just(result);
        }
    };

    static_assert(Transceiver<MockTransport>);
    static_assert(CryptoService<MockCryptoSvc>);
    static_assert(Honey::BFT::AsyncStreamOf<MockMessageStream, Message>);
} // namespace

struct CommonCoinTest {
    static constexpr int N = 4;
    static constexpr int f = 1;
    static constexpr int MyPid = 1;
    static constexpr int Sid = 200;
    static constexpr SystemContext SysCtx { .N = N, .f = f };

    MockTransport transport;
    MockCryptoSvc crypto;

    Message make_share(int sender, int round, uint64_t val_byte)
    {
        std::array<limb_t, LIMB_COUNT> sig;
        std::ranges::fill(sig, 0);
        sig[0] = val_byte;
        return Message {
            .sender = sender,
            .session_id = Sid,
            .payload = SharePayload { .round = round, .sig = sig }
        };
    }
};

// Test 1: Request coin broadcasts own share
TEST_CASE_FIXTURE(CommonCoinTest, "CommonCoinTest.RequestCoinBroadcastsShare")
{
    CommonCoin<MockTransport, MockCryptoSvc> coin(SysCtx, Sid, MyPid, transport, crypto);

    MockMessageStream empty_stream;

    // Start background processing in a separate task (non-blocking)
    // For this test we just want to verify broadcast behavior

    // Request coin for round 1
    exec::static_thread_pool pool(1);
    auto sched = pool.get_scheduler();

    // Start task to trigger broadcast
    stdexec::start_detached(
        stdexec::on(sched, coin.get_coin(1)));

    // Give it a moment to run (since it's detached and async)
    // Ideally we'd use a barrier or notification, but for this test we check broadcasts.
    // We can loop wait or just sync_wait on a separate condition.
    // But since MockTransport is synchronous (returns task<void> that completes immediately?),
    // it might just work if we yield or sleep.
    // However, stdexec::on might run immediately in this thread if scheduler allows, or in pool.
    // static_thread_pool runs in its own thread.
    // So we need to wait for the other thread to execute.
    // A simple busy wait or sleep loop check.

    // Wait for broadcast
    int retries = 0;
    while (transport.broadcasts.empty() && retries++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Should have broadcast our share
    REQUIRE_GE(transport.broadcasts.size(), 1);

    auto& msg = transport.broadcasts[0];
    CHECK_EQ(msg.sender, MyPid);
    CHECK_EQ(msg.session_id, Sid);
    CHECK_EQ(msg.payload.round, 1);
}

// Test 2: Combine shares when threshold reached
TEST_CASE_FIXTURE(CommonCoinTest, "CommonCoinTest.CombinesOnThresholdAndReturnsResult")
{
    CommonCoin<MockTransport, MockCryptoSvc> coin(SysCtx, Sid, MyPid, transport, crypto);

    MockMessageStream stream;
    // Provide threshold shares (f+1 = 2)
    stream.messages.push_back(make_share(0, 1, 0x00)); // Even = bit 0
    stream.messages.push_back(make_share(2, 1, 0x00));

    // Start processing messages
    auto run_task = coin.run(stream);
    auto run_result = stdexec::sync_wait(std::move(run_task));
    REQUIRE(run_result.has_value());

    // Now request the coin - should return immediately as it's computed
    auto request_task = coin.get_coin(1);
    auto result_opt = stdexec::sync_wait(std::move(request_task));
    REQUIRE(result_opt.has_value());
    uint8_t result = std::get<0>(*result_opt);

    // Result should be 0 (even number hashes to 0)
    CHECK_EQ(result, 0);
}

// Test 3: Ignore messages for wrong session
TEST_CASE_FIXTURE(CommonCoinTest, "CommonCoinTest.IgnoresWrongSession")
{
    CommonCoin<MockTransport, MockCryptoSvc> coin(SysCtx, Sid, MyPid, transport, crypto);

    MockMessageStream stream;
    Message wrong_msg = make_share(0, 1, 0x00);
    wrong_msg.session_id = 999; // Wrong session
    stream.messages.push_back(wrong_msg);

    auto run_task = coin.run(stream);
    auto result = stdexec::sync_wait(std::move(run_task));
    REQUIRE(result.has_value());

    // Should not have processed, no broadcasts triggered
    CHECK_EQ(transport.broadcasts.size(), 0);
}

// Test 4: Ignore duplicate shares from same sender
TEST_CASE_FIXTURE(CommonCoinTest, "CommonCoinTest.IgnoresDuplicateShares")
{
    CommonCoin<MockTransport, MockCryptoSvc> coin(SysCtx, Sid, MyPid, transport, crypto);

    MockMessageStream stream;
    stream.messages.push_back(make_share(0, 1, 0x00));
    stream.messages.push_back(make_share(0, 1, 0xFF)); // Duplicate from node 0, different value
    stream.messages.push_back(make_share(2, 1, 0x00)); // From node 2

    auto run_task = coin.run(stream);
    stdexec::sync_wait(std::move(run_task));

    // Combination should happen with threshold shares
    // The duplicate should be ignored
    auto request_task = coin.get_coin(1);
    auto result_opt = stdexec::sync_wait(std::move(request_task));
    REQUIRE(result_opt.has_value());
    uint8_t result = std::get<0>(*result_opt);
    CHECK_EQ(result, 0);
}

// Test 5: Multiple rounds are independent
TEST_CASE_FIXTURE(CommonCoinTest, "CommonCoinTest.MultipleRoundsIndependent")
{
    CommonCoin<MockTransport, MockCryptoSvc> coin(SysCtx, Sid, MyPid, transport, crypto);

    MockMessageStream stream1;
    stream1.messages.push_back(make_share(0, 1, 0x00)); // Round 1, bit 0
    stream1.messages.push_back(make_share(2, 1, 0x00));

    MockMessageStream stream2;
    stream2.messages.push_back(make_share(0, 2, 0x01)); // Round 2, bit 1
    stream2.messages.push_back(make_share(2, 2, 0x01));

    // Process both rounds
    auto run_task1 = coin.run(stream1);
    stdexec::sync_wait(std::move(run_task1));

    auto run_task2 = coin.run(stream2);
    stdexec::sync_wait(std::move(run_task2));

    // Get results for both rounds
    auto result1_task = coin.get_coin(1);
    auto result1_opt = stdexec::sync_wait(std::move(result1_task));
    REQUIRE(result1_opt.has_value());
    uint8_t result1 = std::get<0>(*result1_opt);

    auto result2_task = coin.get_coin(2);
    auto result2_opt = stdexec::sync_wait(std::move(result2_task));
    REQUIRE(result2_opt.has_value());
    uint8_t result2 = std::get<0>(*result2_opt);

    CHECK_EQ(result1, 0);
    CHECK_EQ(result2, 1);
}

// Test 6: Hash to bit correctness
TEST_CASE_FIXTURE(CommonCoinTest, "CommonCoinTest.HashToBitWorks")
{
    CommonCoin<MockTransport, MockCryptoSvc> coin(SysCtx, Sid, MyPid, transport, crypto);

    MockMessageStream stream_even;
    stream_even.messages.push_back(make_share(0, 1, 0x00)); // Even
    stream_even.messages.push_back(make_share(2, 1, 0x00));

    auto run_task = coin.run(stream_even);
    stdexec::sync_wait(std::move(run_task));

    auto result_task = coin.get_coin(1);
    auto result_opt = stdexec::sync_wait(std::move(result_task));
    REQUIRE(result_opt.has_value());
    uint8_t result = std::get<0>(*result_opt);

    CHECK_EQ(result, 0); // Even should give 0

    // Now test odd
    MockMessageStream stream_odd;
    stream_odd.messages.push_back(make_share(0, 2, 0x01)); // Odd
    stream_odd.messages.push_back(make_share(2, 2, 0x01));

    auto run_task2 = coin.run(stream_odd);
    stdexec::sync_wait(std::move(run_task2));

    auto result_task2 = coin.get_coin(2);
    auto result_opt2 = stdexec::sync_wait(std::move(result_task2));
    REQUIRE(result_opt2.has_value());
    uint8_t result2 = std::get<0>(*result_opt2);

    CHECK_EQ(result2, 1); // Odd should give 1
}

} // namespace Honey::BFT::Coin
