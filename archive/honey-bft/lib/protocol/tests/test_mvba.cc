#include "core/common.hpp"
#include "protocol/mvba/mvba.hpp"
#include <deque>
#include <exec/task.hpp>
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <optional>
#include <stdexec/execution.hpp>
#include <string>
#include <vector>

namespace Honey::BFT::MVBA {

template <typename T>
using TaskT = exec::task<T>;

struct MockPRBCService {
    std::vector<std::string> call_log;

    void start_prbc(int instance_id, std::span<const Byte> input)
    {
        call_log.push_back(input.empty() ? "start_prbc_empty" : "start_prbc_input");
        (void)instance_id;
    }

    void dispatch_prbc_msg(int instance_id, int sender_id, const std::vector<Byte>&)
    {
        call_log.push_back("dispatch_prbc");
        (void)instance_id;
        (void)sender_id;
    }
};

struct MockBAService {
    std::vector<std::string> call_log;

    void start_ba(int instance_id, int input_val)
    {
        call_log.push_back("start_ba");
        (void)instance_id;
        (void)input_val;
    }

    void dispatch_ba_msg(int instance_id, int sender_id, const std::vector<Byte>&)
    {
        call_log.push_back("dispatch_ba");
        (void)instance_id;
        (void)sender_id;
    }
};

struct MockEventStream {
    std::deque<MVBAEvent> events;

    TaskT<std::optional<MVBAEvent>> next()
    {
        if (events.empty()) {
            co_return std::nullopt;
        }
        auto ev = std::move(events.front());
        events.pop_front();
        co_return ev;
    }
};

struct MVBATest {
    static constexpr int N = 4;
    static constexpr int f = 1;
    static constexpr int MyPid = 0;
    static constexpr SystemContext sys_ctx { .N = N, .f = f };

    MockPRBCService prbc_svc;
    MockBAService ba_svc;
    MockEventStream stream;
};

TEST_CASE_FIXTURE(MVBATest, "MVBATest.StartsPrbcAndOutputsOnLeader")
{
    MVBAService<TaskT, MockPRBCService, MockBAService> mvba(sys_ctx, MyPid, prbc_svc, ba_svc);

    Proposal proposal { .data = { std::byte { 0x01 } } };

    // Simulate PRBC completions (0,2,3) first
    stream.events.push_back(MVBAEvent {
        .type = MVBAEvent::Type::PrbcDone,
        .instance_id = 0,
        .prbc_output = { .value = { std::byte { 0x00 } }, .proof = { std::byte { 0xAA } } } });
    stream.events.push_back(MVBAEvent {
        .type = MVBAEvent::Type::PrbcDone,
        .instance_id = 2,
        .prbc_output = { .value = { std::byte { 0x02 } }, .proof = { std::byte { 0xAA } } } });
    stream.events.push_back(MVBAEvent {
        .type = MVBAEvent::Type::PrbcDone,
        .instance_id = 3,
        .prbc_output = { .value = { std::byte { 0x03 } }, .proof = { std::byte { 0xAA } } } });

    // BA done picks leader 1 before PRBC[1] finishes
    stream.events.push_back(MVBAEvent {
        .type = MVBAEvent::Type::BaDone,
        .ba_output = 1 });

    // PRBC[1] finishes later
    stream.events.push_back(MVBAEvent {
        .type = MVBAEvent::Type::PrbcDone,
        .instance_id = 1,
        .prbc_output = { .value = { std::byte { 0x01 } }, .proof = { std::byte { 0xAA } } } });

    auto task = mvba.run(proposal, stream);
    auto result = stdexec::sync_wait(std::move(task));

    REQUIRE(result.has_value());
    auto [output] = *result;

    CHECK_EQ(output.leader_id, 1);
    CHECK_EQ(output.data, std::vector<Byte>({ std::byte { 0x01 } }));
    CHECK_EQ(output.proof, std::vector<Byte>({ std::byte { 0xAA } }));

    CHECK_FALSE(prbc_svc.call_log.empty());
    CHECK_FALSE(ba_svc.call_log.empty());
    bool started_ba = false;
    for (const auto& log : ba_svc.call_log) {
        if (log == "start_ba") {
            started_ba = true;
        }
    }
    CHECK(started_ba);
}

} // namespace Honey::BFT::MVBA
