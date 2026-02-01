#pragma once
#include "core/acs/acs_core.hpp"
#include "core/common.hpp"
#include "service/acs/concepts.hpp"
#include "service/acs/events.hpp"
#include "service/acs/messages.hpp"
#include "service/concepts.hpp"

namespace Honey::BFT::ACS {
template <
    template <typename> typename TaskT,
    RBCServiceConcept RBCSvc,
    BAServiceConcept BASvc>
class ACS {
public:
    ACS(const SystemContext& sys, int my_pid, RBCSvc& rbc_svc, BASvc& ba_svc)
        : core_({ .session_id = 0, .node_id = my_pid, .total_nodes = sys.N, .fault_tolerance = sys.f }) // Fix: Correct field names
        , rbc_svc_(rbc_svc)
        , ba_svc_(ba_svc)
        , N_(sys.N)
        , my_pid_(my_pid)
    {
    }

    // ACS Run now accepts a unified Event Stream
    // It doesn't need to know how "Channel" is implemented, as long as it can next() out Event
    template <AsyncStreamOf<ACSEvent> EventStream>
    auto run(std::vector<Byte> my_input, EventStream stream)
        -> TaskT<std::vector<std::vector<Byte>>>
    {
        // 1. Start all RBCs
        // Note: ACS is only responsible for issuing orders, Service is responsible for specific Task generation and running
        for (int i = 0; i < N_; ++i) {
            if (i == my_pid_) {
                rbc_svc_.start_rbc(i, my_input);
            } else {
                rbc_svc_.start_rbc(i, {}); // Empty here means no local input, started as a receiver
            }
        }

        // 2. Event loop
        while (auto event_opt = co_await stream.next()) {
            ACSEvent event = std::move(*event_opt);

            if (auto* net_ev = std::get_if<NetworkMsgEvent>(&event)) {
                handle_network(*net_ev);
            } else if (auto* rbc_ev = std::get_if<RbcDoneEvent>(&event)) {
                handle_rbc_done(*rbc_ev);
            } else if (auto* ba_ev = std::get_if<BaDoneEvent>(&event)) {
                handle_ba_done(*ba_ev);
            }

            // Check if finished
            if (core_.is_complete()) { // Fix: use is_complete()
                // At this time, all RBC data for BAs that are 1 should have been collected via RbcDoneEvent
                co_return core_.get_output();
            }
        }

        co_return std::vector<std::vector<Byte>> {};
    }

private:
    void handle_network(const NetworkMsgEvent& ev)
    {
        // ACS is just routing
        if (ev.is_rbc) {
            rbc_svc_.dispatch_rbc_msg(ev.instance_id, ev.sender, ev.payload);
        } else {
            // BA message routing directly. The Service layer needs to handle logic for "caching messages when BA has not started yet",
            // or the Service layer ensures that start_ba can be called multiple times / safely.
            ba_svc_.dispatch_ba_msg(ev.instance_id, ev.sender, ev.payload);
        }
    }

    void handle_rbc_done(const RbcDoneEvent& ev)
    {
        // Update logic state machine
        auto actions = core_.on_rbc_complete(ev.instance_id, ev.data);

        // If Core suggests giving input 1 to BA, command Service to start BA
        for (auto action : actions) {
            if (action.type == Action::Type::ProposeToBa) {
                ba_svc_.start_ba(action.ba_index, action.ba_value);
            }
        }
    }

    void handle_ba_done(const BaDoneEvent& ev)
    {
        // Update logic state machine
        auto actions = core_.on_ba_complete(ev.instance_id, ev.decision);

        // If vote 0 logic is triggered, command Service to start corresponding BA
        for (auto action : actions) {
            if (action.type == Action::Type::ProposeToBa) {
                ba_svc_.start_ba(action.ba_index, action.ba_value);
            }
        }
    }

    Core core_;
    RBCSvc& rbc_svc_;
    BASvc& ba_svc_;
    int N_;
    int my_pid_;
};

} // namespace Honey::BFT::ACS
