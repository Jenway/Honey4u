#pragma once

#include "core/common.hpp"
#include "core/mvba/mvba_core.hpp"
#include "protocol/concepts.hpp"
#include "protocol/mvba/concepts.hpp"
#include <deque>
#include <exec/task.hpp>
#include <map>
#include <optional>
#include <stdexcept>
#include <stdexec/execution.hpp>

namespace Honey::BFT::MVBA {

using Byte = std::byte;

struct MVBAEvent {
    enum class Type {
        NetworkPrbc,
        NetworkBa,
        PrbcDone,
        BaDone
    } type;

    int instance_id = -1;
    int sender_id = -1;
    std::vector<Byte> payload;
    PRBC::PRBCOutput prbc_output;
    int ba_output = 0;
};

// MVBA Service orchestrates PRBC instances and BA + CommonCoin for leader election.
// This class is modeled after ACS: it only routes events and triggers actions.

template <
    template <typename> typename TaskT,
    PRBCServiceConcept PRBCSvc,
    BAServiceConcept BASvc>
class MVBAService {
public:
    MVBAService(const SystemContext& sys, int my_pid, PRBCSvc& prbc_svc, BASvc& ba_svc)
        : core_({ .session_id = 0, .node_id = my_pid, .total_nodes = sys.N, .fault_tolerance = sys.f })
        , prbc_svc_(prbc_svc)
        , ba_svc_(ba_svc)
        , N_(sys.N)
        , my_pid_(my_pid)
    {
    }

    template <typename EventStream>
        requires AsyncStreamOf<EventStream, MVBAEvent>
    auto run(Proposal proposal, EventStream stream) -> TaskT<Output>
    {
        // Start PRBCs
        for (int i = 0; i < N_; ++i) {
            if (i == my_pid_) {
                prbc_svc_.start_prbc(i, proposal.data);
            } else {
                prbc_svc_.start_prbc(i, {});
            }
        }

        while (auto ev_opt = co_await stream.next()) {
            MVBAEvent ev = std::move(*ev_opt);

            if (ev.type == MVBAEvent::Type::NetworkPrbc) {
                prbc_svc_.dispatch_prbc_msg(ev.instance_id, ev.sender_id, ev.payload);
            } else if (ev.type == MVBAEvent::Type::NetworkBa) {
                ba_svc_.dispatch_ba_msg(ev.instance_id, ev.sender_id, ev.payload);
            } else if (ev.type == MVBAEvent::Type::PrbcDone) {
                handle_prbc_done(ev);
            } else if (ev.type == MVBAEvent::Type::BaDone) {
                handle_ba_done(ev);
            }

            if (output_) {
                co_return *output_;
            }
        }

        co_return Output {};
    }

private:
    void handle_prbc_done(const MVBAEvent& ev)
    {
        PrbcResult res { .data = ev.prbc_output.value, .proof = ev.prbc_output.proof };
        for (auto action : core_.on_prbc_result(ev.instance_id, res)) {
            if (action.type == Action::Type::StartBa) {
                ba_svc_.start_ba(action.ba_round, action.ba_input);
            } else if (action.type == Action::Type::Output) {
                output_ = action.output;
            }
        }
    }

    void handle_ba_done(const MVBAEvent& ev)
    {
        for (auto action : core_.on_coin_result(ev.ba_output)) {
            if (action.type == Action::Type::Output) {
                output_ = action.output;
            }
        }
    }

    Core core_;
    PRBCSvc& prbc_svc_;
    BASvc& ba_svc_;
    int N_;
    int my_pid_;
    std::optional<Output> output_;
};

} // namespace Honey::BFT::MVBA
