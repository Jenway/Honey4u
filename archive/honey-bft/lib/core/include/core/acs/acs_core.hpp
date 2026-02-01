#pragma once

#include <generator>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <vector>

namespace Honey::BFT::ACS {
using Byte = std::byte;

struct ACSConfig {
    int session_id;
    int node_id;
    int total_nodes;
    int fault_tolerance;
    int leader_id;
};

struct Action {
    enum class Type : uint8_t {
        ProposeToBa, // Propose value to a specific BA instance
        Output // Final output ready
    } type;

    int ba_index {}; // Which BA instance
    int ba_value {}; // Value to propose (0 or 1)
    std::span<const std::vector<Byte>> output_data {}; // Final ACS output
};

class Core {
public:
    explicit Core(const ACSConfig& config);

    std::generator<Action> on_rbc_complete(int index, std::vector<Byte> data);
    std::generator<Action> on_ba_complete(int index, int decision);

    [[nodiscard]] int session_id() const { return sid_; }
    [[nodiscard]] int node_id() const { return pid_; }
    [[nodiscard]] bool is_complete() const { return output_triggered_; }
    [[nodiscard]] const std::vector<std::vector<Byte>>& get_output() const { return output_; }

private:
    int sid_, pid_, N_, f_;

    // RBC state
    std::set<int> rbc_completed_;
    std::map<int, std::vector<Byte>> rbc_data_;

    // BA state
    std::map<int, int> ba_input_decided_; // What we proposed to BA j
    std::set<int> ba_completed_; // Which BA instances completed
    std::map<int, int> ba_decisions_; // BA decisions

    int ba_yes_count_ = 0;
    bool vote_0_triggered_ = false;
    bool output_triggered_ = false;

    std::vector<std::vector<Byte>> output_;
};

} // namespace Honey::BFT::ACS
