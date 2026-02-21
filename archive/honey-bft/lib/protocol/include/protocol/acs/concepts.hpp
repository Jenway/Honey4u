#pragma once
#include <cstddef>
#include <span>
#include <vector>

namespace Honey::BFT::ACS {

using Byte = std::byte;

template <typename T>
concept RBCServiceConcept = requires(T& t, int instance_id, std::span<const Byte> input, int sender_id, const std::vector<Byte>& msg_payload) {
    { t.start_rbc(instance_id, input) } -> std::same_as<void>;
    { t.dispatch_rbc_msg(instance_id, sender_id, msg_payload) } -> std::same_as<void>;
};

template <typename T>
concept BAServiceConcept = requires(T& t, int instance_id, int input_val, int sender_id, const std::vector<Byte>& msg_payload) {
    { t.start_ba(instance_id, input_val) } -> std::same_as<void>;
    { t.dispatch_ba_msg(instance_id, sender_id, msg_payload) } -> std::same_as<void>;
};

} // namespace Honey::BFT::ACS
