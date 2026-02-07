#pragma once

#include "core/common.hpp"
#include <span>
#include <vector>

namespace Honey::BFT::MVBA {

using Byte = std::byte;

template <typename T>
concept PRBCServiceConcept = requires(T& t, int instance_id, std::span<const Byte> input, int sender_id, const std::vector<Byte>& msg_payload) {
    { t.start_prbc(instance_id, input) } -> std::same_as<void>;
    { t.dispatch_prbc_msg(instance_id, sender_id, msg_payload) } -> std::same_as<void>;
};

template <typename T>
concept BAServiceConcept = requires(T& t, int instance_id, int input_val, int sender_id, const std::vector<Byte>& msg_payload) {
    { t.start_ba(instance_id, input_val) } -> std::same_as<void>;
    { t.dispatch_ba_msg(instance_id, sender_id, msg_payload) } -> std::same_as<void>;
};

} // namespace Honey::BFT::MVBA
