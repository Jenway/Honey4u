#pragma once

#include "core/common.hpp"
#include <optional>
#include <vector>

namespace Honey::BFT {

template <typename T>
concept LateMessageCache = requires(T& cache, int sid, const std::vector<std::byte>& proof) {
    // Called when a broadcast instance completes
    { cache.add_completed_instance(sid, proof) } -> std::same_as<void>;

    // Called when a message is received for a potentially completed instance
    // Returns true if the message was handled (i.e., instance is completed and cached)
    { cache.handle_late_message(sid, std::vector<std::byte> {}) } -> std::same_as<bool>;
};

// No-op implementation for benchmarking/legacy behavior
struct NoOpLateMessageCache {
    void add_completed_instance(int, const std::vector<std::byte>&) { }
    bool handle_late_message(int, const std::vector<std::byte>&) { return false; }
};

} // namespace Honey::BFT
