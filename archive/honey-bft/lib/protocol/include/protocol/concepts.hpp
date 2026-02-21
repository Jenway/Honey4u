#pragma once

#include <exec/task.hpp>
#include <stdexec/execution.hpp>

namespace Honey::BFT {

template <typename T>
using TaskT = exec::task<T>;

template <typename T>
using TaskOf = exec::task<T>;

template <class S>
concept Sender = stdexec::sender<S>;

template <class S, class T = void>
concept SenderOf = requires {
    requires Sender<S>;
    // TODO: Verify value type if needed, but for now just check it's a sender
};

// Concept for a message stream with next() method returning optional<Message>
template <typename Stream, typename Message>
concept AsyncStreamOf = requires(Stream& s) {
    { s.next() } -> SenderOf<std::optional<Message>>;
};

} // namespace Honey::BFT
