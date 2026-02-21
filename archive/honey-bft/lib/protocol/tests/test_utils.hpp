#pragma once

#include <exec/task.hpp>
#include <stdexec/execution.hpp>

namespace Honey::BFT::TestUtils {

template <typename T>
using Task = exec::task<T>;

inline auto sync_wait(auto&& sender)
{
    return stdexec::sync_wait(std::forward<decltype(sender)>(sender));
}

} // namespace Honey::BFT::TestUtils
