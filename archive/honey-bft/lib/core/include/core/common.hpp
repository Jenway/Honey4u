#pragma once

namespace Honey::BFT {
using NodeId = int;

struct SystemContext {
    int N; ///< Total number of nodes
    int f; ///< Maximum number of Byzantine faults tolerated
};

} // namespace Honey::BFT
