#pragma once

namespace Honey::BFT {

/// Node identifier type
using NodeId = int;

/// System-wide configuration parameters
struct SystemContext {
    int N; ///< Total number of nodes
    int f; ///< Maximum number of Byzantine faults tolerated
};

} // namespace Honey::BFT
