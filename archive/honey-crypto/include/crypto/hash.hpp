#pragma once

#include "crypto/types.hpp"

namespace Honey::Crypto::Utils {

Hash256 sha256(BytesSpan data);

} // namespace Honey::Crypto::Utils
