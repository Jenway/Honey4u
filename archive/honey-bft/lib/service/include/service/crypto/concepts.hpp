#pragma once

#include "protocol/coin/concepts.hpp"
#include "protocol/rbc/concepts.hpp"

namespace Honey::BFT::Crypto {

template <typename T>
concept CryptoService = Coin::CryptoService<T> && RBC::CryptoService<T>;

} // namespace Honey::BFT::Crypto
