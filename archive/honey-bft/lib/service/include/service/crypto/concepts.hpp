#pragma once

#include "service/coin/concepts.hpp"
#include "service/rbc/concepts.hpp"

namespace Honey::BFT::Crypto {

template <typename T>
concept CryptoService = Coin::CryptoService<T> && RBC::CryptoService<T>;

} // namespace Honey::BFT::Crypto
