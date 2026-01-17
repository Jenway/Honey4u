#pragma once
#include "crypto/common.hpp"
#include "crypto/merkle_tree.hpp"
#include <gtest/gtest.h>
#include <iomanip>
#include <string>
#include <vector>

namespace Honey::Crypto {

// 辅助：String -> vector<Byte>
inline std::vector<Byte> to_bytes(std::string_view s)
{
    std::vector<Byte> res;
    res.reserve(s.size());
    for (char c : s)
        res.push_back(static_cast<Byte>(c));
    return res;
}

// 辅助：GTest 打印 Byte
inline void PrintTo(Byte b, std::ostream* os)
{
    *os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
}

// 辅助：GTest 打印 Hash (std::array<Byte, 32>)
inline void PrintTo(const MerkleTree::Hash& h, std::ostream* os)
{
    *os << "\"";
    for (const auto& b : h) {
        *os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    *os << "\"";
}

} // namespace Honey::Crypto