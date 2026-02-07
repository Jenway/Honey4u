#pragma once

#include "service/network/message_bus.hpp"
#include <cstdint>
#include <span>
#include <tuple>
#include <utility>
#include <vector>

namespace Honey::BFT::Network {

inline std::vector<std::byte> encode_frame(const Frame& frame)
{
    const uint32_t payload_size = static_cast<uint32_t>(frame.payload.size());
    std::vector<std::byte> out;
    out.reserve(1 + 4 + 4 + payload_size);
    out.push_back(static_cast<std::byte>(frame.tag));
    out.push_back(static_cast<std::byte>((payload_size >> 24) & 0xFF));
    out.push_back(static_cast<std::byte>((payload_size >> 16) & 0xFF));
    out.push_back(static_cast<std::byte>((payload_size >> 8) & 0xFF));
    out.push_back(static_cast<std::byte>(payload_size & 0xFF));
    const uint32_t target = static_cast<uint32_t>(frame.target);
    out.push_back(static_cast<std::byte>((target >> 24) & 0xFF));
    out.push_back(static_cast<std::byte>((target >> 16) & 0xFF));
    out.push_back(static_cast<std::byte>((target >> 8) & 0xFF));
    out.push_back(static_cast<std::byte>(target & 0xFF));
    out.insert(out.end(), frame.payload.begin(), frame.payload.end());
    return out;
}

inline std::optional<std::tuple<ProtocolTag, uint32_t, int>> decode_header(std::span<const std::byte> data)
{
    if (data.size() < 9) {
        return std::nullopt;
    }
    auto tag = static_cast<ProtocolTag>(std::to_integer<uint8_t>(data[0]));
    uint32_t size = (static_cast<uint32_t>(std::to_integer<uint8_t>(data[1])) << 24)
        | (static_cast<uint32_t>(std::to_integer<uint8_t>(data[2])) << 16)
        | (static_cast<uint32_t>(std::to_integer<uint8_t>(data[3])) << 8)
        | static_cast<uint32_t>(std::to_integer<uint8_t>(data[4]));
    uint32_t target = (static_cast<uint32_t>(std::to_integer<uint8_t>(data[5])) << 24)
        | (static_cast<uint32_t>(std::to_integer<uint8_t>(data[6])) << 16)
        | (static_cast<uint32_t>(std::to_integer<uint8_t>(data[7])) << 8)
        | static_cast<uint32_t>(std::to_integer<uint8_t>(data[8]));
    return std::make_tuple(tag, size, static_cast<int>(target));
}

} // namespace Honey::BFT::Network
