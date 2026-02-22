#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

namespace Honey::BFT::Network {

enum class ProtocolTag : uint8_t {
    Rbc = 1,
    Prbc = 2,
    Ba = 3,
    Coin = 4,
    Acs = 5,
    HbDecShare = 6
};

#pragma pack(push, 1)
struct WireHeader {
    uint32_t payload_len;
    ProtocolTag protocol_tag;
    int32_t session_id;
    int32_t instance_id;
    int32_t sender_id;
};
#pragma pack(pop)
inline constexpr uint32_t MAX_PAYLOAD_SIZE = 16 * 1024 * 1024;

// L2 路由器的键
struct RouteKey {
    ProtocolTag tag;
    int32_t session_id;
    int32_t instance_id;

    bool operator==(const RouteKey& other) const = default;
};

} // namespace Honey::BFT::Network

template <>
struct std::hash<Honey::BFT::Network::RouteKey> {
    std::size_t operator()(const Honey::BFT::Network::RouteKey& k) const noexcept
    {
        return (static_cast<std::size_t>(k.tag)) ^ (std::hash<int32_t> {}(k.session_id) << 1) ^ (std::hash<int32_t> {}(k.instance_id) << 2);
    }
};
