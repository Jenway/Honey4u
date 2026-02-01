#include "crypto/threshold/tpke.hpp"
#include <cstring>

namespace Honey::Crypto::Tpke {

// Ciphertext serialization format:
// [u_component: 96 bytes] [v_len: 4 bytes] [v_component: v_len bytes] [w_component: 192 bytes]
std::vector<Byte> Ciphertext::serialize() const
{
    std::vector<Byte> result;

    // Serialize U (P1)
    auto u_bytes = u_component.serialize();
    result.insert(result.end(), u_bytes.begin(), u_bytes.end());

    // Serialize V length (4 bytes, big-endian)
    uint32_t v_len = static_cast<uint32_t>(v_component.size());
    result.push_back(static_cast<Byte>((v_len >> 24) & 0xFF));
    result.push_back(static_cast<Byte>((v_len >> 16) & 0xFF));
    result.push_back(static_cast<Byte>((v_len >> 8) & 0xFF));
    result.push_back(static_cast<Byte>(v_len & 0xFF));

    // Serialize V
    result.insert(result.end(), v_component.begin(), v_component.end());

    // Serialize W (P2)
    std::array<uint8_t, 192> w_bytes;
    w_component.serialize(w_bytes);
    for (auto b : w_bytes) {
        result.push_back(static_cast<Byte>(b));
    }

    return result;
}

std::expected<Ciphertext, std::error_code> Ciphertext::deserialize(std::span<const Byte> data)
{
    // Minimum size: 96 (U) + 4 (len) + 0 (V) + 192 (W) = 292 bytes
    if (data.size() < 292) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    size_t offset = 0;

    // Deserialize U
    std::array<Byte, 96> u_bytes;
    std::memcpy(u_bytes.data(), data.data() + offset, 96);
    auto u_result = P1::deserialize(u_bytes);
    if (!u_result) {
        return std::unexpected(u_result.error());
    }
    offset += 96;

    // Deserialize V length
    uint32_t v_len = (static_cast<uint32_t>(data[offset]) << 24) | (static_cast<uint32_t>(data[offset + 1]) << 16) | (static_cast<uint32_t>(data[offset + 2]) << 8) | static_cast<uint32_t>(data[offset + 3]);
    offset += 4;

    // Validate size
    if (data.size() < offset + v_len + 192) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    // Deserialize V
    std::vector<Byte> v_component(data.begin() + offset, data.begin() + offset + v_len);
    offset += v_len;

    // Deserialize W
    std::array<Byte, 192> w_bytes;
    std::memcpy(w_bytes.data(), data.data() + offset, 192);
    auto w_result = P2::deserialize(w_bytes);
    if (!w_result) {
        return std::unexpected(w_result.error());
    }

    return Ciphertext {
        .u_component = *u_result,
        .v_component = std::move(v_component),
        .w_component = *w_result
    };
}

// HybridCiphertext serialization format:
// [key_ct_len: 4 bytes] [key_ciphertext: key_ct_len bytes] [data_ct_len: 4 bytes] [data_ciphertext: data_ct_len bytes]
std::vector<Byte> HybridCiphertext::serialize() const
{
    std::vector<Byte> result;

    // Serialize key_ciphertext
    auto key_bytes = key_ciphertext.serialize();
    uint32_t key_len = static_cast<uint32_t>(key_bytes.size());

    // Write key length
    result.push_back(static_cast<Byte>((key_len >> 24) & 0xFF));
    result.push_back(static_cast<Byte>((key_len >> 16) & 0xFF));
    result.push_back(static_cast<Byte>((key_len >> 8) & 0xFF));
    result.push_back(static_cast<Byte>(key_len & 0xFF));

    // Write key ciphertext
    result.insert(result.end(), key_bytes.begin(), key_bytes.end());

    // Write data ciphertext length
    uint32_t data_len = static_cast<uint32_t>(data_ciphertext.size());
    result.push_back(static_cast<Byte>((data_len >> 24) & 0xFF));
    result.push_back(static_cast<Byte>((data_len >> 16) & 0xFF));
    result.push_back(static_cast<Byte>((data_len >> 8) & 0xFF));
    result.push_back(static_cast<Byte>(data_len & 0xFF));

    // Write data ciphertext
    result.insert(result.end(), data_ciphertext.begin(), data_ciphertext.end());

    return result;
}

std::expected<HybridCiphertext, std::error_code> HybridCiphertext::deserialize(std::span<const Byte> data)
{
    // Minimum size: 4 (key_len) + 292 (min Ciphertext) + 4 (data_len) = 300 bytes
    if (data.size() < 300) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    size_t offset = 0;

    // Read key_ciphertext length
    uint32_t key_len = (static_cast<uint32_t>(data[offset]) << 24) | (static_cast<uint32_t>(data[offset + 1]) << 16) | (static_cast<uint32_t>(data[offset + 2]) << 8) | static_cast<uint32_t>(data[offset + 3]);
    offset += 4;

    if (data.size() < offset + key_len + 4) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    // Deserialize key_ciphertext
    auto key_ct_result = Ciphertext::deserialize(
        std::span(data.data() + offset, key_len));
    if (!key_ct_result) {
        return std::unexpected(key_ct_result.error());
    }
    offset += key_len;

    // Read data_ciphertext length
    uint32_t data_len = (static_cast<uint32_t>(data[offset]) << 24) | (static_cast<uint32_t>(data[offset + 1]) << 16) | (static_cast<uint32_t>(data[offset + 2]) << 8) | static_cast<uint32_t>(data[offset + 3]);
    offset += 4;

    if (data.size() < offset + data_len) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    // Deserialize data_ciphertext
    std::vector<Byte> data_ct(data.begin() + offset, data.begin() + offset + data_len);

    return HybridCiphertext {
        .key_ciphertext = *key_ct_result,
        .data_ciphertext = std::move(data_ct)
    };
}

} // namespace Honey::Crypto::Tpke
