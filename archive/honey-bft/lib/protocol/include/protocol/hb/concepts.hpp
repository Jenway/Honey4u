#pragma once
#include "crypto/threshold/tpke.hpp"
#include "protocol/concepts.hpp"
#include <concepts>
#include <vector>

namespace Honey::BFT::HoneyBadger {

using Byte = std::byte;
using Honey::BFT::SenderOf;
using Honey::Crypto::Tpke::Ciphertext;
using Honey::Crypto::Tpke::DecryptionShare;
using Honey::Crypto::Tpke::HybridCiphertext;
using Honey::Crypto::Tpke::PartialDecryption;

// Message type for decryption shares
struct DecShareMessage {
    int epoch;
    int ciphertext_index;
    int sender_id;
    std::vector<Byte> share_data;
};

// Concept for ACS Service
template <typename T>
concept ACSServiceConcept = requires(T& acs_svc, int epoch, std::vector<Byte> input) {
    { acs_svc.start_acs(epoch, input) } -> SenderOf<void>;
};

/**
 * @brief Concept for TPKE Crypto Service
 *
 * 纯密码学操作，不涉及序列化。
 * 输入输出都是类型化的数据结构。
 */
template <typename T>
concept CryptoServiceConcept = requires(T& crypto_svc,
    std::span<const Byte> plaintext,
    Ciphertext ciphertext,
    std::span<const PartialDecryption> shares) {
    // Encrypt plaintext, returns HybridCiphertext (NOT serialized)
    { crypto_svc.async_encrypt(plaintext) } -> SenderOf<HybridCiphertext>;

    // Generate decryption share, returns DecryptionShare (P1 point, NOT serialized)
    { crypto_svc.async_decrypt_share(ciphertext) } -> SenderOf<DecryptionShare>;

    // Combine shares to decrypt, returns plaintext or nullopt
    {
        crypto_svc.async_decrypt(ciphertext, shares)
    } -> SenderOf<std::optional<std::vector<Byte>>>;
};

// Concept for Transceiver (network transport)
template <typename T>
concept Transceiver = requires(T& t, DecShareMessage msg) {
    { t.broadcast(msg) } -> SenderOf<void>;
};

} // namespace Honey::BFT::HoneyBadger
