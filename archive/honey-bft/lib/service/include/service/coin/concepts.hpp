#pragma once

#include "core/coin/messages.hpp"
#include "core/common.hpp"
#include "service/concepts.hpp"
#include <cstddef>
#include <optional>
#include <span>

namespace Honey::BFT::Coin {

template <typename T>
concept Transceiver = requires(T& t, NodeId target, const Message& msg) {
    { t.unicast(target, msg) } -> Sender;
    { t.broadcast(msg) } -> Sender;
};

template <typename T>
concept CanSignShare = requires(T& service, std::span<const std::byte> message) {
    { service.async_sign_share(message) } -> SenderOf<SignatureShare>;
};

template <typename T>
concept CanVerifyShare = requires(
    T& service,
    const SignatureShare& share,
    std::span<const std::byte> message,
    int signer_id) {
    { service.async_verify_share(share, message, signer_id) } -> SenderOf<bool>;
};

template <typename T>
concept CanVerifySignature = requires(
    T& service,
    const Signature& combined_sig,
    std::span<const std::byte> message) {
    { service.async_verify_signature(combined_sig, message) } -> SenderOf<bool>;
};

template <typename T>
concept CanCombineSignatures = requires(
    T& service,
    std::span<const PartialSignature> partial_sigs) {
    { service.async_combine_signatures(partial_sigs) } -> SenderOf<std::optional<Signature>>;
};

template <typename T>
concept CanHashToBit = requires(T& service, const Signature& sig) {
    { service.hash_to_bit(sig) } -> std::same_as<uint8_t>;
};

template <typename T>
concept CryptoService = CanSignShare<T> && CanVerifyShare<T> && CanVerifySignature<T> && CanCombineSignatures<T> && CanHashToBit<T>;

} // namespace Honey::BFT::Coin
