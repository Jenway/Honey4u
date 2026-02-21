#pragma once

#include "core/prbc/messages.hpp"
#include "protocol/rbc/concepts.hpp"
#include <optional>
#include <utility>
#include <vector>

namespace Honey::BFT::PRBC {

using Honey::BFT::NodeId;
using Honey::BFT::SenderOf;
using Honey::BFT::RBC::Byte;
using Honey::BFT::RBC::BytesSpan;

template <typename T>
concept Transceiver = requires(T& t, NodeId target, const PRBCMessage& msg) {
    { t.unicast(target, msg) } -> Sender;
    { t.broadcast(msg) } -> Sender;
};

template <typename T>
concept CanSignThreshold = requires(T& t, BytesSpan data) {
    { t.async_sign_share(data) } -> SenderOf<typename T::SignatureShare>;
};

template <typename T>
concept CanVerifyThresholdShare = requires(T& t, const typename T::SignatureShare& share, BytesSpan data, int signer_id) {
    { t.async_verify_share(share, data, signer_id) } -> SenderOf<bool>;
};

template <typename T>
concept CanCombineThresholdSignatures = requires(T& t, std::span<const typename T::PartialSignature> shares) {
    { t.async_combine_signatures(shares) } -> SenderOf<std::optional<typename T::Signature>>;
};

template <typename T>
concept CanVerifyThresholdSignature = requires(T& t, const typename T::Signature& signature, BytesSpan data) {
    { t.async_verify_signature(signature, data) } -> SenderOf<bool>;
};

template <typename T>
concept CryptoService = Honey::BFT::RBC::CryptoService<T> && CanSignThreshold<T> && CanVerifyThresholdShare<T> && CanCombineThresholdSignatures<T> && CanVerifyThresholdSignature<T>;

} // namespace Honey::BFT::PRBC
