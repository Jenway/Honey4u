#pragma once

#include "core/rbc/messages.hpp"
#include "crypto/threshold/tbls.hpp"
#include "protocol/coin/concepts.hpp"
#include <optional>
#include <stdexcept>
#include <stdexec/execution.hpp>
#include <vector>

namespace Honey::BFT::Crypto::Components {

using Byte = std::byte;
using BytesSpan = std::span<const Byte>;

template <typename Scheduler>
class TblsMixin {
private:
    std::optional<Honey::Crypto::Tbls::TblsPrivateKeyShare> private_key_share_;
    std::optional<Honey::Crypto::Tbls::TblsVerificationParameters> verification_params_;

public:
    using Hash = Honey::Crypto::MerkleTree::SHA256Hash;
    using SignatureShare = Honey::Crypto::Tbls::SignatureShare;
    using Signature = Honey::Crypto::Tbls::Signature;
    using PartialSignature = Honey::Crypto::Tbls::PartialSignature;

    explicit TblsMixin(Scheduler s)
        : scheduler_(s)
    {
    }

    void set_private_key_share(const Honey::Crypto::Tbls::TblsPrivateKeyShare& share)
    {
        private_key_share_ = share;
    }

    void set_verification_params(const Honey::Crypto::Tbls::TblsVerificationParameters& params)
    {
        verification_params_ = params;
    }

    static uint8_t hash_to_bit(const Signature& sig)
    {
        uint8_t acc = 0;
        auto bytes = std::span(reinterpret_cast<const std::byte*>(&sig), sizeof(Signature));
        for (auto b : bytes) {
            acc ^= std::to_integer<uint8_t>(b);
        }
        return acc & 1;
    }

    auto async_sign_share(BytesSpan message)
    {
        return stdexec::schedule(scheduler_)
            | stdexec::then([this,
                                msg_vec = std::vector<Byte>(message.begin(), message.end())]() mutable -> SignatureShare {
                  if (!private_key_share_) {
                      throw std::runtime_error("Private key share not initialized");
                  }
                  auto sig = Honey::Crypto::Tbls::sign_share(*private_key_share_, BytesSpan(msg_vec));
                  return sig.value;
              });
    }

    auto async_verify_share(
        const SignatureShare& share,
        BytesSpan message,
        int player_id)
    {

        return stdexec::schedule(scheduler_)
            | stdexec::then([this, share, player_id,
                                msg_vec = std::vector<Byte>(message.begin(), message.end())]() mutable {
                  if (!verification_params_) {
                      throw std::runtime_error("Verification parameters not initialized");
                  }
                  auto r = Honey::Crypto::Tbls::verify_share(
                      *verification_params_, share, BytesSpan(msg_vec), player_id);
                  return r.has_value();
              });
    }

    auto async_combine_signatures(std::span<const PartialSignature> shares)
    {
        return stdexec::schedule(scheduler_)
            | stdexec::then([this,
                                shares_vec = std::vector<PartialSignature>(shares.begin(), shares.end())]() mutable -> std::optional<Signature> {
                  if (!verification_params_) {
                      throw std::runtime_error("Verification parameters not initialized");
                  }
                  auto r = Honey::Crypto::Tbls::combine_partial_signatures(
                      *verification_params_, std::span(shares_vec));
                  return r ? std::optional(*r) : std::nullopt;
              });
    }

    auto async_verify_signature(const Signature& sig, BytesSpan message)
    {
        return stdexec::schedule(scheduler_)
            | stdexec::then([this, sig,
                                msg_vec = std::vector<Byte>(message.begin(), message.end())]() mutable {
                  if (!verification_params_) {
                      throw std::runtime_error("Verification parameters not initialized");
                  }
                  auto r = Honey::Crypto::Tbls::verify_signature(
                      *verification_params_, BytesSpan(msg_vec), sig);
                  return r.has_value();
              });
    }

protected:
    Scheduler scheduler_;
};

}
