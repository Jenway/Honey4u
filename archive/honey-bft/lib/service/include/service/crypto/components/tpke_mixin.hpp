#pragma once

#include "crypto/threshold/tpke.hpp"
#include "service/concepts.hpp"
#include <exec/task.hpp>
#include <stdexec/execution.hpp>
#include <vector>

namespace Honey::BFT::Crypto::Components {

using Byte = std::byte;
using Honey::Crypto::Tpke::Ciphertext;
using Honey::Crypto::Tpke::DecryptionShare;
using Honey::Crypto::Tpke::HybridCiphertext;
using Honey::Crypto::Tpke::PartialDecryption;
using Honey::Crypto::Tpke::TpkePrivateKeyShare;
using Honey::Crypto::Tpke::TpkeVerificationParameters;

template <typename Scheduler>
class TpkeMixin {
public:
    using TpkeParams = TpkeVerificationParameters;
    using TpkeShare = TpkePrivateKeyShare;

    TpkeMixin(Scheduler scheduler, const TpkeParams& params, const TpkeShare& share)
        : scheduler_(scheduler)
        , tpke_params_(params)
        , tpke_share_(share)
        , ctx_()
    {
    }

    auto async_encrypt(std::span<const Byte> plaintext) -> exec::task<HybridCiphertext>
    {
        co_return co_await stdexec::schedule(scheduler_)
            | stdexec::then([this, pt = std::vector<Byte>(plaintext.begin(), plaintext.end())]() mutable {
                  return Honey::Crypto::Tpke::encrypt(ctx_, tpke_params_, std::span<const Byte>(pt));
              });
    }

    auto async_decrypt_share(const Ciphertext& ciphertext) -> exec::task<DecryptionShare>
    {
        co_return co_await stdexec::schedule(scheduler_)
            | stdexec::then([this, ct = ciphertext]() {
                  return Honey::Crypto::Tpke::detail::decrypt_share(tpke_share_, ct);
              });
    }

    auto async_decrypt(const Ciphertext& ciphertext, std::span<const PartialDecryption> shares)
        -> exec::task<std::optional<std::vector<Byte>>>
    {
        co_return co_await stdexec::schedule(scheduler_)
            | stdexec::then([this, ct = ciphertext,
                                shares_vec = std::vector<PartialDecryption>(shares.begin(), shares.end())]() mutable
                                -> std::optional<std::vector<Byte>> {
                  HybridCiphertext hct {
                      .key_ciphertext = ct,
                      .data_ciphertext = {}
                  };
                  auto result = Honey::Crypto::Tpke::decrypt(ctx_, tpke_params_, hct, std::span(shares_vec));
                  return result ? std::optional(*result) : std::nullopt;
              });
    }

protected:
    Scheduler scheduler_;
    TpkeParams tpke_params_;
    TpkeShare tpke_share_;
    Honey::Crypto::Tpke::Context ctx_;
};

}
