#pragma once

#include "crypto/threshold/tpke.hpp"
#include "service/concepts.hpp"
#include <exec/task.hpp>
#include <optional>
#include <stdexec/execution.hpp>
#include <vector>

namespace Honey::BFT::Crypto {

using Byte = std::byte;
using Honey::Crypto::Tpke::Ciphertext;
using Honey::Crypto::Tpke::DecryptionShare;
using Honey::Crypto::Tpke::HybridCiphertext;
using Honey::Crypto::Tpke::PartialDecryption;
using Honey::Crypto::Tpke::TpkeKeySet;
using Honey::Crypto::Tpke::TpkePrivateKeyShare;
using Honey::Crypto::Tpke::TpkeVerificationParameters;

/**
 * @brief Asynchronous TPKE Service for HoneyBadger
 *
 * 纯密码学服务，不处理序列化。
 * 输入输出都是类型化的数据结构（Ciphertext, DecryptionShare 等）。
 *
 * 序列化由调用者（HoneyBadger Service 或网络层）负责。
 */
template <typename Scheduler>
class TPKEService {
public:
    /**
     * @brief Construct TPKE service
     * @param scheduler Execution scheduler for async operations
     * @param public_params Public verification parameters
     * @param private_share This node's private key share
     */
    TPKEService(Scheduler scheduler,
        const TpkeVerificationParameters& public_params,
        const TpkePrivateKeyShare& private_share)
        : scheduler_(scheduler)
        , public_params_(public_params)
        , private_share_(private_share)
        , ctx_()
    {
    }

    /**
     * @brief Encrypt plaintext with TPKE (async)
     * @param plaintext Data to encrypt
     * @return HybridCiphertext (NOT serialized)
     */
    auto async_encrypt(std::span<const Byte> plaintext) -> exec::task<HybridCiphertext>
    {
        // Schedule encryption on worker thread
        co_return co_await stdexec::schedule(scheduler_)
            | stdexec::then([this, pt = std::vector<Byte>(plaintext.begin(), plaintext.end())]() mutable {
                  return Honey::Crypto::Tpke::encrypt(
                      ctx_,
                      public_params_,
                      std::span<const Byte>(pt));
              });
    }

    /**
     * @brief Generate decryption share for ciphertext (async)
     * @param ciphertext Ciphertext to decrypt (NOT serialized)
     * @return DecryptionShare (P1 point, NOT serialized)
     */
    auto async_decrypt_share(const Ciphertext& ciphertext) -> exec::task<DecryptionShare>
    {
        co_return co_await stdexec::schedule(scheduler_)
            | stdexec::then([this, ct = ciphertext]() {
                  return Honey::Crypto::Tpke::detail::decrypt_share(
                      private_share_, ct);
              });
    }

    /**
     * @brief Combine decryption shares and decrypt (async)
     * @param ciphertext Ciphertext to decrypt
     * @param partial_decryptions List of decryption shares with player IDs
     * @return Decrypted plaintext, or nullopt if decryption fails
     */
    auto async_decrypt(
        const Ciphertext& ciphertext,
        std::span<const PartialDecryption> partial_decryptions)
        -> exec::task<std::optional<std::vector<Byte>>>
    {
        co_return co_await stdexec::schedule(scheduler_)
            | stdexec::then([this, ct = ciphertext,
                                shares = std::vector<PartialDecryption>(
                                    partial_decryptions.begin(),
                                    partial_decryptions.end())]() mutable
                                -> std::optional<std::vector<Byte>> {
                  // Construct HybridCiphertext (assume v_component is empty for now)
                  // In real implementation, need to get full HybridCiphertext
                  HybridCiphertext hct {
                      .key_ciphertext = ct,
                      .data_ciphertext = {} // TODO: Get from somewhere
                  };

                  auto result = Honey::Crypto::Tpke::decrypt(
                      ctx_, public_params_, hct, std::span(shares));

                  if (result.has_value()) {
                      return *result;
                  }
                  return std::nullopt;
              });
    }

    /**
     * @brief Get public parameters
     */
    [[nodiscard]] const TpkeVerificationParameters& public_params() const
    {
        return public_params_;
    }

private:
    Scheduler scheduler_;
    TpkeVerificationParameters public_params_;
    TpkePrivateKeyShare private_share_;
    Honey::Crypto::Tpke::Context ctx_;
};

} // namespace Honey::BFT::Crypto
