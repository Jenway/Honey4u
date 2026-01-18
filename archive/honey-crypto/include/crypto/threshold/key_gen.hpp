#pragma once

#include "crypto/blst/Scalar.hpp"
#include <algorithm>
#include <ranges>
#include <span>
#include <vector>

namespace Honey::Crypto::Threshold {

using Scalar = Honey::Crypto::bls::Scalar;

template <typename T>
concept IsGroupElement = requires(T a, Scalar s) {
    { T::generator() } -> std::same_as<T>;
    { a.mult(s) } -> std::same_as<T&>;
};

// 秘密份额（标量）
using SecretShare = Scalar;

/**
 * @struct VerificationParameters
 * @brief Holds all public information required to verify the threshold scheme.
 */
template <IsGroupElement MasterKeyT, IsGroupElement ShareKeyT>
struct VerificationParameters {
    using MasterPublicKey = MasterKeyT;
    using SharePublicKey = ShareKeyT;

    int total_players;
    int threshold;

    MasterPublicKey master_public_key;
    std::vector<SharePublicKey> verification_vector;
};

/**
 * @struct PrivateKeyShare
 * @brief A container for a single player's private key share and their ID.
 *        This is highly sensitive and constitutes the player's private key.
 */
struct PrivateKeyShare {
    int player_id;
    SecretShare secret; // The secret scalar, which is the private key material.
};

/**
 * @struct DistributedKeySet
 * @brief The complete output of the key generation dealer, containing both the
 *        public verification parameters and the set of all private key shares.
 */
template <IsGroupElement MasterKeyT, IsGroupElement ShareKeyT>
struct DistributedKeySet {
    VerificationParameters<MasterKeyT, ShareKeyT> public_params;
    std::vector<PrivateKeyShare> private_shares;
};

inline std::vector<Scalar> random_poly(int degree)
{
    std::vector<Scalar> coeffs(degree);
    std::ranges::generate(coeffs, [] { return *Scalar::random(); });
    return coeffs;
}

inline Scalar polynom_eval(Scalar x, std::span<const Scalar> coeffs)
{
    if (coeffs.empty())
        return Scalar::from_uint64(0);
    Scalar res = coeffs.back();
    for (auto it = coeffs.rbegin() + 1; it != coeffs.rend(); ++it)
        res = res * x + (*it);
    return res;
}

template <IsGroupElement MasterKeyT, IsGroupElement ShareKeyT>
auto generate_keys(int players, int k)
    -> std::expected<DistributedKeySet<MasterKeyT, ShareKeyT>, std::error_code>
{
    if (k < 1 || k > players || players < 1)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));

    // A (k, n) scheme requires a polynomial of degree k-1, which has k coefficients.
    auto secret_polynomial = random_poly(k);

    // The master secret key is the constant term (a_0) of the polynomial.
    const auto& master_secret = secret_polynomial[0];

    // Calculate the master public key: G * master_secret
    auto master_public_key = MasterKeyT::generator().mult(master_secret);

    std::vector<PrivateKeyShare> private_shares;
    std::vector<ShareKeyT> verification_vector;
    private_shares.reserve(players);
    verification_vector.reserve(players);

    for (int player_id : std::views::iota(1, players + 1)) {
        // Evaluate the polynomial at the player's ID to get their secret share.
        SecretShare player_secret_share = polynom_eval(Scalar::from_uint64(player_id), secret_polynomial);

        private_shares.push_back({
            .player_id = player_id,
            .secret = player_secret_share,
        });

        // Calculate the corresponding public verification key for this share: H * share
        auto share_public_key = ShareKeyT::generator();
        share_public_key.mult(player_secret_share);
        verification_vector.push_back(share_public_key);
    }

    return DistributedKeySet<MasterKeyT, ShareKeyT> {
        .public_params = {
            .total_players = players,
            .threshold = k,
            .master_public_key = master_public_key,
            .verification_vector = std::move(verification_vector),
        },
        .private_shares = std::move(private_shares),
    };
}

} // namespace Honey::Crypto::Threshold