#pragma once

#include "crypto/blst/Scalar.hpp"
#include <span>
#include <unordered_set>
#include <vector>

namespace Honey::Crypto::Math {

using Scalar = Honey::Crypto::bls::Scalar;

template <typename T>
concept Interpolatable = requires(T a, T b, Scalar s) {
    { a.identity() } -> std::same_as<T>;
    { a.add(b) } -> std::same_as<T&>;
    { a.mult(s) } -> std::same_as<T&>;
};

template <typename T>
concept ShareLike = requires(const T& a) {
    { a.player_id } -> std::convertible_to<int>;
    requires Interpolatable<decltype(a.value)>;
};

/**
 * @brief Performs Lagrange interpolation to find the polynomial's value at x=0.
 *
 *
 * @tparam ShareT A type that satisfies the ShareLike concept.
 * @param shares A span of k shares to interpolate.
 * @return The interpolated value at x=0, or an error.
 */
template <ShareLike ShareT>
auto interpolate_at_zero(std::span<const ShareT> shares)
    -> std::expected<std::decay_t<decltype(shares[0].value)>, std::error_code>
{
    // The return type is now deduced from the share's value type.
    using ValueT = std::decay_t<decltype(shares[0].value)>;

    const size_t k = shares.size();
    if (k == 0) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    // --- 校验并提取插值点 x_i ---
    std::vector<Scalar> xs;
    xs.reserve(k);
    std::unordered_set<int> seen_ids;
    for (const auto& s : shares) {
        if (!seen_ids.insert(s.player_id).second) {
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        }
        xs.push_back(std::move(Scalar::from_uint64(s.player_id)));
    }

    // --- 聚合 ∑ λ_i(0) · y_i ---
    auto result = ValueT::identity();

    for (size_t i = 0; i < k; ++i) {
        // 计算拉格朗日基多项式 λ_i(0) = Π_{j≠i} (0 - x_j) / Π_{j≠i} (x_i - x_j)
        auto numerator = Scalar::from_uint64(1);
        auto denominator = Scalar::from_uint64(1);
        for (size_t j = 0; j < k; ++j) {
            if (i == j)
                continue;
            numerator *= -xs[j];
            denominator *= (xs[i] - xs[j]);
        }
        Scalar lambda = numerator * denominator.inverse();

        // 计算 λ_i(0) * y_i
        ValueT term = shares[i].value; // This is a copy
        term.mult(lambda);

        result.add(term);
    }

    return result;
}
} // namespace Honey::Crypto::Math
