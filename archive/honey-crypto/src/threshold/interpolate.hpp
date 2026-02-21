#pragma once

#include "blst/ops.hpp"
#include "crypto/threshold/blst/Scalar.hpp"
#include <span>
#include <vector>

namespace Honey::Crypto::Math {

using Scalar = Honey::Crypto::bls::Scalar;
using Honey::Crypto::bls::ops::add;
using Honey::Crypto::bls::ops::inverse;
using Honey::Crypto::bls::ops::mult;
using Honey::Crypto::bls::ops::neg;
using Honey::Crypto::bls::ops::sub;

template <typename T>
concept Interpolatable = requires(T a, T b, Scalar s) {
    { a.identity() } -> std::same_as<T>;
    // Check for ops::add, ops::mult availability via ADL or explicit ns
    // Since we used namespace ops, we can just check add(a, b)
    add(a, b);
    mult(a, s);
};

template <typename T>
concept ShareLike = requires(const T& a) {
    { a.player_id } -> std::convertible_to<int>;
    requires Interpolatable<decltype(a.value)>;
};

namespace detail {
    inline void batch_inverse(std::span<Scalar> vec)
    {
        if (vec.empty())
            return;

        const size_t n = vec.size();
        std::vector<Scalar> prefix_products;
        prefix_products.reserve(n);

        // 1. 计算前缀积
        // prefix_products[i] = vec[0] * ... * vec[i]
        Scalar acc = Scalar::from_uint64(1);
        for (const auto& val : vec) {
            mult(acc, val);
            prefix_products.push_back(acc);
        }

        // 2. 计算所有元素乘积的逆元 (这里是唯一的 1 次昂贵的 inverse 调用)
        Scalar all_inv = inverse(acc);

        // 3. 反向计算每个元素的逆元
        // vec[i]^-1 = (vec[0]*...*vec[i])^-1 * (vec[0]*...*vec[i-1])
        //           = global_inv * prefix[i-1]
        for (size_t i = n; i-- > 0;) {
            Scalar current_val = vec[i]; // 暂存当前值用于更新 inv

            if (i > 0) {
                // vec[i] 的逆元 = 当前的总逆元 * 前一个前缀积
                vec[i] = all_inv;
                mult(vec[i], prefix_products[i - 1]);
            } else {
                // 第一个元素 (i=0)，此时 all_inv 已经是 vec[0] 的逆元了
                vec[i] = all_inv;
            }

            // 从总逆元中剔除当前元素，为下一次迭代做准备
            // all_inv_new = all_inv_old * vec[i]
            mult(all_inv, current_val);
        }
    }
} // namespace detail

template <ShareLike ShareT>
auto interpolate_at_zero(std::span<const ShareT> shares)
    -> std::expected<std::decay_t<decltype(shares[0].value)>, std::error_code>
{
    using ValueT = std::decay_t<decltype(shares[0].value)>;

    const size_t k = shares.size();
    if (k == 0) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    // --- 1. 提取 x 坐标 ---
    std::vector<Scalar> xs;
    xs.reserve(k);
    // std::unordered_set<int> seen_ids;
    for (size_t i = 0; i < k; ++i) {
        for (size_t j = 0; j < i; ++j) {
            if (shares[i].player_id == shares[j].player_id)
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        }
        xs.push_back(Scalar::from_uint64(shares[i].player_id));
    }
    // --- 2. 预计算所有分母 ---
    // Lagrange basis: λ_i(0) = numerator_i / denominator_i
    // denominator_i = Π_{j≠i} (x_i - x_j)
    std::vector<Scalar> denominators;
    denominators.reserve(k);

    for (size_t i = 0; i < k; ++i) {
        Scalar denom = Scalar::from_uint64(1);
        for (size_t j = 0; j < k; ++j) {
            if (i == j)
                continue;

            // diff = x_i - x_j
            Scalar diff = xs[i];
            sub(diff, xs[j]);

            mult(denom, diff);
        }
        denominators.push_back(denom);
    }

    // --- 3. 批量求逆---
    // 现在 denominators[i] 变成了 1 / Π(x_i - x_j)
    detail::batch_inverse(denominators);

    // --- 4. 计算分子并聚合结果 ---
    auto result = ValueT::identity();

    for (size_t i = 0; i < k; ++i) {
        // 计算分子: numerator_i = Π_{j≠i} (0 - x_j) = Π_{j≠i} (-x_j)
        Scalar numerator = Scalar::from_uint64(1);
        for (size_t j = 0; j < k; ++j) {
            if (i == j)
                continue;

            Scalar neg_xj = neg(xs[j]);
            mult(numerator, neg_xj);
        }

        // 组合: lambda_i = numerator * (1/denominator)
        Scalar lambda = numerator;
        mult(lambda, denominators[i]); // 这里使用的是已经求逆后的分母

        // 累加: result += y_i * lambda_i
        ValueT term = shares[i].value;
        mult(term, lambda);
        add(result, term);
    }

    return result;
}

} // namespace Honey::Crypto::Math
