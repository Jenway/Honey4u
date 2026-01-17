#pragma once

#include "crypto/blst/Scalar.hpp"
#include <array>
#include <compare>
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>

namespace Honey::Crypto::bls {

// 前向声明
class P1_Affine;
class P2;

// =================================================================================
// P2_Affine (G2 Affine Point)
// Size: 192 bytes (96 bytes * 2 coordinates)
// =================================================================================
class P2_Affine {
public:
    // 24 * 8 = 192 bytes
    std::array<uint64_t, 24> storage;

    P2_Affine() = default;

    /* ---------- factories ---------- */
    static std::expected<P2_Affine, std::error_code> from_bytes(BytesSpan in);
    static P2_Affine generator();

    /* ---------- observers ---------- */
    friend bool operator==(const P2_Affine& a, const P2_Affine& b);

    // 状态检查
    bool on_curve() const;
    bool in_group() const;
    bool is_inf() const;

    // 验证签名
    // 注意：这里 pk 是 P1_Affine，意味着我们在验证 "PK in G1, Sig in G2" 的组合
    std::error_code core_verify(
        const P1_Affine& pk,
        bool hash_or_encode,
        BytesSpan msg,
        BytesSpan dst,
        BytesSpan aug = {}) const;

    static P2_Affine from_P2(const P2& jac);

    // 序列化
    void serialize(std::span<uint8_t, 192> out) const;
    void compress(std::span<uint8_t, 96> out) const;
};

// =================================================================================
// P2 (G2 Jacobian Point)
// Size: 288 bytes (96 bytes * 3 coordinates)
// =================================================================================
class P2 {
public:
    // 36 * 8 = 288 bytes
    std::array<uint64_t, 36> storage;

    P2() = default;

    /* ---------- factories ---------- */
    static P2 generator();
    static P2 identity(); // 无穷远点/零点
    static std::expected<P2, std::error_code> from_bytes(BytesSpan in);
    static P2 from_affine(const P2_Affine& a);
    static P2 from_hash(BytesSpan msg, BytesSpan dst = {});

    /* ---------- mutators ---------- */

    P2& add(const P2& a);
    P2& add(const P2_Affine& a);
    P2& dbl(); // Double

    P2& mult(const Scalar& s);

    P2& neg();
    P2 operator-() const;

    /* ---------- observers ---------- */
    bool on_curve() const;
    bool in_group() const;
    bool is_inf() const;

    friend bool operator==(const P2& a, const P2& b);

    void serialize(std::span<uint8_t, 192> out) const;
    void compress(std::span<uint8_t, 96> out) const;

    /* ---------- hash / sign ---------- */

    P2& sign_with(const Scalar& s);

    P2& hash_to(
        BytesSpan msg,
        BytesSpan dst,
        BytesSpan aug = {});
};

} // namespace Honey::Crypto::bls