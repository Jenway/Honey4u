#pragma once

#include "crypto/blst/Scalar.hpp"
#include "crypto/common.hpp"
#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>

namespace Honey::Crypto::bls {

class P2_Affine;
class P1;

// =================================================================================
// P1_Affine (G1 Affine Point)
// Size: 96 bytes (384 bits * 2 coordinates)
// =================================================================================
class P1_Affine {
public:
    // 12 * 8 = 96 bytes
    std::array<uint64_t, 12> storage;

    P1_Affine() = default;

    /* ---------- factories ---------- */
    static std::expected<P1_Affine, std::error_code> from_bytes(BytesSpan in);
    static P1_Affine generator();

    /* ---------- observers ---------- */
    // 检查是否相等
    friend bool operator==(const P1_Affine& a, const P1_Affine& b);

    // 验证签名
    // 注意：这里只使用前向声明的 P2_Affine，不需要包含 P2.hpp
    std::error_code core_verify(
        const P2_Affine& pk,
        bool hash_or_encode,
        BytesSpan msg,
        BytesSpan dst,
        BytesSpan aug = {}) const;

    // 转换
    static P1_Affine from_P1(const P1& jac);

    // 序列化
    void serialize(std::span<uint8_t, 96> out) const;
    void compress(std::span<uint8_t, 48> out) const;
};

// =================================================================================
// P1 (G1 Jacobian Point)
// Size: 144 bytes (384 bits * 3 coordinates)
// =================================================================================
class P1 {
public:
    // 18 * 8 = 144 bytes
    std::array<uint64_t, 18> storage;

    P1() = default;

    /* ---------- factories ---------- */
    static P1 generator();
    static P1 identity(); // 无穷远点/零点
    static std::expected<P1, std::error_code> from_bytes(BytesSpan in);
    static P1 from_affine(const P1_Affine& a);
    static P1 from_hash(BytesSpan msg, BytesSpan dst = {});

    /* ---------- operators & mutators ---------- */

    // 加法 (in-place)
    P1& add(const P1& a);
    P1& add(const P1_Affine& a);
    P1& dbl(); // Double

    // 标量乘法 (Scalar mul)
    P1& mult(const Scalar& s);

    // 取反
    P1& neg(); // in-place
    P1 operator-() const; // return new

    // 运算符重载
    friend bool operator==(const P1& a, const P1& b);

    // hash / sign
    // 注意：sign_with 通常需要 Scalar 私钥
    P1& sign_with(const Scalar& s);

    P1& hash_to(
        BytesSpan msg,
        BytesSpan dst,
        BytesSpan aug = {});

    // serilize
    [[nodiscard]] std::array<Byte, 48> compress() const;
};

} // namespace Honey::Crypto::bls