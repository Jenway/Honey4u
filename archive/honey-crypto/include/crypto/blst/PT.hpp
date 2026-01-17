#pragma once

#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"

#include <array>
#include <compare>
#include <cstdint>
#include <span>

namespace Honey::Crypto::bls {

// =================================================================================
// PT (Fp12 Point / Target Group)
// Size: 576 bytes (48 bytes * 12 coefficients)
// =================================================================================
class PT {
public:
    // 72 * 8 = 576 bytes
    std::array<uint64_t, 72> storage;

    PT() = default;

    // --- Constructors (Mapping / Pairing) ---

    // 从 G1/G2 Affine 映射到 GT (通常用于聚合签名的验签部分)
    explicit PT(const P1_Affine& p);
    explicit PT(const P2_Affine& q);

    // Miller Loop (配对运算的核心)
    PT(const P2_Affine& q, const P1_Affine& p);
    PT(const P1_Affine& p, const P2_Affine& q); // 为了方便，允许参数反转

    // 接受 Jacobian 点，内部会自动转 Affine
    PT(const P2& q, const P1& p);
    PT(const P1& p, const P2& q);

    // --- Factories ---
    static PT one();

    // --- Operations ---

    PT dup() const { return *this; }

    // 算术运算
    PT& sqr();
    PT& mul(const PT& p);
    PT& final_exp();

    // --- Observers ---

    bool is_one() const;
    // 检查是否在群中
    bool in_group() const;

    friend bool operator==(const PT& a, const PT& b);

    // 序列化 (大端序输出 576 字节)
    void to_bendian(std::span<uint8_t, 576> out) const;

    // --- Static Verification ---

    // 验证 GT 上的等式 e(P1, Q1) * e(P2, Q2)... == 1 ?
    static bool finalverify(const PT& gt1, const PT& gt2);
};

} // namespace Honey::Crypto::bls