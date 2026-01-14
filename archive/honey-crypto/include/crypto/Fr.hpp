#pragma once

#include <algorithm> 
#include <blst.hpp>
#include <cstring>
#include <openssl/rand.h>
#include <span> 
#include <stdexcept>
#include <vector>

// ==========================================
// Fr (标量场)
// ==========================================
class Fr {
public:
    blst::Scalar val;

    Fr()
        : val()
    {
    }

    Fr(const blst::Scalar& s)
        : val(s)
    {
    }

    // 整数构造：手动处理端序
    explicit Fr(uint64_t i)
    {
        // 直接构造 uint64 数组可能比逐字节移位更快，但在 Little Endian 机器上才有效。
        // 为了跨平台安全，保留你的位移逻辑，但稍微优化写法。
        uint64_t le_val = htole64_compat(i);
        // 注意：blst::Scalar 通常提供从 uint64[4] 构造的方法，这比序列化 bytes 更快
        // 这里为了兼容你的逻辑保持 from_lendian
        blst::byte buf[32] = { 0 };
        std::memcpy(buf, &le_val, sizeof(uint64_t));
        val.from_lendian(buf, 32);
    }

    // CSPRNG 随机数
    // DST: Domain Separation Tag，允许为不同的用途使用不同的随机源哈希
    static Fr random(const char* dst = "HBFT_DEFAULT_SALT")
    {
        blst::byte ikm[32];
        if (RAND_bytes(ikm, 32) != 1) {
            throw std::runtime_error("OpenSSL RAND_bytes failed");
        }
        blst::Scalar s;
        s.hash_to(ikm, 32, dst);
        return Fr(s);
    }


    Fr& operator+=(const Fr& other)
    {
        val.add(other.val); 
        return *this;
    }

    Fr& operator-=(const Fr& other)
    {
        val.sub(other.val);
        return *this;
    }

    Fr& operator*=(const Fr& other)
    {
        val.mul(other.val);
        return *this;
    }

    [[nodiscard]] friend Fr operator+(Fr lhs, const Fr& rhs)
    {
        lhs += rhs;
        return lhs;
    }

    [[nodiscard]] friend Fr operator-(Fr lhs, const Fr& rhs)
    {
        lhs -= rhs;
        return lhs;
    }

    [[nodiscard]] friend Fr operator*(Fr lhs, const Fr& rhs)
    {
        lhs *= rhs;
        return lhs;
    }

    // 一元取反 (-x)
    [[nodiscard]] Fr operator-() const
    {
        return Fr(0) - *this;
        // 或者如果 blst 有 neg() 接口: Fr res(*this); res.val.neg(); return res;
    }

    // ==================================================
    // 比较运算符 (优化性能)
    // ==================================================

    bool operator==(const Fr& other) const
    {
        // 直接比较内存，比序列化快得多
        // blst::Scalar 内部通常是 4 个 uint64_t
        return std::memcmp(&val, &other.val, sizeof(val)) == 0;
    }

    bool operator!=(const Fr& other) const
    {
        return !(*this == other);
    }

    // ==================================================
    // 数学工具
    // ==================================================

    [[nodiscard]] Fr inverse() const
    {
        blst::Scalar res = val.dup();
        res.inverse();
        return Fr(res);
    }

private:
    // 简单的 host-to-little-endian 辅助
    static uint64_t htole64_compat(uint64_t host)
    {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
        return host;
#else
        // 如果是大端序机器，需要 byteswap
        return __builtin_bswap64(host);
#endif
    }
};

namespace TBLSMath {

// 使用 inline 防止多重定义
// 优化：使用 Horner's Rule (霍纳法则) 减少乘法次数
// poly = a0 + a1*x + ... + an*x^n
//      = a0 + x(a1 + x(a2 + ...))
[[nodiscard]]
inline Fr polynom_eval(const Fr& x, std::span<const Fr> coeffs)
{
    if (coeffs.empty())
        return Fr(0);

    // 从高次项开始计算
    // result = coeffs[n]
    // result = result * x + coeffs[n-1]
    // ...
    Fr res = coeffs.back();
    for (auto it = coeffs.rbegin() + 1; it != coeffs.rend(); ++it) {
        res = res * x + (*it);
    }
    return res;
}

[[nodiscard]]
inline Fr lagrange_coeff(std::span<const int> ids, int j)
{
    Fr num = Fr(1);
    Fr den = Fr(1);
    Fr fr_j(j);

    bool found_j = false;

    for (int id : ids) {
        if (id == j) {
            found_j = true;
            continue;
        }

        Fr fr_id(id);
        // num *= (0 - id)  =>  num *= -id
        num *= -fr_id;
        // den *= (j - id)
        den *= (fr_j - fr_id);
    }

    if (!found_j) {
        // 实际上在 combine_shares 中通常不需要这个检查，因为我们遍历的就是 ids
        // 但保留以防误用
        throw std::runtime_error("Lagrange: ID j not found in list");
    }

    return num * den.inverse();
}

} // namespace TBLSMath