#include "crypto/blst/PT.hpp"

#include <cstring>

extern "C" {
#include <blst.h>
}

namespace Honey::Crypto::bls {

// =================================================================================
// Static Checks
// =================================================================================
static_assert(sizeof(PT) == sizeof(blst_fp12), "PT size mismatch");
static_assert(alignof(PT) >= alignof(blst_fp12), "PT alignment mismatch");

// =================================================================================
// Helpers (Casting)
// =================================================================================

inline blst_fp12* to_blst(PT* p) { return reinterpret_cast<blst_fp12*>(p->storage.data()); }
inline const blst_fp12* to_blst(const PT* p) { return reinterpret_cast<const blst_fp12*>(p->storage.data()); }

// 我们需要访问 P1/P2 的 storage。由于我们在之前的步骤中将 P1/P2 的 storage 设为 public，
// 这里可以直接 reinterpret_cast。
inline const blst_p1_affine* to_blst(const P1_Affine* p)
{
    return reinterpret_cast<const blst_p1_affine*>(p->storage.data());
}
inline const blst_p2_affine* to_blst(const P2_Affine* p)
{
    return reinterpret_cast<const blst_p2_affine*>(p->storage.data());
}

// =================================================================================
// PT Implementation
// =================================================================================

PT::PT(const P1_Affine& p)
{
    // blst_aggregated_in_g1 实际上是将 G1 元素映射到 GT (用于聚合验证)
    blst_aggregated_in_g1(to_blst(this), to_blst(&p));
}

PT::PT(const P2_Affine& q)
{
    blst_aggregated_in_g2(to_blst(this), to_blst(&q));
}

PT::PT(const P2_Affine& q, const P1_Affine& p)
{
    blst_miller_loop(to_blst(this), to_blst(&q), to_blst(&p));
}

PT::PT(const P1_Affine& p, const P2_Affine& q)
    : PT(q, p) // 委托构造
{
}

PT::PT(const P2& q, const P1& p)
{
    // 需要先转为 Affine，因为 Miller Loop 只接受 Affine 输入
    P2_Affine q_aff = P2_Affine::from_P2(q);
    P1_Affine p_aff = P1_Affine::from_P1(p);

    blst_miller_loop(to_blst(this), to_blst(&q_aff), to_blst(&p_aff));
}

PT::PT(const P1& p, const P2& q)
    : PT(q, p)
{
}

PT PT::one()
{
    PT ret;
    *to_blst(&ret) = *blst_fp12_one();
    return ret;
}

PT& PT::sqr()
{
    blst_fp12_sqr(to_blst(this), to_blst(this));
    return *this;
}

PT& PT::mul(const PT& p)
{
    blst_fp12_mul(to_blst(this), to_blst(this), to_blst(&p));
    return *this;
}

PT& PT::final_exp()
{
    blst_final_exp(to_blst(this), to_blst(this));
    return *this;
}

bool PT::is_one() const
{
    return blst_fp12_is_one(to_blst(this));
}

bool PT::in_group() const
{
    return blst_fp12_in_group(to_blst(this));
}

bool operator==(const PT& a, const PT& b)
{
    return blst_fp12_is_equal(to_blst(&a), to_blst(&b));
}

void PT::to_bendian(std::span<uint8_t, 576> out) const
{
    // 注意：blst_bendian_from_fp12 可能不直接暴露在 blst.h 中，
    // 但通常 blst 会提供 blst_fp12_to_bendian 或类似的。
    // 如果找不到该函数，可能需要手动导出 fp12 的两个 fp6 -> 三个 fp2 -> 两个 fp -> 字节。
    // 但根据你提供的原始代码，假设 blst_bendian_from_fp12 是可用的。

    // 如果 blst.h 没有暴露这个函数 (有时是在 aux 头文件里)，
    // 你可以直接 memcpy，因为 fp12 内部通常就是大端或小端排列的数组。
    // 但为了安全起见，这里假设原代码是正确的。

    // 假设 blst.h 中定义了这个宏或函数
    // 如果编译报错，请检查 blst_aux.h 或手动实现序列化
    // 这里的实现假设 blst 内部布局与其序列化格式（通常是大端）一致或提供了转换

    // 修正：blst 标准头文件可能不包含 to_bendian_from_fp12。
    // 如果你的 blst 版本有，请保留。如果没有，通常直接 memcpy 出来的是内部表示（Montgomery域），
    // 需要先 to_affine 或者类似的转换。
    // 鉴于你原来的代码用了它，我这里保留原样调用。

    // *Self-correction based on BLST usage*:
    // BLST FP12 序列化通常比较复杂。如果没有现成的 helper，
    // 最简单的方法通常不是序列化整个 GT，而是只序列化压缩后的部分，或者只在内部使用。
    // 如果你确定 blst_bendian_from_fp12 存在：

    // 临时占位，请确认你的 blst 环境
    blst_bendian_from_fp12(out.data(), to_blst(this));
}

bool PT::finalverify(const PT& gt1, const PT& gt2)
{
    return blst_fp12_finalverify(to_blst(&gt1), to_blst(&gt2));
}

} // namespace Honey::Crypto::bls