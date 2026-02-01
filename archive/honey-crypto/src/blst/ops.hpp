#pragma once

#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"
#include "crypto/blst/Scalar.hpp"

namespace Honey::Crypto::bls::ops {

// P1 operations
void add(P1& acc, const P1& rhs);
void mult(P1& p, const Scalar& s);
void neg(P1& p);
void sign_with(P1& p, const Scalar& s);
void hash_to(P1& p, BytesSpan msg, BytesSpan dst, BytesSpan aug);

// P2 operations
void add(P2& acc, const P2& rhs);
void mult(P2& p, const Scalar& s);
void neg(P2& p);
void sign_with(P2& p, const Scalar& s);
void hash_to(P2& p, BytesSpan msg, BytesSpan dst, BytesSpan aug);

// Scalar operations
void add(Scalar& acc, const Scalar& rhs);
void sub(Scalar& acc, const Scalar& rhs);
void mult(Scalar& acc, const Scalar& rhs);
Scalar neg(const Scalar& val);
Scalar inverse(const Scalar& val);

// Helper to check equality (if not using operator==)
bool is_equal(const P1& a, const P1& b);
bool is_equal(const P2& a, const P2& b);

} // namespace Honey::Crypto::bls::ops
