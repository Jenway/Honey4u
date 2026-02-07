# Honey::Crypto

The cryptographic foundation for HoneyBadger BFT, providing robust and type-safe primitives for threshold cryptography, erasure coding, and basic crypto operations.

## Architecture

This library is designed as a **pure logic layer**. It handles cryptographic transformations but avoids:
- I/O operations (file/network)
- Concurrency management (threading/schedulers)
- Wire format serialization (except where strictly defined by crypto standards). Service layer is responsible for JSON serialization.

### Components

1.  **Threshold Cryptography** (`crypto/threshold/`)
    *   **TPKE (Threshold Public Key Encryption)**: Allows encryption to a master public key, where decryption requires cooperation of `f+1` nodes. Implemented using **Pimpl pattern** (`Tpke::Context`) to hide OpenSSL/AES implementation details.
    *   **TBLS (Threshold BLS Signatures)**: Distributed signing and aggregation using BLS12-381 curves.

2.  **BLS12-381 Primitives** (`crypto/blst/`)
    *   Type-safe C++ wrappers around [BLST](https://github.com/supranational/blst).
    *   `Scalar`, `P1` (G1 group), `P2` (G2 group), `GT`.
    *   Strong typing prevents mixing group elements.

3.  **Core Primitives**
    *   **Merkle Tree**: For efficient data verification.
    *   **Erasure Coding**: Reed-Solomon coding via Intel ISA-L.
    *   **ECDSA**: Secp256k1 signing for standard transactions.
    *   **AES-GCM**: Symmetric encryption (internal use by TPKE).

## Usage

### Error Handling
We use `std::expected<T, std::error_code>` for all fallible operations.
```cpp
#include <crypto/error.hpp>

auto result = decrypt(ctx, ciphertext, shares);
if (!result) {
    // Handle specific errors
    if (result.error() == Honey::Crypto::Error::NotEnoughShares) { ... }
}
```

### Opaque Contexts
Complex state (like AES contexts) is managed via opaque handles to maintain ABI stability and reduce compile-time dependencies.
```cpp
// tpke.hpp does NOT include <openssl/evp.h>
Tpke::Context ctx(epoch, threshold);
```

## Dependencies
*   **OpenSSL**: For AES, SHA256.
*   **BLST**: For BLS12-381 math.
*   **Intel ISA-L**: For erasure coding.
*   **libsecp256k1**: For ECDSA.

## Build Integration
The library exports `Honey::Crypto` target. Internal headers (`src/`) are hidden from consumers.
Generated ABI headers (via `blst_abi_probe`) ensure correct memory layout for BLST types.
