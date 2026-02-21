#pragma once
#include "crypto/threshold/blst/P1.hpp"
#include "crypto/threshold/blst/P2.hpp"
#include "crypto/threshold/blst/Scalar.hpp"
#include <vector>

namespace Honey::Crypto::Threshold {

using G1Point = bls::P1;
using G2Point = bls::P2;
using Scalar = bls::Scalar;

using SecretShare = Scalar;

struct SystemTopology {
    int n; // total_players
    int f; // fault_tolerance
    int k; // threshold (usually f + 1)

    [[nodiscard]] bool is_valid() const { return n >= (3 * f) + 1 && k == f + 1; }
};

template <typename MasterKeyT, typename ShareKeyT>
struct VerificationParameters {
    using MasterPublicKey = MasterKeyT;
    using SharePublicKey = ShareKeyT;

    int total_players;
    int threshold;

    MasterPublicKey master_public_key;
    std::vector<SharePublicKey> verification_vector;
};

struct PrivateKeyShare {
    int player_id {};
    SecretShare secret; // The secret scalar, which is the private key material.
};

template <typename MasterKeyT, typename ShareKeyT>
struct DistributedKeySet {
    VerificationParameters<MasterKeyT, ShareKeyT> public_params;
    std::vector<PrivateKeyShare> private_shares;
};

} // namespace Honey::Crypto::Threshold
