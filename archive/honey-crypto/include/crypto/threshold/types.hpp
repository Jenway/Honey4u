#pragma once

#include "crypto/blst/Scalar.hpp"
#include <vector>

namespace Honey::Crypto::Threshold {

using Scalar = Honey::Crypto::bls::Scalar;
using SecretShare = Scalar;

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
