#include "crypto/threshold/tbls.hpp"
#include "crypto/threshold/tpke.hpp"
#include "service/crypto/crypto_service.hpp"
#include <algorithm>
#include <cstddef>
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <optional>
#include <span>
#include <stdexec/execution.hpp>
#include <string_view>
#include <vector>

namespace Honey::BFT::Crypto {

namespace {

    using Byte = std::byte;
    using BytesSpan = std::span<const Byte>;

    std::vector<Byte> to_bytes(std::string_view sv)
    {
        std::vector<Byte> out;
        out.reserve(sv.size());
        for (unsigned char c : sv) {
            out.push_back(static_cast<Byte>(c));
        }
        return out;
    }

    UnifiedCryptoService make_service(const TblsParams& params,
        const TblsShare& share)
    {
        const int players = 4;
        const int threshold = 3;

        auto tpke_keys = Honey::Crypto::Tpke::generate_keys(players, threshold).value();

        return UnifiedCryptoService(
            2,
            params,
            share,
            tpke_keys.public_params,
            tpke_keys.private_shares[0]);
    }

} // namespace

TEST_CASE("AsyncCryptoServiceTest.BuildsMerkleAndVerifiesProof")
{
    auto keyset = Honey::Crypto::Tbls::generate_keys(4, 3);
    REQUIRE(keyset.has_value());
    auto svc = make_service(keyset->public_params, keyset->private_shares[0]);

    const auto data = to_bytes("hello async crypto");
    const int k = 2;
    const int n = 4;

    auto tree_result = stdexec::sync_wait(svc.async_build_merkle_tree(k, n, BytesSpan { data }));
    REQUIRE(tree_result.has_value());
    auto& tree = std::get<0>(*tree_result);

    const auto& proof = tree.proofs[1];
    auto shard_span = tree.shards.shard(1);
    std::vector<Byte> leaf_vec(shard_span.begin(), shard_span.end());

    auto verify_result = stdexec::sync_wait(
        svc.async_verify_merkle(std::move(leaf_vec), proof.leaf_index, proof.siblings, tree.root));

    REQUIRE(verify_result.has_value());
    CHECK(std::get<0>(*verify_result));
}

TEST_CASE("AsyncCryptoServiceTest.SignsAndCombinesThresholdSignatures")
{
    const int players = 4;
    const int threshold = 3;
    const auto message = to_bytes("threshold-signing-test");

    auto keyset = Honey::Crypto::Tbls::generate_keys(players, threshold);
    REQUIRE(keyset.has_value());

    auto svc = make_service(keyset->public_params, keyset->private_shares[0]);
    svc.set_verification_params(keyset->public_params);

    std::vector<UnifiedCryptoService::PartialSignature> parts;
    parts.reserve(threshold);

    for (int i = 0; i < threshold; ++i) {
        svc.set_private_key_share(keyset->private_shares[i]);

        auto share_result = stdexec::sync_wait(svc.async_sign_share(BytesSpan { message }));
        REQUIRE(share_result.has_value());
        auto& share = std::get<0>(*share_result);

        parts.push_back({ keyset->private_shares[i].player_id, share });

        auto verify_share_result = stdexec::sync_wait(
            svc.async_verify_share(parts.back().value, BytesSpan { message }, parts.back().player_id));
        REQUIRE(verify_share_result.has_value());
        CHECK(std::get<0>(*verify_share_result));
    }

    auto combined_result = stdexec::sync_wait(svc.async_combine_signatures(parts));
    REQUIRE(combined_result.has_value());
    auto& combined = std::get<0>(*combined_result);
    REQUIRE(combined.has_value());

    auto verify_sig_result = stdexec::sync_wait(svc.async_verify_signature(*combined, BytesSpan { message }));
    REQUIRE(verify_sig_result.has_value());
    CHECK(std::get<0>(*verify_sig_result));
}

TEST_CASE("AsyncCryptoServiceTest.EncodesAndDecodesShards")
{
    auto keyset = Honey::Crypto::Tbls::generate_keys(4, 3);
    REQUIRE(keyset.has_value());
    auto svc = make_service(keyset->public_params, keyset->private_shares[0]);

    const auto data = to_bytes("erasure-code payload");
    const int k = 3;
    const int n = 5;

    auto tree_result = stdexec::sync_wait(svc.async_build_merkle_tree(k, n, BytesSpan { data }));
    REQUIRE(tree_result.has_value());
    auto& tree = std::get<0>(*tree_result);

    std::vector<std::pair<int, std::vector<Byte>>> shards;
    shards.reserve(k);
    for (int i = 0; i < k; ++i) {
        auto shard_span = tree.shards.shard(i);
        shards.emplace_back(i, std::vector<Byte>(shard_span.begin(), shard_span.end()));
    }

    auto decode_result = stdexec::sync_wait(svc.async_decode(k, n, std::span { shards }));
    REQUIRE(decode_result.has_value());
    auto& decoded_opt = std::get<0>(*decode_result);

    REQUIRE(decoded_opt.has_value());
    const auto& decoded = *decoded_opt;

    REQUIRE_EQ(decoded.size(), data.size());
    CHECK(std::equal(decoded.begin(), decoded.end(), data.begin()));
}
} // namespace Honey::BFT::Crypto
