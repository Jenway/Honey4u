#include "crypto/threshold/tbls.hpp"
#include "service/crypto/async_crypto_service.hpp"
#include <algorithm>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <stdexec/execution.hpp>
#include <string_view>
#include <vector>

namespace Honey::BFT::Crypto {

namespace {

    std::vector<Byte> to_bytes(std::string_view sv)
    {
        std::vector<Byte> out;
        out.reserve(sv.size());
        for (unsigned char c : sv) {
            out.push_back(static_cast<Byte>(c));
        }
        return out;
    }

} // namespace

TEST(AsyncCryptoServiceTest, BuildsMerkleAndVerifiesProof)
{
    AsyncCryptoService svc(2);

    const auto data = to_bytes("hello async crypto");
    const int k = 2;
    const int n = 4;

    auto tree_result = stdexec::sync_wait(svc.async_build_merkle_tree(k, n, BytesSpan { data }));
    ASSERT_TRUE(tree_result.has_value());
    auto& tree = std::get<0>(*tree_result);

    auto payload = svc.extract_val_payload(tree, 1);

    auto verify_result = stdexec::sync_wait(
        svc.async_verify_merkle(BytesSpan { payload.stripe }, payload.proof_index, std::span { payload.merkle_path }, payload.root_hash));

    ASSERT_TRUE(verify_result.has_value());
    EXPECT_TRUE(std::get<0>(*verify_result));
}

TEST(AsyncCryptoServiceTest, SignsAndCombinesThresholdSignatures)
{
    AsyncCryptoService svc(2);
    const int players = 4;

    const int threshold = 3;
    const auto message = to_bytes("threshold-signing-test");

    auto keyset = Honey::Crypto::Tbls::generate_keys(players, threshold);
    ASSERT_TRUE(keyset.has_value());

    svc.set_verification_params(keyset->public_params);

    std::vector<AsyncCryptoService::PartialSignature> parts;
    parts.reserve(threshold);

    for (int i = 0; i < threshold; ++i) {
        svc.set_private_key_share(keyset->private_shares[i]);

        auto share_result = stdexec::sync_wait(svc.async_sign_share(BytesSpan { message }));
        ASSERT_TRUE(share_result.has_value());
        auto& share = std::get<0>(*share_result);

        parts.push_back({ keyset->private_shares[i].player_id, share });

        auto verify_share_result = stdexec::sync_wait(
            svc.async_verify_share(parts.back().value, BytesSpan { message }, parts.back().player_id));
        ASSERT_TRUE(verify_share_result.has_value());
        EXPECT_TRUE(std::get<0>(*verify_share_result));
    }

    auto combined_result = stdexec::sync_wait(svc.async_combine_signatures(parts));
    ASSERT_TRUE(combined_result.has_value());
    auto& combined = std::get<0>(*combined_result);
    ASSERT_TRUE(combined.has_value());

    auto verify_sig_result = stdexec::sync_wait(svc.async_verify_signature(*combined, BytesSpan { message }));
    ASSERT_TRUE(verify_sig_result.has_value());
    EXPECT_TRUE(std::get<0>(*verify_sig_result));
}

TEST(AsyncCryptoServiceTest, EncodesAndDecodesShards)
{
    AsyncCryptoService svc(2);

    const auto data = to_bytes("erasure-code payload");
    const int k = 3;
    const int n = 5;

    auto tree_result = stdexec::sync_wait(svc.async_build_merkle_tree(k, n, BytesSpan { data }));
    ASSERT_TRUE(tree_result.has_value());
    auto& tree = std::get<0>(*tree_result);

    std::vector<std::pair<int, std::vector<Byte>>> shards;
    shards.reserve(k);
    for (int i = 0; i < k; ++i) {
        shards.emplace_back(i, std::vector<Byte>(tree.leaf(i).begin(), tree.leaf(i).end()));
    }

    auto decode_result = stdexec::sync_wait(svc.async_decode(k, n, std::span { shards }));
    ASSERT_TRUE(decode_result.has_value());
    auto& decoded_opt = std::get<0>(*decode_result);

    ASSERT_TRUE(decoded_opt.has_value());
    const auto& decoded = *decoded_opt;

    ASSERT_EQ(decoded.size(), data.size());
    EXPECT_TRUE(std::equal(decoded.begin(), decoded.end(), data.begin()));
}
} // namespace Honey::BFT::Crypto
