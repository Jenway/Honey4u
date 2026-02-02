#include "crypto/merkle_tree.hpp"
#include <gtest/gtest.h>

namespace Honey::Crypto::MerkleTree {

namespace {

    std::vector<Byte> to_bytes(std::string_view s)
    {
        std::vector<Byte> res;
        res.reserve(s.size());
        for (char c : s)
            res.push_back(static_cast<Byte>(c));
        return res;
    }

    auto create_leaves(const std::vector<std::string>& strings)
    {
        std::vector<std::vector<Byte>> leaves;
        leaves.reserve(strings.size());
        for (const auto& s : strings) {
            leaves.push_back(to_bytes(s));
        }
        return leaves;
    }

    std::vector<std::vector<Byte>> to_leaves(const std::vector<std::string>& strings)
    {
        return create_leaves(strings);
    }

    TreeData build_tree(const std::vector<std::string>& strings)
    {
        auto leaves = to_leaves(strings);
        return build_and_prove(leaves);
    }

    bool verify_leaf(const std::vector<Byte>& leaf,
        const Proof& proof,
        const Hash& root)
    {
        return verify(BytesSpan { leaf }, proof, root);
    }
}

class MerkleTreeTest : public ::testing::Test {
protected:
};

TEST_F(MerkleTreeTest, BuildEmpty)
{
    auto tree = build_and_prove({});
    EXPECT_EQ(tree.proofs.size(), 0);
    EXPECT_EQ(tree.root, Hash {});
}

TEST_F(MerkleTreeTest, SingleNode)
{
    auto leaves = create_leaves({ "data_1" });
    const auto& leaf_data = leaves[0];

    auto tree = build_and_prove(leaves);

    ASSERT_EQ(tree.proofs.size(), 1);
    const auto& proof = tree.proofs[0];

    EXPECT_EQ(proof.siblings.size(), 0);
    EXPECT_TRUE(verify_leaf(leaf_data, proof, tree.root));
}

TEST_F(MerkleTreeTest, PowerOfTwo)
{
    auto leaves = create_leaves({ "d1", "d2", "d3", "d4" });
    auto tree = build_and_prove(leaves);

    ASSERT_EQ(tree.proofs.size(), leaves.size());

    for (size_t i = 0; i < leaves.size(); ++i) {
        EXPECT_TRUE(verify_leaf(leaves[i], tree.proofs[i], tree.root))
            << "Verification failed for index " << i;
    }
}

TEST_F(MerkleTreeTest, OddNumberOfLeaves)
{
    auto leaves = create_leaves({ "d1", "d2", "d3" });
    auto tree = build_and_prove(leaves);

    ASSERT_EQ(tree.proofs.size(), leaves.size());

    for (size_t i = 0; i < leaves.size(); ++i) {
        EXPECT_TRUE(verify_leaf(leaves[i], tree.proofs[i], tree.root));
    }
}

TEST_F(MerkleTreeTest, DetectsTampering)
{
    auto leaves = create_leaves({ "d1", "d2", "d3", "d4" });
    auto tree = build_and_prove(leaves);

    const auto& proof_for_leaf_1 = tree.proofs[1];
    const auto& original_leaf_1 = leaves[1];

    auto fake_data = to_bytes("malicious_data");
    EXPECT_FALSE(verify_leaf(fake_data, proof_for_leaf_1, tree.root))
        << "Should fail when data is changed";

    Hash fake_root = tree.root;
    fake_root[0] ^= std::byte(0xFF);
    EXPECT_FALSE(verify_leaf(original_leaf_1, proof_for_leaf_1, fake_root))
        << "Should fail when root is changed";
}

TEST_F(MerkleTreeTest, DetectsProofTampering)
{
    auto leaves = create_leaves({ "d1", "d2", "d3", "d4" });
    auto tree = build_and_prove(leaves);

    auto proof = tree.proofs[0];
    ASSERT_FALSE(proof.siblings.empty());

    proof.siblings[0][0] ^= std::byte(0xFF);

    EXPECT_FALSE(verify_leaf(leaves[0], proof, tree.root));
}

TEST_F(MerkleTreeTest, LargeTree)
{
    const size_t N = 100;
    std::vector<std::string> many_strings;
    many_strings.reserve(N);
    for (size_t i = 0; i < N; ++i) {
        many_strings.push_back("leaf_" + std::to_string(i));
    }
    auto many_leaves = create_leaves(many_strings);

    auto tree = build_and_prove(many_leaves);
    ASSERT_EQ(tree.proofs.size(), many_leaves.size());

    std::vector<size_t> indices_to_check = { 0, 1, 33, 50, 99 };
    for (size_t idx : indices_to_check) {
        EXPECT_TRUE(verify_leaf(many_leaves[idx], tree.proofs[idx], tree.root));
    }
}

} // namespace Honey::Crypto::MerkleTree
