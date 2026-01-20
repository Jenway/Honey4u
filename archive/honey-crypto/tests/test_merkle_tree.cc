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
}

class MerkleTreeTest : public ::testing::Test {
protected:
};

TEST_F(MerkleTreeTest, BuildEmpty)
{
    Tree tree = Tree::build({}); // Pass an empty rvalue vector
    EXPECT_TRUE(tree.empty());
    EXPECT_EQ(tree.size(), 0);
    // A valid but empty tree should have a predictable "empty" root hash
    // or we can decide it should be an error state. Here we assume it's valid.
    // The specific value of the root for an empty tree depends on the desired semantics.
    // Let's assume an empty tree's root() returns a zeroed hash for predictability.
    EXPECT_EQ(tree.root(), Hash {});
}

TEST_F(MerkleTreeTest, SingleNode)
{
    auto leaves = create_leaves({ "data_1" });
    const auto& leaf_data = leaves[0];

    Tree tree = Tree::build(std::move(leaves));

    ASSERT_FALSE(tree.empty());
    EXPECT_EQ(tree.size(), 1);

    // Verify: prove for index 0
    auto proof_res = tree.prove(0);
    ASSERT_TRUE(proof_res.has_value());
    const auto& proof = *proof_res;

    // A single node's proof should have 0 siblings up to the padded root
    // For a tree padded to 1 leaf, the height is 0, so 0 siblings.
    EXPECT_EQ(proof.siblings.size(), 0);

    // Verification logic should pass using the static verify function
    EXPECT_TRUE(verify(leaf_data, proof, tree.root()));
}

TEST_F(MerkleTreeTest, PowerOfTwo)
{
    auto leaves = create_leaves({ "d1", "d2", "d3", "d4" });
    Tree tree = Tree::build(std::move(leaves));

    EXPECT_EQ(tree.size(), 4);

    // Verify each leaf against the single root
    for (size_t i = 0; i < tree.size(); ++i) {
        auto proof = tree.prove(i).value();
        // Use tree.leaf(i) to get the original data back for verification
        EXPECT_TRUE(verify(tree.leaf(i), proof, tree.root()))
            << "Verification failed for index " << i;
    }
}

TEST_F(MerkleTreeTest, OddNumberOfLeaves)
{
    auto leaves = create_leaves({ "d1", "d2", "d3" });
    Tree tree = Tree::build(std::move(leaves));

    EXPECT_EQ(tree.size(), 3); // Logical size is 3

    // Verify the existing leaves
    for (size_t i = 0; i < tree.size(); ++i) {
        auto proof = tree.prove(i).value();
        EXPECT_TRUE(verify(tree.leaf(i), proof, tree.root()));
    }

    // Attempting to get a proof for an out-of-bounds index should fail
    auto proof_out_of_bound = tree.prove(3);
    EXPECT_FALSE(proof_out_of_bound.has_value());
}

TEST_F(MerkleTreeTest, DetectsTampering)
{
    auto leaves = create_leaves({ "d1", "d2", "d3", "d4" });
    Tree tree = Tree::build(std::move(leaves));

    auto proof_for_leaf_1 = tree.prove(1).value();
    const auto& original_leaf_1 = tree.leaf(1);

    // Scenario A: Verify with incorrect data
    auto fake_data = to_bytes("malicious_data");
    EXPECT_FALSE(verify(fake_data, proof_for_leaf_1, tree.root()))
        << "Should fail when data is changed";

    // Scenario B: Verify with incorrect root
    Hash fake_root = tree.root();
    fake_root[0] ^= std::byte(0xFF); // Flip a bit
    EXPECT_FALSE(verify(original_leaf_1, proof_for_leaf_1, fake_root))
        << "Should fail when root is changed";
}

// Test 6: Detect proof tampering
TEST_F(MerkleTreeTest, DetectsProofTampering)
{
    auto leaves = create_leaves({ "d1", "d2", "d3", "d4" });
    Tree tree = Tree::build(std::move(leaves));

    auto proof = tree.prove(0).value();
    ASSERT_FALSE(proof.siblings.empty());

    // Tamper with one of the sibling hashes in the proof
    proof.siblings[0][0] ^= std::byte(0xFF);

    EXPECT_FALSE(verify(tree.leaf(0), proof, tree.root()));
}

// TEST_F(MerkleTreeTest, DomainSeparationPreventsCollision)
// {
//     // This test ensures that hash_leaf(A || B) != hash_internal(A, B)
//     // We can't directly call detail functions, so we test through the public API.

//     auto h1 = Utils::sha256(to_bytes("hash1"));
//     auto h2 = Utils::sha256(to_bytes("hash2"));

//     // Construct a leaf whose data is the concatenation of two hashes
//     std::vector<Byte> malicious_leaf_data;
//     malicious_leaf_data.insert(malicious_leaf_data.end(), h1.begin(), h1.end());
//     malicious_leaf_data.insert(malicious_leaf_data.end(), h2.begin(), h2.end());

//     // Build a simple tree where the root is hash_internal(h1, h2)
//     auto leaves = create_leaves({ "leaf1", "leaf2" });
//     // Manually get the leaf hashes to find the internal hash
//     impl::EvpMdCtxPtr ctx(EVP_MD_CTX_new());
//     auto leaf1_h = hash_leaf(ctx.get(), leaves[0]).value();
//     auto leaf2_h = hash_leaf(ctx.get(), leaves[1]).value();
//     auto internal_h = hash_internal(ctx.get(), leaf1_h, leaf2_h).value();

//     // Calculate the hash of the malicious leaf
//     auto malicious_leaf_h = hash_leaf(ctx.get(), malicious_leaf_data).value();

//     // The core assertion: The hash of the concatenated data (a leaf operation)
//     // must not be equal to the hash of the two separate hashes (an internal operation).
//     EXPECT_NE(malicious_leaf_h, internal_h) << "Domain separation is broken!";
// }

TEST_F(MerkleTreeTest, LargeTree)
{
    const size_t N = 100;
    std::vector<std::string> many_strings;
    many_strings.reserve(N);
    for (size_t i = 0; i < N; ++i) {
        many_strings.push_back("leaf_" + std::to_string(i));
    }
    auto many_leaves = create_leaves(many_strings);

    Tree tree = Tree::build(std::move(many_leaves));
    EXPECT_EQ(tree.size(), N);

    // Sample and verify
    std::vector<size_t> indices_to_check = { 0, 1, 33, 50, 99 };
    for (size_t idx : indices_to_check) {
        auto proof = tree.prove(idx).value();
        EXPECT_TRUE(verify(tree.leaf(idx), proof, tree.root()));
    }
}

} // namespace Honey::Crypto::MerkleTree
