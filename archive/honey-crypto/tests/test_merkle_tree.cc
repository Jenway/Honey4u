#include "crypto/merkle_tree.hpp"
#include "merkle_test_utils.hpp" // 上面的辅助文件
#include <gtest/gtest.h>

namespace Honey::Crypto::MerkleTree {

class MerkleTreeTest : public ::testing::Test {
protected:
    // 准备一些常用的测试数据
    std::vector<std::vector<Byte>> data_blocks;

    void SetUp() override
    {
        data_blocks = {
            to_bytes("data_1"),
            to_bytes("data_2"),
            to_bytes("data_3"),
            to_bytes("data_4"),
            to_bytes("data_5")
        };
    }
};

// 测试 1: 构建空树
TEST_F(MerkleTreeTest, BuildEmpty)
{
    std::vector<std::vector<Byte>> empty_leaves;
    Tree tree = build(empty_leaves);

    EXPECT_EQ(tree.leaf_count(), 0);
    EXPECT_FALSE(tree.root().has_value());
}

// 测试 2: 单节点树
TEST_F(MerkleTreeTest, SingleNode)
{
    std::vector<std::vector<Byte>> leaves = { data_blocks[0] };
    Tree tree = build(leaves);

    EXPECT_EQ(tree.leaf_count(), 1);
    ASSERT_TRUE(tree.root().has_value());

    // 验证: 证明索引 0
    auto proof_res = tree.prove(0);
    ASSERT_TRUE(proof_res.has_value());
    const auto& proof = *proof_res;

    // 单节点的 Proof 应该为空 (或者取决于你的具体实现，通常没有 sibling)
    EXPECT_EQ(proof.siblings.size(), 0);

    // 验证逻辑应该通过
    EXPECT_TRUE(verify(leaves[0], *tree.root(), proof));
}

// 测试 3: 标准 2^N (4个节点)
TEST_F(MerkleTreeTest, PowerOfTwo)
{
    std::vector<std::vector<Byte>> leaves = {
        data_blocks[0], data_blocks[1], data_blocks[2], data_blocks[3]
    };
    Tree tree = build(leaves);

    EXPECT_EQ(tree.leaf_count(), 4);
    auto root = tree.root();
    ASSERT_TRUE(root.has_value());

    // 对每个叶子进行验证
    for (size_t i = 0; i < 4; ++i) {
        auto proof_res = tree.prove(i);
        ASSERT_TRUE(proof_res.has_value());
        EXPECT_TRUE(verify(leaves[i], *root, *proof_res)) << "Verification failed for index " << i;
    }
}

// 测试 4: 非 2^N (3个节点) - 测试 Padding 逻辑
// 根据 Python 逻辑，3个节点会被补全到 4 个，第4个是空串(b'')的哈希
TEST_F(MerkleTreeTest, OddNumberOfLeaves)
{
    std::vector<std::vector<Byte>> leaves = {
        data_blocks[0], data_blocks[1], data_blocks[2]
    };
    Tree tree = build(leaves);

    EXPECT_EQ(tree.leaf_count(), 3); // 逻辑数量
    // 内部实现可能 padded 到了 4

    auto root = tree.root();
    ASSERT_TRUE(root.has_value());

    // 验证存在的节点
    for (size_t i = 0; i < 3; ++i) {
        auto proof_res = tree.prove(i);
        ASSERT_TRUE(proof_res.has_value());
        EXPECT_TRUE(verify(leaves[i], *root, *proof_res));
    }

    // 尝试获取越界的 Proof (Index 3) 应该失败或返回错误
    // 这取决于你的 prove 实现是返回 error 还是 assert
    auto proof_out_of_bound = tree.prove(3);
    EXPECT_FALSE(proof_out_of_bound.has_value());
}

// 测试 5: 数据篡改检测 (Tampering)
TEST_F(MerkleTreeTest, DetectsTampering)
{
    std::vector<std::vector<Byte>> leaves = {
        data_blocks[0], data_blocks[1], data_blocks[2], data_blocks[3]
    };
    Tree tree = build(leaves);
    auto root = *tree.root();
    auto proof = *tree.prove(1); // Proof for data_2

    // 场景 A: 验证错误的数据
    auto fake_data = to_bytes("malicious_data");
    EXPECT_FALSE(verify(fake_data, root, proof)) << "Should fail when data is changed";

    // 场景 B: 验证错误的 Root
    Hash fake_root = root;
    fake_root[0] ^= std::byte(0xFF); // Flip a bit
    EXPECT_FALSE(verify(leaves[1], fake_root, proof)) << "Should fail when root is changed";
}

// 测试 6: Proof 篡改检测
TEST_F(MerkleTreeTest, DetectsProofTampering)
{
    std::vector<std::vector<Byte>> leaves = {
        data_blocks[0], data_blocks[1], data_blocks[2], data_blocks[3]
    };
    Tree tree = build(leaves);
    auto proof = *tree.prove(0);

    ASSERT_GT(proof.siblings.size(), 0);

    // 修改 proof 路径中的一个哈希
    proof.siblings[0][0] ^= std::byte(0xFF);

    EXPECT_FALSE(verify(leaves[0], *tree.root(), proof));
}

// 测试 7: 域分离 (Domain Separation) 检查
// 如果你实现了 hash_leaf(0x00|data) 和 hash_internal(0x01|left|right)
// 这个测试确保叶子节点的哈希值不仅仅是数据的直接 SHA256
TEST_F(MerkleTreeTest, DomainSeparation)
{
    // 这是一个白盒测试，需要访问 detail 或者通过构造冲突来测试
    // 这里我们假设可以通过 detail 访问 hash_leaf

    auto data = to_bytes("test");

    // 直接 SHA256
    auto direct_hash = Utils::sha256(data);

    // Merkle Tree 的 hash_leaf
    auto leaf_hash = detail::hash_leaf(data);

    // 它们不应该相等，否则存在第二原像攻击风险
    EXPECT_NE(direct_hash, leaf_hash) << "Domain separation is likely missing!";
}

// 测试 8: 大量数据 (确保递归/循环逻辑没问题)
TEST_F(MerkleTreeTest, LargeTree)
{
    size_t N = 100;
    std::vector<std::vector<Byte>> many_leaves;
    for (size_t i = 0; i < N; ++i) {
        many_leaves.push_back(to_bytes("leaf_" + std::to_string(i)));
    }

    Tree tree = build(many_leaves);
    auto root = *tree.root();

    // 抽样验证
    std::vector<size_t> indices_to_check = { 0, 1, 33, 50, 99 };
    for (size_t idx : indices_to_check) {
        auto proof = *tree.prove(idx);
        EXPECT_TRUE(verify(many_leaves[idx], root, proof));
    }
}

} // namespace Honey::Crypto::MerkleTree