#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "crypto/tpke.hpp"

using namespace blst;

TEST(TPKE_Test, HybridEncryptionFlow)
{
    int N = 5;
    int K = 3;

    TPKE::PublicKey pk;
    std::vector<TPKE::PrivateKeyShare> sks;

    TPKE::dealer(N, K, pk, sks);

    ASSERT_EQ(sks.size(), N);

    // 2. Encrypt
    std::string secret_msg = "HoneyBadger BFT is robust!";

    // 使用 HybridEnc 进行加密
    // 假设 HybridEnc 类在头文件中可见
    HybridCiphertext hc = HybridEnc::encrypt(pk, secret_msg);

    // 检查密文不为空
    EXPECT_FALSE(hc.aes_c.empty());

    // 3. Decrypt Shares
    std::vector<int> decryptors = { 1, 3, 5 }; // 选取 K 个解密者
    std::vector<blst::P1> shares;

    for (int id : decryptors) {
        // 生成解密份额
        blst::P1 s = TPKE::decrypt_share(sks[id - 1], hc.tpke_c);

        // 验证份额
        bool share_valid = TPKE::verify_share(pk, id, hc.tpke_c, s);
        EXPECT_TRUE(share_valid) << "Decryption share verification failed for ID: " << id;

        if (share_valid) {
            shares.push_back(s);
        }
    }

    ASSERT_EQ(shares.size(), K);

    // 4. Combine & Decrypt
    std::string decrypted_msg = HybridEnc::decrypt(pk, hc, decryptors, shares);

    // 5. 验证结果
    EXPECT_EQ(decrypted_msg, secret_msg) << "Decrypted message does not match original";
}

// 测试解密失败的情况（份额错误）
TEST(TPKE_Test, WrongShareFails)
{
    int N = 5;
    int K = 3;
    TPKE::PublicKey pk;
    std::vector<TPKE::PrivateKeyShare> sks;
    TPKE::dealer(N, K, pk, sks);

    std::string secret_msg = "Test";
    HybridCiphertext hc = HybridEnc::encrypt(pk, secret_msg);

    // 故意使用错误的私钥生成份额
    // 比如：节点 1 用了节点 2 的私钥来解密节点 1 的份（逻辑上不对，或者直接生成错误点）
    // 这里简单模拟：用一个随机数生成的份额混进去

    std::vector<int> decryptors = { 1, 2, 3 };
    std::vector<blst::P1> shares;

    // 正常添加 1 和 2
    shares.push_back(TPKE::decrypt_share(sks[0], hc.tpke_c));
    shares.push_back(TPKE::decrypt_share(sks[1], hc.tpke_c));

    // 第 3 个份额是胡乱生成的
    blst::P1 bad_share = blst::P1::generator();
    shares.push_back(bad_share);

    // 验证那个坏份额应该失败
    EXPECT_FALSE(TPKE::verify_share(pk, 3, hc.tpke_c, bad_share));

    // 如果强制 combine，AES 解密出来的东西应该是乱码
    // 注意：HybridEnc::decrypt 可能会抛出 padding 异常，或者解密出乱码
    // 取决于你的 AES 实现是否检查 padding
    try {
        std::string bad_result = HybridEnc::decrypt(pk, hc, decryptors, shares);
        EXPECT_NE(bad_result, secret_msg);
    } catch (...) {
        // 如果抛出异常也是符合预期的，因为 AES padding check 会挂
        SUCCEED();
    }
}