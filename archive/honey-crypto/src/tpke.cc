#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "crypto/tpke.hpp"
#include "crypto/utils.hpp"

using namespace blst;

namespace TPKE {
void dealer(int l, int k, PublicKey& pk, std::vector<PrivateKeyShare>& sks)
{
    std::vector<Fr> a;
    for (int i = 0; i < k; ++i)
        a.push_back(Fr::random());
    Fr secret = a[0];

    auto poly_eval = [&](Fr x) {
        Fr y = Fr(0);
        Fr xx = Fr(1);
        for (const auto& c : a) {
            y = y + (c * xx);
            xx = xx * x;
        }
        return y;
    };

    blst::P1 VK_G1 = blst::P1::generator();
    VK_G1.mult(secret.val);

    std::vector<blst::P2> VKs_G2;
    std::vector<Fr> SKs;

    for (int i = 1; i <= l; ++i) {
        Fr sk = poly_eval(Fr(i));
        SKs.push_back(sk);

        blst::P2 vk_i = blst::P2::generator();
        vk_i.mult(sk.val);
        VKs_G2.push_back(vk_i);
    }

    pk = { l, k, VK_G1, VKs_G2 };
    sks.clear();
    for (int i = 0; i < l; ++i) {
        sks.push_back({ i + 1, SKs[i], VK_G1, VKs_G2 });
    }
}

Ciphertext encrypt_key(const PublicKey& pk, const std::vector<byte>& message_32b)
{
    if (message_32b.size() != 32)
        throw std::runtime_error("Message key must be 32 bytes");

    Fr r = Fr::random();

    blst::P1 U = blst::P1::generator();
    U.mult(r.val);

    blst::P1 mask_point = pk.vk_g1;
    mask_point.mult(r.val);
    std::vector<byte> mask = CryptoUtils::hashG(mask_point);

    std::vector<byte> V = CryptoUtils::xor_bytes(message_32b, mask);

    blst::P2 H = CryptoUtils::hashH(U, V);
    blst::P2 W = H;
    W.mult(r.val);

    return { U, V, W };
}

bool verify_ciphertext(const Ciphertext& C)
{
    // e(g1, W) == e(U, H)
    blst::P1_Affine g1_aff(blst::P1::generator());
    blst::P2_Affine W_aff(C.W);

    blst::P1_Affine U_aff(C.U);
    blst::P2_Affine H_aff(CryptoUtils::hashH(C.U, C.V));

    // PT(P2, P1) -> MillerLoop(P2, P1)
    blst::PT lhs(W_aff, g1_aff);
    lhs.final_exp();

    blst::PT rhs(H_aff, U_aff);
    rhs.final_exp();

    return lhs.is_equal(rhs);
}

blst::P1 decrypt_share(const PrivateKeyShare& sk, const Ciphertext& C)
{
    if (!verify_ciphertext(C))
        throw std::runtime_error("Invalid Ciphertext");

    blst::P1 Ui = C.U;
    Ui.mult(sk.sk.val);
    return Ui;
}
bool verify_share(const PublicKey& pk, int id, const Ciphertext& C, const blst::P1& Ui)
{
    if (id < 1 || id > pk.l)
        return false;

    // e(Ui, g2) == e(U, Y_i)
    blst::P1_Affine Ui_aff(Ui);
    blst::P2_Affine g2_aff(blst::P2::generator());

    blst::P1_Affine U_aff(C.U);
    blst::P2_Affine Yi_aff(pk.vks_g2[id - 1]);

    blst::PT lhs(g2_aff, Ui_aff);
    lhs.final_exp();

    blst::PT rhs(Yi_aff, U_aff);
    rhs.final_exp();

    return lhs.is_equal(rhs);
}

std::vector<byte> combine_shares(const PublicKey& pk, const Ciphertext& C,
    const std::vector<int>& ids,
    const std::vector<blst::P1>& shares)
{
    if (ids.size() != (size_t)pk.k)
        throw std::runtime_error("Need k shares");

    std::set<int> S(ids.begin(), ids.end());
    blst::P1 res_point; // Identity

    for (size_t i = 0; i < ids.size(); ++i) {
        int id = ids[i];

        Fr num = Fr(1);
        Fr den = Fr(1);
        for (int jj : S) {
            if (jj == id)
                continue;
            num = num * (Fr(0) - Fr(jj));
            den = den * (Fr(id) - Fr(jj));
        }
        Fr coeff = num * den.inverse();

        blst::P1 part = shares[i];
        part.mult(coeff.val);
        res_point.add(part);
    }

    std::vector<byte> mask = CryptoUtils::hashG(res_point);
    return CryptoUtils::xor_bytes(C.V, mask);
}
};

namespace HybridEnc {
HybridCiphertext encrypt(const TPKE::PublicKey& pk,
    const std::string& plaintext)
{
    std::vector<byte> session_key(32);
    RAND_bytes(session_key.data(), 32);

    TPKE::Ciphertext c_key = TPKE::encrypt_key(pk, session_key);

    std::vector<byte> pt_bytes(plaintext.begin(), plaintext.end());
    std::vector<byte> c_data = CryptoUtils::aes_encrypt(session_key, pt_bytes);

    return { c_key, c_data };
}

std::string decrypt(const TPKE::PublicKey& pk,
    const HybridCiphertext& hc,
    const std::vector<int>& ids,
    const std::vector<blst::P1>& shares)
{
    std::vector<byte> session_key = TPKE::combine_shares(pk, hc.tpke_c, ids, shares);
    std::vector<byte> pt_bytes = CryptoUtils::aes_decrypt(session_key, hc.aes_c);
    return std::string(pt_bytes.begin(), pt_bytes.end());
}
};

void print_hex(const std::string& label, const std::vector<byte>& data)
{
    std::cout << label << ": ";
    for (byte b : data)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << std::dec << std::endl;
}
