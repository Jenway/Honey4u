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

#include "Fr.hpp"
#include "utils.hpp"

using namespace blst;

namespace TPKE {

struct Ciphertext {
    blst::P1 U;
    std::vector<blst::byte> V;
    blst::P2 W;
};

struct PrivateKeyShare {
    int id;
    Fr sk;
    blst::P1 vk_g1;
    std::vector<blst::P2> vks_g2;
};

struct PublicKey {
    int l, k;
    blst::P1 vk_g1;
    std::vector<blst::P2> vks_g2;
};
}
namespace TPKE {
void dealer(int l, int k, PublicKey& pk, std::vector<PrivateKeyShare>& sks);
Ciphertext encrypt_key(const PublicKey& pk, const std::vector<byte>& message_32b);
bool verify_ciphertext(const Ciphertext& C);

blst::P1 decrypt_share(const PrivateKeyShare& sk, const Ciphertext& C);

bool verify_share(const PublicKey& pk, int id, const Ciphertext& C, const blst::P1& Ui);
std::vector<byte> combine_shares(const PublicKey& pk, const Ciphertext& C,
    const std::vector<int>& ids,
    const std::vector<blst::P1>& shares);
};

// ==========================================
// 4. Hybrid Encryption
// ==========================================

struct HybridCiphertext {
    TPKE::Ciphertext tpke_c;
    std::vector<byte> aes_c;
};

namespace HybridEnc {
HybridCiphertext encrypt(const TPKE::PublicKey& pk,
    const std::string& plaintext);
std::string decrypt(const TPKE::PublicKey& pk,
    const HybridCiphertext& hc,
    const std::vector<int>& ids,
    const std::vector<blst::P1>& shares);
};

void print_hex(const std::string& label, const std::vector<byte>& data);