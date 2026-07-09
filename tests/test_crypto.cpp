#include "check.hpp"
#include "crypto.hpp"

#include <cstring>
#include <string>

using namespace sealpack;

TEST_MAIN("crypto") {
    // ---- content_hash: deterministic, collision-distinct ----
    uint8_t h1[32], h2[32], h3[32];
    content_hash(h1, reinterpret_cast<const uint8_t*>("hello"), 5);
    content_hash(h2, reinterpret_cast<const uint8_t*>("hello"), 5);
    content_hash(h3, reinterpret_cast<const uint8_t*>("world"), 5);
    CHECK(ct_equal(h1, h2, 32));    // same bytes -> same hash (dedup key)
    CHECK(!ct_equal(h1, h3, 32));   // different bytes -> different hash

    // ---- random_bytes: fills, two draws differ ----
    uint8_t r1[32] = {0}, r2[32] = {0};
    CHECK_EQ(random_bytes(r1, sizeof r1), 0);
    CHECK_EQ(random_bytes(r2, sizeof r2), 0);
    CHECK(!ct_equal(r1, r2, 32));   // collision is astronomically unlikely

    // ---- KDF: same pw+salt -> same key; different pw -> different key ----
    uint8_t salt[16];
    CHECK_EQ(random_bytes(salt, sizeof salt), 0);
    KdfParams fast;
    fast.nb_blocks = 256;  // 256 KiB / 1 pass — keep the unit test fast
    fast.nb_passes = 1;
    uint8_t k1[32], k2[32], k3[32];
    CHECK_EQ(derive_key(k1, "hunter2", salt, fast), 0);
    CHECK_EQ(derive_key(k2, "hunter2", salt, fast), 0);
    CHECK_EQ(derive_key(k3, "hunter3", salt, fast), 0);
    CHECK(ct_equal(k1, k2, 32));    // deterministic
    CHECK(!ct_equal(k1, k3, 32));   // password-sensitive

    // ---- AEAD round-trip ----
    const char* msg = "the quick brown fox jumps over the lazy dog";
    const size_t n = std::strlen(msg);
    uint8_t nonce[24];
    CHECK_EQ(random_bytes(nonce, sizeof nonce), 0);
    std::string cipher(n, '\0');
    uint8_t mac[16];
    aead_encrypt(reinterpret_cast<uint8_t*>(cipher.data()), mac, k1, nonce,
                 nullptr, 0, reinterpret_cast<const uint8_t*>(msg), n);
    CHECK(std::memcmp(cipher.data(), msg, n) != 0);  // actually encrypted

    std::string plain(n, '\0');
    CHECK_EQ(aead_decrypt(reinterpret_cast<uint8_t*>(plain.data()), mac, k1, nonce,
                          nullptr, 0, reinterpret_cast<const uint8_t*>(cipher.data()), n),
             0);
    CHECK(std::memcmp(plain.data(), msg, n) == 0);   // recovered exactly

    // ---- tamper detection: flip one cipher byte -> auth fail ----
    std::string tampered = cipher;
    tampered[0] = static_cast<char>(tampered[0] ^ 1);
    CHECK_EQ(aead_decrypt(reinterpret_cast<uint8_t*>(plain.data()), mac, k1, nonce,
                          nullptr, 0, reinterpret_cast<const uint8_t*>(tampered.data()), n),
             -1);

    // ---- THE guarantee: wrong key (wrong password) -> can't decrypt ----
    CHECK_EQ(aead_decrypt(reinterpret_cast<uint8_t*>(plain.data()), mac, k3, nonce,
                          nullptr, 0, reinterpret_cast<const uint8_t*>(cipher.data()), n),
             -1);
}
