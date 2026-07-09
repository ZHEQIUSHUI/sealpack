#ifndef SEALPACK_CRYPTO_HPP
#define SEALPACK_CRYPTO_HPP

// Thin, sealpack-specific wrapper over monocypher. All algorithm work is
// monocypher's (audited, constant-time); this file only picks parameters and
// pulls OS entropy for salt/nonce. No hand-rolled crypto.

#include <cstddef>
#include <cstdint>

namespace sealpack {

constexpr size_t kKeyBytes   = 32;  // XChaCha20 key / Argon2 output
constexpr size_t kNonceBytes = 24;  // XChaCha20 nonce (192-bit: random-safe)
constexpr size_t kMacBytes   = 16;  // Poly1305 tag
constexpr size_t kHashBytes  = 32;  // BLAKE2b content hash (CAS key)
constexpr size_t kSaltBytes  = 16;  // Argon2 salt

// Argon2id cost. Defaults ≈ 64 MiB / 3 passes — deliberately slow so brute
// forcing a password is expensive even on GPUs. Tune down only for tests.
struct KdfParams {
    uint32_t nb_blocks = 65536;  // memory in 1 KiB blocks (65536 = 64 MiB)
    uint32_t nb_passes = 3;
    uint32_t nb_lanes  = 1;
};

// password (+ public salt) -> 32-byte master key via Argon2id.
// Returns 0 on success, -1 if the work-area allocation fails.
int derive_key(uint8_t key[kKeyBytes], const char* password,
               const uint8_t salt[kSaltBytes], const KdfParams& p);

// XChaCha20-Poly1305 AEAD. `cipher` holds text_size bytes; `mac` is the 16-byte
// tag. `ad` (associated data, may be null) is authenticated but not encrypted.
void aead_encrypt(uint8_t* cipher, uint8_t mac[kMacBytes],
                  const uint8_t key[kKeyBytes], const uint8_t nonce[kNonceBytes],
                  const uint8_t* ad, size_t ad_size,
                  const uint8_t* plain, size_t text_size);

// Inverse. Returns 0 on success, -1 on auth failure (wrong key or tampered) —
// this is the "no password, no plaintext" guarantee.
int aead_decrypt(uint8_t* plain, const uint8_t mac[kMacBytes],
                 const uint8_t key[kKeyBytes], const uint8_t nonce[kNonceBytes],
                 const uint8_t* ad, size_t ad_size,
                 const uint8_t* cipher, size_t text_size);

// BLAKE2b-256 content hash — the content-addressed store key.
void content_hash(uint8_t hash[kHashBytes], const uint8_t* data, size_t n);

// Fill buf from the OS CSPRNG (getrandom, falling back to /dev/urandom).
// Returns 0 ok, -1 fail. This is NOT a home-grown RNG.
int random_bytes(uint8_t* buf, size_t n);

// Constant-time equality (1 = equal, 0 = not) — no early-out, no timing leak.
int ct_equal(const uint8_t* a, const uint8_t* b, size_t n);

// Zero sensitive memory such that the compiler can't optimize it away.
void wipe(void* p, size_t n);

}  // namespace sealpack

#endif  // SEALPACK_CRYPTO_HPP
