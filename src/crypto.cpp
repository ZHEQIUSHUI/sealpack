#include "crypto.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "monocypher.h"
}

#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

namespace sealpack {

int derive_key(uint8_t key[kKeyBytes], const char* password,
               const uint8_t salt[kSaltBytes], const KdfParams& p) {
    const size_t work_size = static_cast<size_t>(p.nb_blocks) * 1024u;
    void* work = std::malloc(work_size);
    if (!work) return -1;

    crypto_argon2_config cfg;
    cfg.algorithm = CRYPTO_ARGON2_ID;
    cfg.nb_blocks = p.nb_blocks;
    cfg.nb_passes = p.nb_passes;
    cfg.nb_lanes  = p.nb_lanes;

    crypto_argon2_inputs in;
    in.pass      = reinterpret_cast<const uint8_t*>(password);
    in.pass_size = static_cast<uint32_t>(std::strlen(password));
    in.salt      = salt;
    in.salt_size = kSaltBytes;

    crypto_argon2(key, kKeyBytes, work, cfg, in, crypto_argon2_no_extras);
    crypto_wipe(work, work_size);  // scrub the memory-hard buffer
    std::free(work);
    return 0;
}

void aead_encrypt(uint8_t* cipher, uint8_t mac[kMacBytes],
                  const uint8_t key[kKeyBytes], const uint8_t nonce[kNonceBytes],
                  const uint8_t* ad, size_t ad_size,
                  const uint8_t* plain, size_t text_size) {
    crypto_aead_lock(cipher, mac, key, nonce, ad, ad_size, plain, text_size);
}

int aead_decrypt(uint8_t* plain, const uint8_t mac[kMacBytes],
                 const uint8_t key[kKeyBytes], const uint8_t nonce[kNonceBytes],
                 const uint8_t* ad, size_t ad_size,
                 const uint8_t* cipher, size_t text_size) {
    return crypto_aead_unlock(plain, mac, key, nonce, ad, ad_size, cipher, text_size);
}

void content_hash(uint8_t hash[kHashBytes], const uint8_t* data, size_t n) {
    crypto_blake2b(hash, kHashBytes, data, n);
}

int random_bytes(uint8_t* buf, size_t n) {
#if defined(__linux__)
    {
        size_t off = 0;
        while (off < n) {
            ssize_t r = getrandom(buf + off, n - off, 0);
            if (r < 0) { if (errno == EINTR) continue; break; }  // fall through
            off += static_cast<size_t>(r);
        }
        if (off == n) return 0;
    }
#endif
    int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < n) {
        ssize_t r = ::read(fd, buf + off, n - off);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            ::close(fd);
            return -1;
        }
        off += static_cast<size_t>(r);
    }
    ::close(fd);
    return 0;
}

int ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    // Fold all byte diffs into one accumulator with no data-dependent branch —
    // runtime is independent of where/whether a mismatch occurs.
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    return diff == 0 ? 1 : 0;
}

void wipe(void* p, size_t n) { crypto_wipe(p, n); }

}  // namespace sealpack
