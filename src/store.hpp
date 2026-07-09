#ifndef SEALPACK_STORE_HPP
#define SEALPACK_STORE_HPP

// Single-file layout + crash-safe atomic commit, with key-wrapping.
//
// The data is encrypted under a random MASTER key. Passwords never derive the
// master key directly — instead each password wraps (AEAD-encrypts) the master
// key into one of N key slots in the header. So:
//   - changing a password rewrites one 88-byte slot, not the whole file;
//   - multiple passwords can open the same pack (one slot each), LUKS-style.
//
// On-disk layout (fixed-offset front matter, then an append-only data region):
//
//   0    Header       "SEALPACK" magic(8) + version(4) + Argon2 params(12) = 24
//   24   KeySlot[8]   88 bytes each: salt(16) + AEAD-wrapped master key
//                     (nonce24 + mac16 + cipher32). Empty slot = all-zero salt.
//   728  Superblock A ┐ 64 bytes each, AEAD{seq, root_off, root_len} under the
//   792  Superblock B ┘ MASTER key. Active = larger seq with a valid MAC; commit
//                       writes the other slot then fsyncs (the atomic point).
//   856  Data region  append-only: encrypted blobs + manifests (master key).
//                      Never overwritten — a crash can't damage committed bytes.
//
// Store treats blob/manifest bytes as opaque (Pack encrypts them). Store owns
// the header/slots/superblocks; Pack owns the password→master-key wrapping.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "crypto.hpp"

namespace sealpack {

constexpr int    kNumKeySlots = 8;
constexpr size_t kWrappedBytes = kNonceBytes + kMacBytes + kKeyBytes;  // 72

// A password-wrapped master key. Empty slot = all-zero salt.
struct KeySlot {
    uint8_t salt[kSaltBytes]      = {0};
    uint8_t wrapped[kWrappedBytes] = {0};  // nonce | mac | cipher(master key)
    bool empty() const;
};

// What the active superblock points at (the current manifest). len 0 = empty.
struct Root {
    uint64_t offset = 0;
    uint64_t len    = 0;
};

class Store {
public:
    // Create a new file (fails if it exists): header + empty slots + superblocks
    // under `master`. Pack fills slot 0 afterwards via write_slot.
    static std::unique_ptr<Store> create(const std::string& path,
                                          const uint8_t master[kKeyBytes],
                                          const KdfParams& kdf);

    // Read the Argon2 params + all key slots WITHOUT the master key — Pack uses
    // these to try unwrapping the master key from a slot.
    static bool read_meta(const std::string& path, KdfParams* kdf,
                          KeySlot slots[kNumKeySlots]);

    // Open with the (already unwrapped) master key: verifies a superblock
    // decrypts. Returns nullptr on a bad master key / I/O error.
    static std::unique_ptr<Store> open(const std::string& path,
                                        const uint8_t master[kKeyBytes]);

    ~Store();
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;

    const KdfParams& kdf() const;
    Root root() const;

    // Key-slot access (rekey/addkey/rmkey work here). write_slot persists
    // immediately (single 88-byte pwrite + fsync); the data region is untouched.
    KeySlot slot(int idx) const;
    bool write_slot(int idx, const KeySlot& s);

    // Append opaque bytes; returns the file offset (>0), or 0 on error. Not
    // durable until commit().
    uint64_t append(const void* data, size_t n);

    // Read n bytes at offset. false on short read / I/O error.
    bool read_at(uint64_t offset, void* buf, size_t n);

    // Atomic commit: fsync data, write the inactive superblock (seq+1) under
    // `master`, fsync it. A power loss before that fsync keeps the old root.
    bool commit(uint64_t root_offset, uint64_t root_len, const uint8_t master[kKeyBytes]);

private:
    Store();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace sealpack

#endif  // SEALPACK_STORE_HPP
