#ifndef SEALPACK_STORE_HPP
#define SEALPACK_STORE_HPP

// Single-file layout + crash-safe atomic commit.
//
// On-disk layout (fixed-offset front matter, then an append-only data region):
//
//   0    Header      "SEALPACK" magic + version + Argon2 salt/params (plaintext;
//                     the salt is public, that's fine)
//   40   Superblock A ┐ 64 bytes each, AEAD-encrypted {seq, root_off, root_len}.
//   104  Superblock B ┘ The active one is whichever has the larger seq and a
//                       valid MAC. Commit writes the *other* slot then fsyncs —
//                       that fsync is the single atomic commit point.
//   168  Data region  append-only: encrypted blobs + encrypted manifests. Never
//                      overwritten, so a crash can't damage already-committed
//                      bytes.
//
// Store treats blob/manifest bytes as opaque (Pack encrypts them). Store only
// encrypts its own superblocks, which gives two things for free: a wrong key
// can't open the pack, and a torn superblock write is caught by its MAC.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "crypto.hpp"

namespace sealpack {

struct StoreHeader {
    uint8_t   salt[kSaltBytes];
    KdfParams kdf;
};

// What the active superblock points at (the current manifest). len 0 = empty.
struct Root {
    uint64_t offset = 0;
    uint64_t len    = 0;
};

class Store {
public:
    // Create a new file (fails if it exists): header + two superblocks. `key`
    // encrypts the superblocks. Returns nullptr on error.
    static std::unique_ptr<Store> create(const std::string& path,
                                          const StoreHeader& hdr,
                                          const uint8_t key[kKeyBytes]);

    // Read just the header (salt + kdf) so the caller can derive the key.
    static bool read_header(const std::string& path, StoreHeader* out);

    // Open existing, selecting the newest superblock that decrypts. Returns
    // nullptr on wrong key (neither superblock decrypts) or I/O error.
    static std::unique_ptr<Store> open(const std::string& path,
                                        const uint8_t key[kKeyBytes]);

    ~Store();
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;

    const StoreHeader& header() const;
    Root root() const;

    // Append opaque bytes; returns the file offset (>0), or 0 on error. Not
    // durable until commit().
    uint64_t append(const void* data, size_t n);

    // Read n bytes at offset. false on short read / I/O error.
    bool read_at(uint64_t offset, void* buf, size_t n);

    // Atomic commit: fsync the data region, write the inactive superblock with
    // seq+1 pointing at [root_offset, root_len], fsync it. A power loss before
    // that final fsync returns leaves the previous root fully intact.
    bool commit(uint64_t root_offset, uint64_t root_len, const uint8_t key[kKeyBytes]);

private:
    Store();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace sealpack

#endif  // SEALPACK_STORE_HPP
