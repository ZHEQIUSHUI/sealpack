#ifndef SEALPACK_HPP
#define SEALPACK_HPP

// sealpack C++ API — the core. The C API in sealpack.h is a thin wrapper over
// this class. Single-file, password-encrypted, content-addressed blob store
// with crash-safe atomic commits; see sealpack.h for the format/guarantees.
//
// No exceptions: methods return bool (or nullptr) and set last_error() to a
// sealpack_status code — friendly for embedded targets and the C wrapper.
//
//   auto pack = sealpack::Pack::create("models.sealpack", "hunter2");
//   pack->put("yolo/v2.axmodel", bytes);
//   pack->commit();                       // durable + atomic here
//
//   auto ro = sealpack::Pack::open("models.sealpack", "hunter2");  // null on bad pw
//   std::string data;
//   ro->get("yolo/v2.axmodel", &data);    // decrypts just this blob

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace sealpack {

class Pack {
public:
    // One logical file's metadata (for list()/stat() → a file-manager UI).
    struct Entry {
        std::string path;
        uint64_t    size  = 0;  // plaintext size
        uint64_t    mtime = 0;  // unix seconds
    };

    // Create a new pack (fails if the file exists) / open an existing one.
    // Returns nullptr on failure — check the thread-local last open error via
    // a freshly attempted call's last_error(), or just treat null as "no pack".
    static std::unique_ptr<Pack> create(const std::string& path, const std::string& password);
    static std::unique_ptr<Pack> open(const std::string& path, const std::string& password);

    ~Pack();
    Pack(const Pack&) = delete;
    Pack& operator=(const Pack&) = delete;

    // ---- CRUD (buffered until commit) ----
    bool put(const std::string& path, const void* data, size_t size);
    bool put(const std::string& path, const std::string& data);
    bool get(const std::string& path, std::string* out) const;   // decrypts one blob
    bool del(const std::string& path);
    bool has(const std::string& path) const;

    // ---- file-manager ops (path layer; O(1), the blob never moves) ----
    bool move(const std::string& from, const std::string& to);   // rename/move
    bool copy(const std::string& from, const std::string& to);   // dedup, 0 extra bytes
    bool stat(const std::string& path, Entry* out) const;
    std::vector<Entry> list() const;                             // sorted by path

    // ---- durability + maintenance ----
    bool commit();    // atomic double-superblock swap (the crash-safe point)
    bool compact();   // rewrite the file dropping unreferenced blobs

    // ---- key slots: multiple passwords, rotate without re-encrypting ----
    // Data is under a random master key; each password wraps that key into one
    // of 8 slots. These rewrite an 88-byte slot only — blobs never move, so it's
    // instant even on a multi-GB pack. An empty password ("") is allowed but
    // offers no protection (the salt is public → anyone can open it).
    bool verify_password(const std::string& password) const;  // does `password` open THIS handle's slot?
    bool rekey(const std::string& new_password);   // re-wrap under a new password in THIS handle's slot
    int  addkey(const std::string& new_password);  // wrap into a free slot → its index, or -1 if full
    bool rmkey(int slot_idx);                       // revoke a slot (not the one in use, not the last)
    int  num_keys() const;                          // slots currently in use (1..8)
    int  opened_slot() const;                       // slot index this handle's password opened

    int last_error() const;  // sealpack_status code of the last failing call

private:
    Pack();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace sealpack

#endif  // SEALPACK_HPP
