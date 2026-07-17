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

    // ---- incremental update: ship a small pack, not the whole thing ----
    // A "patch" is just another sealpack containing the files you want to update.
    // merge() overlays every file from `other` onto this pack: same path
    // overwrites, new path is added, everything else is left untouched. So to
    // update a file, build a tiny pack with just that file (create + put) and
    // merge it into the deployed one. Base-independent and idempotent. Buffered
    // like put()/del() — call commit() after.
    // Deletions travel in the patch too: if `other` contains a file named
    // ".spkdel" its lines are treated as paths to delete (that control file is
    // consumed, not merged). So an update pack fully describes its update.
    bool merge(const Pack& other);

    // Logical delta from THIS pack (old) to `newer`: fills the paths that were
    // added (in newer only), modified (in both, different content), and deleted
    // (in this only). Cheap — compares content hashes, reads no blobs. Producer
    // helper for building an update pack (put the added+modified files + a
    // `.spkdel` of the deleted ones); the device just merge()s that pack.
    void diff(const Pack& newer,
              std::vector<std::string>* added,
              std::vector<std::string>* modified,
              std::vector<std::string>* deleted) const;

    // ---- password: change it without re-encrypting the data ----
    // Data is under a random master key; the password only wraps that key into
    // an 88-byte slot, so rekey rewrites that slot alone — the blobs never move,
    // so it's instant even on a multi-GB pack. An empty password ("") is allowed
    // but offers no protection (the salt is public → anyone can open it).
    bool verify_password(const std::string& password) const;  // does `password` open this pack?
    bool rekey(const std::string& new_password);              // change the password

    int last_error() const;  // sealpack_status code of the last failing call

private:
    Pack();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace sealpack

#endif  // SEALPACK_HPP
