#ifndef SEALPACK_INDEX_HPP
#define SEALPACK_INDEX_HPP

// The logical + physical map of a pack, serialized (then encrypted) as the
// manifest. Two layers, deliberately decoupled:
//   - paths : logical filesystem-style path  -> content hash (+ mtime)
//   - blobs : content hash -> where the bytes live + how many paths use it
// Every file-manager op (add/move/copy/delete) touches only `paths`; the
// physical blobs never move. move/copy are therefore O(1) — the CAS sweet spot.

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace sealpack {

// One content-addressed blob: where its (encrypted) bytes sit + refcount.
struct BlobRef {
    uint64_t offset     = 0;  // byte offset of the blob record in the pack file
    uint64_t enc_size   = 0;  // on-disk size (nonce + mac + ciphertext)
    uint64_t plain_size = 0;  // original plaintext size
    uint32_t refcount   = 0;  // live paths pointing here (0 = reclaimable)
    bool operator==(const BlobRef& o) const {
        return offset == o.offset && enc_size == o.enc_size &&
               plain_size == o.plain_size && refcount == o.refcount;
    }
};

// A logical path's payload: which blob, and when it was last written (for the
// UI's "modified" column). Same blob under many paths → each keeps its own mtime.
struct PathEntry {
    std::string hash;       // content hash (32 bytes)
    uint64_t    mtime = 0;  // unix seconds
    bool operator==(const PathEntry& o) const {
        return hash == o.hash && mtime == o.mtime;
    }
};

struct Index {
    std::map<std::string, BlobRef>   blobs;  // hash(32B) -> ref
    std::map<std::string, PathEntry> paths;  // "yolo/v2.axmodel" -> entry
};

// Normalize to filesystem-style: collapse "//", drop leading/trailing '/',
// reject any '..' segment (no escaping out of the pack). Returns "" if the path
// is illegal or empty after normalization.
std::string normalize_path(const std::string& path);

// Portable little-endian (de)serialization. deserialize returns false on any
// truncation or bad magic — defensive against corrupt / adversarial input.
std::string serialize(const Index& idx);
bool deserialize(const uint8_t* data, size_t n, Index* out);

}  // namespace sealpack

#endif  // SEALPACK_INDEX_HPP
