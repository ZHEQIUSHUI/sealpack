#include "index.hpp"

#include <utility>
#include <vector>

namespace sealpack {
namespace {

void put_u32(std::string& s, uint32_t v) {
    for (int i = 0; i < 4; ++i) s.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
}
void put_u64(std::string& s, uint64_t v) {
    for (int i = 0; i < 8; ++i) s.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
}
bool get_u32(const uint8_t* d, size_t n, size_t& p, uint32_t& v) {
    if (p + 4 > n) return false;
    v = uint32_t(d[p]) | uint32_t(d[p + 1]) << 8 | uint32_t(d[p + 2]) << 16 |
        uint32_t(d[p + 3]) << 24;
    p += 4;
    return true;
}
bool get_u64(const uint8_t* d, size_t n, size_t& p, uint64_t& v) {
    if (p + 8 > n) return false;
    v = 0;
    for (int i = 0; i < 8; ++i) v |= uint64_t(d[p + i]) << (8 * i);
    p += 8;
    return true;
}
bool get_bytes(const uint8_t* d, size_t n, size_t& p, size_t len, std::string& out) {
    if (p + len > n) return false;
    out.assign(reinterpret_cast<const char*>(d) + p, len);
    p += len;
    return true;
}

constexpr uint32_t kIndexMagic = 0x53504958;  // "SPIX"

}  // namespace

std::string normalize_path(const std::string& path) {
    std::vector<std::string> segs;
    size_t i = 0;
    while (i < path.size()) {
        size_t j = path.find('/', i);
        if (j == std::string::npos) j = path.size();
        std::string seg = path.substr(i, j - i);
        if (seg.empty() || seg == ".") {
            // collapse "//", "/./", leading/trailing slash
        } else if (seg == "..") {
            return "";  // never let a path escape the pack
        } else {
            segs.push_back(std::move(seg));
        }
        i = j + 1;
    }
    if (segs.empty()) return "";
    std::string out;
    for (size_t k = 0; k < segs.size(); ++k) {
        if (k) out.push_back('/');
        out += segs[k];
    }
    return out;
}

std::string serialize(const Index& idx) {
    std::string s;
    put_u32(s, kIndexMagic);

    put_u32(s, static_cast<uint32_t>(idx.blobs.size()));
    for (const auto& kv : idx.blobs) {
        s.append(kv.first);  // 32-byte content hash key
        put_u64(s, kv.second.offset);
        put_u64(s, kv.second.enc_size);
        put_u64(s, kv.second.plain_size);
        put_u32(s, kv.second.refcount);
    }

    put_u32(s, static_cast<uint32_t>(idx.paths.size()));
    for (const auto& kv : idx.paths) {
        put_u32(s, static_cast<uint32_t>(kv.first.size()));
        s.append(kv.first);           // logical path
        s.append(kv.second.hash);     // 32-byte hash
        put_u64(s, kv.second.mtime);
    }
    return s;
}

bool deserialize(const uint8_t* d, size_t n, Index* out) {
    size_t p = 0;
    uint32_t magic;
    if (!get_u32(d, n, p, magic) || magic != kIndexMagic) return false;

    Index idx;
    uint32_t nblobs;
    if (!get_u32(d, n, p, nblobs)) return false;
    for (uint32_t i = 0; i < nblobs; ++i) {
        std::string hash;
        if (!get_bytes(d, n, p, 32, hash)) return false;
        BlobRef ref;
        if (!get_u64(d, n, p, ref.offset)) return false;
        if (!get_u64(d, n, p, ref.enc_size)) return false;
        if (!get_u64(d, n, p, ref.plain_size)) return false;
        if (!get_u32(d, n, p, ref.refcount)) return false;
        idx.blobs.emplace(std::move(hash), ref);
    }

    uint32_t npaths;
    if (!get_u32(d, n, p, npaths)) return false;
    for (uint32_t i = 0; i < npaths; ++i) {
        uint32_t plen;
        if (!get_u32(d, n, p, plen)) return false;
        std::string path;
        if (!get_bytes(d, n, p, plen, path)) return false;
        PathEntry e;
        if (!get_bytes(d, n, p, 32, e.hash)) return false;
        if (!get_u64(d, n, p, e.mtime)) return false;
        idx.paths.emplace(std::move(path), std::move(e));
    }

    *out = std::move(idx);
    return true;
}

}  // namespace sealpack
