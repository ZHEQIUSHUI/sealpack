#include "store.hpp"

#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>

namespace sealpack {
namespace {

// ---- fixed layout ----
constexpr size_t   kHeaderSize = 40;   // magic8 + ver4 + salt16 + kdf(3*u32)
constexpr size_t   kSbSize     = 64;   // nonce24 + mac16 + cipher24
constexpr uint64_t kSbAOff     = 40;
constexpr uint64_t kSbBOff     = 40 + 64;      // 104
constexpr uint64_t kDataStart  = 40 + 64 + 64; // 168
constexpr uint32_t kVersion    = 1;

void enc_u32(uint8_t* p, uint32_t v) { for (int i = 0; i < 4; ++i) p[i] = uint8_t(v >> (8 * i)); }
void enc_u64(uint8_t* p, uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = uint8_t(v >> (8 * i)); }
uint32_t dec_u32(const uint8_t* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
uint64_t dec_u64(const uint8_t* p) {
    uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= uint64_t(p[i]) << (8 * i); return v;
}

bool pwrite_all(int fd, const void* buf, size_t n, uint64_t off) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t done = 0;
    while (done < n) {
        ssize_t w = ::pwrite(fd, p + done, n - done, static_cast<off_t>(off + done));
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; return false; }
        done += static_cast<size_t>(w);
    }
    return true;
}
bool pread_all(int fd, void* buf, size_t n, uint64_t off) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < n) {
        ssize_t r = ::pread(fd, p + done, n - done, static_cast<off_t>(off + done));
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return false; }
        done += static_cast<size_t>(r);
    }
    return true;
}

// Superblock on disk: nonce(24) | mac(16) | ciphertext(24 = seq|off|len).
bool write_sb(int fd, uint64_t pos, uint64_t seq, uint64_t off, uint64_t len,
              const uint8_t key[kKeyBytes]) {
    uint8_t plain[24];
    enc_u64(plain + 0, seq);
    enc_u64(plain + 8, off);
    enc_u64(plain + 16, len);
    uint8_t sb[kSbSize];
    if (random_bytes(sb, kNonceBytes) != 0) return false;         // nonce
    aead_encrypt(sb + kNonceBytes + kMacBytes, sb + kNonceBytes,   // cipher, mac
                 key, sb /*nonce*/, nullptr, 0, plain, sizeof plain);
    return pwrite_all(fd, sb, kSbSize, pos);
}
bool read_sb(int fd, uint64_t pos, const uint8_t key[kKeyBytes],
             uint64_t* seq, uint64_t* off, uint64_t* len) {
    uint8_t sb[kSbSize];
    if (!pread_all(fd, sb, kSbSize, pos)) return false;
    uint8_t plain[24];
    if (aead_decrypt(plain, sb + kNonceBytes, key, sb /*nonce*/, nullptr, 0,
                     sb + kNonceBytes + kMacBytes, sizeof plain) != 0)
        return false;  // wrong key, or torn/corrupt write
    *seq = dec_u64(plain + 0);
    *off = dec_u64(plain + 8);
    *len = dec_u64(plain + 16);
    return true;
}

// Flush to stable storage. On macOS plain fsync only reaches the drive cache,
// not the platter — F_FULLFSYNC is what crash durability actually needs there.
// On Linux fdatasync is enough and cheaper (data only, skips metadata).
int durable_sync(int fd) {
#if defined(__APPLE__)
    if (::fcntl(fd, F_FULLFSYNC) == 0) return 0;
    return ::fsync(fd);  // fall back if the fs doesn't support F_FULLFSYNC
#elif defined(__linux__)
    return ::fdatasync(fd);
#else
    return ::fsync(fd);
#endif
}

}  // namespace

struct Store::Impl {
    int         fd = -1;
    StoreHeader hdr{};
    uint64_t    seq = 0;         // active superblock seq
    int         active_slot = 0; // 0 = A, 1 = B
    Root        root{};
    uint64_t    file_size = 0;   // append position (end of data region)
    ~Impl() { if (fd >= 0) ::close(fd); }
};

Store::Store() : impl_(new Impl) {}
Store::~Store() = default;

std::unique_ptr<Store> Store::create(const std::string& path, const StoreHeader& hdr,
                                     const uint8_t key[kKeyBytes]) {
    int fd = ::open(path.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) return nullptr;

    uint8_t h[kHeaderSize];
    std::memcpy(h, "SEALPACK", 8);
    enc_u32(h + 8, kVersion);
    std::memcpy(h + 12, hdr.salt, kSaltBytes);
    enc_u32(h + 28, hdr.kdf.nb_blocks);
    enc_u32(h + 32, hdr.kdf.nb_passes);
    enc_u32(h + 36, hdr.kdf.nb_lanes);

    // A holds the (newer) active seq 1 = empty pack; B holds seq 0. Both valid,
    // A wins by seq → deterministic. First commit writes B with seq 2.
    if (!pwrite_all(fd, h, kHeaderSize, 0) ||
        !write_sb(fd, kSbAOff, 1, 0, 0, key) ||
        !write_sb(fd, kSbBOff, 0, 0, 0, key) ||
        durable_sync(fd) != 0) {
        ::close(fd);
        ::unlink(path.c_str());
        return nullptr;
    }

    std::unique_ptr<Store> st(new Store);
    st->impl_->fd = fd;
    st->impl_->hdr = hdr;
    st->impl_->seq = 1;
    st->impl_->active_slot = 0;
    st->impl_->root = {0, 0};
    st->impl_->file_size = kDataStart;
    return st;
}

bool Store::read_header(const std::string& path, StoreHeader* out) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    uint8_t h[kHeaderSize];
    bool ok = pread_all(fd, h, kHeaderSize, 0) && std::memcmp(h, "SEALPACK", 8) == 0 &&
              dec_u32(h + 8) == kVersion;
    if (ok) {
        std::memcpy(out->salt, h + 12, kSaltBytes);
        out->kdf.nb_blocks = dec_u32(h + 28);
        out->kdf.nb_passes = dec_u32(h + 32);
        out->kdf.nb_lanes  = dec_u32(h + 36);
    }
    ::close(fd);
    return ok;
}

std::unique_ptr<Store> Store::open(const std::string& path, const uint8_t key[kKeyBytes]) {
    int fd = ::open(path.c_str(), O_RDWR);
    if (fd < 0) return nullptr;

    uint8_t h[kHeaderSize];
    if (!pread_all(fd, h, kHeaderSize, 0) || std::memcmp(h, "SEALPACK", 8) != 0 ||
        dec_u32(h + 8) != kVersion) {
        ::close(fd);
        return nullptr;
    }
    StoreHeader hdr;
    std::memcpy(hdr.salt, h + 12, kSaltBytes);
    hdr.kdf.nb_blocks = dec_u32(h + 28);
    hdr.kdf.nb_passes = dec_u32(h + 32);
    hdr.kdf.nb_lanes  = dec_u32(h + 36);

    uint64_t sA, oA, lA, sB, oB, lB;
    bool okA = read_sb(fd, kSbAOff, key, &sA, &oA, &lA);
    bool okB = read_sb(fd, kSbBOff, key, &sB, &oB, &lB);
    if (!okA && !okB) { ::close(fd); return nullptr; }  // wrong password / both torn

    int slot; uint64_t seq, off, len;
    if (okA && (!okB || sA >= sB)) { slot = 0; seq = sA; off = oA; len = lA; }
    else                           { slot = 1; seq = sB; off = oB; len = lB; }

    off_t end = ::lseek(fd, 0, SEEK_END);
    if (end < static_cast<off_t>(kDataStart)) end = static_cast<off_t>(kDataStart);

    std::unique_ptr<Store> st(new Store);
    st->impl_->fd = fd;
    st->impl_->hdr = hdr;
    st->impl_->seq = seq;
    st->impl_->active_slot = slot;
    st->impl_->root = {off, len};
    st->impl_->file_size = static_cast<uint64_t>(end);
    return st;
}

const StoreHeader& Store::header() const { return impl_->hdr; }
Root Store::root() const { return impl_->root; }

uint64_t Store::append(const void* data, size_t n) {
    const uint64_t off = impl_->file_size;
    if (n == 0) return off;
    if (!pwrite_all(impl_->fd, data, n, off)) return 0;
    impl_->file_size += n;
    return off;
}

bool Store::read_at(uint64_t offset, void* buf, size_t n) {
    return pread_all(impl_->fd, buf, n, offset);
}

bool Store::commit(uint64_t root_offset, uint64_t root_len, const uint8_t key[kKeyBytes]) {
    // 1) data (blobs + manifest, already appended) must hit disk before the SB
    //    that references it — otherwise a crash could leave the SB pointing at
    //    bytes that never landed.
    if (durable_sync(impl_->fd) != 0) return false;
    // 2) write the *inactive* superblock with seq+1.
    const int next_slot = impl_->active_slot ^ 1;
    const uint64_t pos = next_slot == 0 ? kSbAOff : kSbBOff;
    const uint64_t next_seq = impl_->seq + 1;
    if (!write_sb(impl_->fd, pos, next_seq, root_offset, root_len, key)) return false;
    // 3) the commit point: once this fsync returns, the new SB is durable and
    //    becomes active on the next open; before it, the old SB still wins.
    if (durable_sync(impl_->fd) != 0) return false;

    impl_->seq = next_seq;
    impl_->active_slot = next_slot;
    impl_->root = {root_offset, root_len};
    return true;
}

}  // namespace sealpack
