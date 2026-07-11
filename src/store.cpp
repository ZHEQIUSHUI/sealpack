#include "store.hpp"

#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>

namespace sealpack {
namespace {

// ---- fixed layout ----
constexpr uint64_t kHeaderSize = 24;   // magic8 + version4 + kdf(3*u32)
constexpr uint64_t kSlotSize   = kSaltBytes + kWrappedBytes;  // 16 + 72 = 88
constexpr uint64_t kSlotsOff   = kHeaderSize;                 // 24
constexpr uint64_t kSlotsSize  = static_cast<uint64_t>(kNumKeySlots) * kSlotSize;  // 704
constexpr uint64_t kSbSize     = 64;   // nonce24 + mac16 + cipher24
constexpr uint64_t kSbAOff     = kSlotsOff + kSlotsSize;      // 728
constexpr uint64_t kSbBOff     = kSbAOff + kSbSize;           // 792
constexpr uint64_t kDataStart  = kSbBOff + kSbSize;           // 856
constexpr uint32_t kVersion    = 2;    // v2 = key-wrapping (v1 was direct-derive)

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

// On macOS fsync only reaches the drive cache — F_FULLFSYNC hits the platter,
// which crash-durability needs there; Linux fdatasync is enough and cheaper.
int durable_sync(int fd) {
#if defined(__APPLE__)
    if (::fcntl(fd, F_FULLFSYNC) == 0) return 0;
    return ::fsync(fd);
#elif defined(__linux__)
    return ::fdatasync(fd);
#else
    return ::fsync(fd);
#endif
}

// Superblock on disk: nonce(24) | mac(16) | ciphertext(24 = seq|off|len), under
// the master key.
bool write_sb(int fd, uint64_t pos, uint64_t seq, uint64_t off, uint64_t len,
              const uint8_t master[kKeyBytes]) {
    uint8_t plain[24];
    enc_u64(plain + 0, seq);
    enc_u64(plain + 8, off);
    enc_u64(plain + 16, len);
    uint8_t sb[kSbSize];
    if (random_bytes(sb, kNonceBytes) != 0) return false;
    aead_encrypt(sb + kNonceBytes + kMacBytes, sb + kNonceBytes,
                 master, sb /*nonce*/, nullptr, 0, plain, sizeof plain);
    return pwrite_all(fd, sb, kSbSize, pos);
}
bool read_sb(int fd, uint64_t pos, const uint8_t master[kKeyBytes],
             uint64_t* seq, uint64_t* off, uint64_t* len) {
    uint8_t sb[kSbSize];
    if (!pread_all(fd, sb, kSbSize, pos)) return false;
    uint8_t plain[24];
    if (aead_decrypt(plain, sb + kNonceBytes, master, sb /*nonce*/, nullptr, 0,
                     sb + kNonceBytes + kMacBytes, sizeof plain) != 0)
        return false;  // wrong master key, or torn/corrupt write
    *seq = dec_u64(plain + 0);
    *off = dec_u64(plain + 8);
    *len = dec_u64(plain + 16);
    return true;
}

uint64_t slot_off(int idx) { return kSlotsOff + static_cast<uint64_t>(idx) * kSlotSize; }

}  // namespace

bool KeySlot::empty() const {
    uint8_t acc = 0;
    for (uint8_t b : salt) acc |= b;
    return acc == 0;  // all-zero salt marks an empty slot
}

struct Store::Impl {
    int       fd = -1;
    KdfParams kdf{};
    uint64_t  seq = 0;         // active superblock seq
    int       active_slot = 0; // 0 = SB A, 1 = SB B
    Root      root{};
    uint64_t  file_size = 0;   // append position (end of data region)
    ~Impl() { if (fd >= 0) ::close(fd); }
};

Store::Store() : impl_(new Impl) {}
Store::~Store() = default;

std::unique_ptr<Store> Store::create(const std::string& path,
                                     const uint8_t master[kKeyBytes],
                                     const KdfParams& kdf) {
    int fd = ::open(path.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) return nullptr;

    uint8_t h[kHeaderSize];
    std::memcpy(h, "SEALPACK", 8);
    enc_u32(h + 8, kVersion);
    enc_u32(h + 12, kdf.nb_blocks);
    enc_u32(h + 16, kdf.nb_passes);
    enc_u32(h + 20, kdf.nb_lanes);

    uint8_t empty_slots[kSlotsSize];
    std::memset(empty_slots, 0, sizeof empty_slots);

    // A holds active seq 1 (empty pack), B seq 0. First commit writes B seq 2.
    if (!pwrite_all(fd, h, kHeaderSize, 0) ||
        !pwrite_all(fd, empty_slots, kSlotsSize, kSlotsOff) ||
        !write_sb(fd, kSbAOff, 1, 0, 0, master) ||
        !write_sb(fd, kSbBOff, 0, 0, 0, master) ||
        durable_sync(fd) != 0) {
        ::close(fd);
        ::unlink(path.c_str());
        return nullptr;
    }

    std::unique_ptr<Store> st(new Store);
    st->impl_->fd = fd;
    st->impl_->kdf = kdf;
    st->impl_->seq = 1;
    st->impl_->active_slot = 0;
    st->impl_->root = {0, 0};
    st->impl_->file_size = kDataStart;
    return st;
}

// The header (magic, version, Argon2 params) is PLAINTEXT and is consumed by
// derive_key() BEFORE any password/MAC check — so a crafted or corrupt pack's
// params reach monocypher unauthenticated. Reject degenerate values here:
// nb_lanes==0 divides-by-zero in crypto_argon2 (SIGFPE on open), and an absurd
// nb_blocks would ask derive_key for a multi-TB work area. This is the single
// choke point for both open() and read_meta(), so validating once covers both.
constexpr uint32_t kMaxKdfLanes  = 64;         // single-threaded anyway; bound it
constexpr uint32_t kMaxKdfBlocks = 1u << 22;   // 4 GiB work area ceiling (default is 64 MiB)

static bool read_header_kdf(int fd, KdfParams* kdf) {
    uint8_t h[kHeaderSize];
    if (!pread_all(fd, h, kHeaderSize, 0) || std::memcmp(h, "SEALPACK", 8) != 0 ||
        dec_u32(h + 8) != kVersion)
        return false;
    const uint32_t nb_blocks = dec_u32(h + 12);
    const uint32_t nb_passes = dec_u32(h + 16);
    const uint32_t nb_lanes  = dec_u32(h + 20);
    if (nb_lanes == 0 || nb_lanes > kMaxKdfLanes ||   // 0 → divide-by-zero in argon2
        nb_passes == 0 ||
        nb_blocks < 8u * nb_lanes ||                  // monocypher's stated minimum
        nb_blocks > kMaxKdfBlocks)                    // cap the work-area allocation
        return false;
    kdf->nb_blocks = nb_blocks;
    kdf->nb_passes = nb_passes;
    kdf->nb_lanes  = nb_lanes;
    return true;
}

bool Store::read_meta(const std::string& path, KdfParams* kdf, KeySlot slots[kNumKeySlots]) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    bool ok = read_header_kdf(fd, kdf);
    for (int i = 0; ok && i < kNumKeySlots; ++i) {
        uint8_t buf[kSlotSize];
        if (!pread_all(fd, buf, kSlotSize, slot_off(i))) { ok = false; break; }
        std::memcpy(slots[i].salt, buf, kSaltBytes);
        std::memcpy(slots[i].wrapped, buf + kSaltBytes, kWrappedBytes);
    }
    ::close(fd);
    return ok;
}

std::unique_ptr<Store> Store::open(const std::string& path, const uint8_t master[kKeyBytes]) {
    int fd = ::open(path.c_str(), O_RDWR);
    if (fd < 0) return nullptr;
    KdfParams kdf;
    if (!read_header_kdf(fd, &kdf)) { ::close(fd); return nullptr; }

    uint64_t sA, oA, lA, sB, oB, lB;
    bool okA = read_sb(fd, kSbAOff, master, &sA, &oA, &lA);
    bool okB = read_sb(fd, kSbBOff, master, &sB, &oB, &lB);
    if (!okA && !okB) { ::close(fd); return nullptr; }  // bad master key / both torn

    int slot; uint64_t seq, off, len;
    if (okA && (!okB || sA >= sB)) { slot = 0; seq = sA; off = oA; len = lA; }
    else                           { slot = 1; seq = sB; off = oB; len = lB; }

    off_t end = ::lseek(fd, 0, SEEK_END);
    if (end < static_cast<off_t>(kDataStart)) end = static_cast<off_t>(kDataStart);

    std::unique_ptr<Store> st(new Store);
    st->impl_->fd = fd;
    st->impl_->kdf = kdf;
    st->impl_->seq = seq;
    st->impl_->active_slot = slot;
    st->impl_->root = {off, len};
    st->impl_->file_size = static_cast<uint64_t>(end);
    return st;
}

const KdfParams& Store::kdf() const { return impl_->kdf; }
Root Store::root() const { return impl_->root; }

KeySlot Store::slot(int idx) const {
    KeySlot s;
    if (idx < 0 || idx >= kNumKeySlots) return s;
    uint8_t buf[kSlotSize];
    if (pread_all(impl_->fd, buf, kSlotSize, slot_off(idx))) {
        std::memcpy(s.salt, buf, kSaltBytes);
        std::memcpy(s.wrapped, buf + kSaltBytes, kWrappedBytes);
    }
    return s;
}

bool Store::write_slot(int idx, const KeySlot& s) {
    if (idx < 0 || idx >= kNumKeySlots) return false;
    uint8_t buf[kSlotSize];
    std::memcpy(buf, s.salt, kSaltBytes);
    std::memcpy(buf + kSaltBytes, s.wrapped, kWrappedBytes);
    return pwrite_all(impl_->fd, buf, kSlotSize, slot_off(idx)) &&
           durable_sync(impl_->fd) == 0;
}

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

bool Store::commit(uint64_t root_offset, uint64_t root_len, const uint8_t master[kKeyBytes]) {
    if (durable_sync(impl_->fd) != 0) return false;             // data before the SB
    const int next_slot = impl_->active_slot ^ 1;
    const uint64_t pos = next_slot == 0 ? kSbAOff : kSbBOff;
    const uint64_t next_seq = impl_->seq + 1;
    if (!write_sb(impl_->fd, pos, next_seq, root_offset, root_len, master)) return false;
    if (durable_sync(impl_->fd) != 0) return false;             // the commit point
    impl_->seq = next_seq;
    impl_->active_slot = next_slot;
    impl_->root = {root_offset, root_len};
    return true;
}

}  // namespace sealpack
