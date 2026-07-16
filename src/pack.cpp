#include "sealpack.hpp"

#include <cstring>

#include "crypto.hpp"
#include "index.hpp"
#include "os.hpp"
#include "sealpack.h"  // status codes shared with the C API
#include "store.hpp"

namespace sealpack {
namespace {

uint64_t now_sec() { return os::now_seconds(); }

// A stored record = nonce | mac | ciphertext. So enc_size = 40 + plain_size.
constexpr size_t kRecOverhead = kNonceBytes + kMacBytes;

// ---- patch (incremental update) format ----
// A .spkpatch turns one pack's logical content into another's, carrying only the
// files that differ. Layout: "SPKPATCH" + version + a length-prefixed META record
// then one record per shipped blob, every record AEAD-sealed under the BASE pack's
// master key (nonce|mac|cipher). META plaintext:
//   base_fp(32)                                  BLAKE2b of the base's logical state
//   u32 nblobs; { hash(32); u64 plain_len }      shipped blobs, ordered by hash
//   u32 nputs;  { u32 plen; path; hash(32) }     path -> content assignments
//   u32 ndels;  { u32 plen; path }               removed paths
constexpr char     kPatchMagic[8] = {'S','P','K','P','A','T','C','H'};
constexpr uint32_t kPatchVersion  = 1;

void put_u32(std::string& s, uint32_t v) { for (int i = 0; i < 4; ++i) s.push_back(char((v >> (8 * i)) & 0xff)); }
void put_u64(std::string& s, uint64_t v) { for (int i = 0; i < 8; ++i) s.push_back(char((v >> (8 * i)) & 0xff)); }
bool get_u32(const uint8_t* d, size_t n, size_t& p, uint32_t& v) {
    if (p + 4 > n) return false;
    v = uint32_t(d[p]) | uint32_t(d[p+1]) << 8 | uint32_t(d[p+2]) << 16 | uint32_t(d[p+3]) << 24;
    p += 4; return true;
}
bool get_u64(const uint8_t* d, size_t n, size_t& p, uint64_t& v) {
    if (p + 8 > n) return false;
    v = 0; for (int i = 0; i < 8; ++i) v |= uint64_t(d[p+i]) << (8 * i);
    p += 8; return true;
}
bool get_bytes(const uint8_t* d, size_t n, size_t& p, size_t len, std::string& out) {
    if (p + len > n) return false;
    out.assign(reinterpret_cast<const char*>(d) + p, len); p += len; return true;
}

// Canonical hash of a pack's LOGICAL content (path -> content hash), ignoring
// physical layout (offsets, mtimes). Two logically-identical packs — even if one
// was compacted — fingerprint the same, so a patch still applies across copies.
void logical_fingerprint(const Index& idx, uint8_t out[kHashBytes]) {
    std::string s;
    put_u32(s, static_cast<uint32_t>(idx.paths.size()));
    for (const auto& kv : idx.paths) {   // std::map → sorted, deterministic
        put_u32(s, static_cast<uint32_t>(kv.first.size()));
        s += kv.first;
        s += kv.second.hash;             // 32-byte content hash
    }
    content_hash(out, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// One AEAD record (nonce|mac|cipher) under `key`, into a fresh string. Empty on
// RNG failure.
std::string seal_record(const uint8_t key[kKeyBytes], const void* data, size_t n) {
    std::string rec(kRecOverhead + n, '\0');
    uint8_t* p = reinterpret_cast<uint8_t*>(&rec[0]);
    if (random_bytes(p, kNonceBytes) != 0) return std::string();
    aead_encrypt(p + kRecOverhead, p + kNonceBytes, key, p, nullptr, 0,
                 static_cast<const uint8_t*>(data), n);
    return rec;
}
bool open_record(const uint8_t key[kKeyBytes], const uint8_t* rec, size_t enc_len, std::string* out) {
    if (enc_len < kRecOverhead) return false;
    const size_t plain = enc_len - kRecOverhead;
    out->assign(plain, '\0');
    return aead_decrypt(reinterpret_cast<uint8_t*>(&(*out)[0]), rec + kNonceBytes, key, rec,
                        nullptr, 0, rec + kRecOverhead, plain) == 0;
}

// Encrypt `data` and append it as one record; fill *out (refcount left 0).
bool encrypt_append(Store& st, const uint8_t key[kKeyBytes],
                    const void* data, size_t n, BlobRef* out) {
    std::string rec(kRecOverhead + n, '\0');
    uint8_t* p = reinterpret_cast<uint8_t*>(&rec[0]);
    if (random_bytes(p, kNonceBytes) != 0) return false;
    aead_encrypt(p + kRecOverhead, p + kNonceBytes, key, p, nullptr, 0,
                 static_cast<const uint8_t*>(data), n);
    uint64_t off = st.append(rec.data(), rec.size());
    if (off == 0) return false;
    out->offset = off;
    out->enc_size = rec.size();
    out->plain_size = n;
    out->refcount = 0;
    return true;
}

// Read + decrypt a record into *out. false = I/O or auth failure.
bool read_decrypt(Store& st, const uint8_t key[kKeyBytes], const BlobRef& ref,
                  std::string* out) {
    std::string rec(ref.enc_size, '\0');
    if (!st.read_at(ref.offset, &rec[0], ref.enc_size)) return false;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(rec.data());
    out->assign(ref.plain_size, '\0');
    return aead_decrypt(reinterpret_cast<uint8_t*>(&(*out)[0]), p + kNonceBytes, key,
                        p, nullptr, 0, p + kRecOverhead, ref.plain_size) == 0;
}

// Serialize + encrypt the index as the manifest, append it, and commit.
bool flush_manifest(Store& st, const uint8_t key[kKeyBytes], const Index& idx) {
    std::string plain = serialize(idx);
    std::string rec(kRecOverhead + plain.size(), '\0');
    uint8_t* p = reinterpret_cast<uint8_t*>(&rec[0]);
    if (random_bytes(p, kNonceBytes) != 0) return false;
    aead_encrypt(p + kRecOverhead, p + kNonceBytes, key, p, nullptr, 0,
                 reinterpret_cast<const uint8_t*>(plain.data()), plain.size());
    uint64_t off = st.append(rec.data(), rec.size());
    if (off == 0) return false;
    return st.commit(off, rec.size(), key);
}

// Read + decrypt the manifest the active superblock points at.
bool load_manifest(Store& st, const uint8_t key[kKeyBytes], Index* out) {
    Root r = st.root();
    if (r.len == 0) { *out = Index{}; return true; }  // fresh pack
    if (r.len < kRecOverhead) return false;
    std::string rec(r.len, '\0');
    if (!st.read_at(r.offset, &rec[0], r.len)) return false;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(rec.data());
    const size_t plain_size = r.len - kRecOverhead;
    std::string plain(plain_size, '\0');
    if (aead_decrypt(reinterpret_cast<uint8_t*>(&plain[0]), p + kNonceBytes, key, p,
                     nullptr, 0, p + kRecOverhead, plain_size) != 0)
        return false;
    return deserialize(reinterpret_cast<const uint8_t*>(plain.data()), plain.size(), out);
}

// ---- key wrapping: a password wraps the random master key into a key slot ----

// Fill slot.salt + slot.wrapped so `password` unlocks `master`. Fresh random
// salt + nonce each call, so rewrapping the same master under the same password
// still yields different ciphertext.
bool wrap_master(KeySlot* slot, const uint8_t master[kKeyBytes],
                 const std::string& password, const KdfParams& kdf) {
    if (random_bytes(slot->salt, kSaltBytes) != 0) return false;
    uint8_t kek[kKeyBytes];
    if (derive_key(kek, password.c_str(), slot->salt, kdf) != 0) { wipe(kek, kKeyBytes); return false; }
    uint8_t* nonce  = slot->wrapped;
    uint8_t* mac    = slot->wrapped + kNonceBytes;
    uint8_t* cipher = slot->wrapped + kNonceBytes + kMacBytes;
    bool ok = random_bytes(nonce, kNonceBytes) == 0;
    if (ok) aead_encrypt(cipher, mac, kek, nonce, nullptr, 0, master, kKeyBytes);
    wipe(kek, kKeyBytes);
    return ok;
}

// Recover `master` from a slot using `password`. false = empty slot or wrong
// password (AEAD auth fails — the "no password, no plaintext" guarantee).
bool unwrap_master(uint8_t master[kKeyBytes], const KeySlot& slot,
                   const std::string& password, const KdfParams& kdf) {
    if (slot.empty()) return false;
    uint8_t kek[kKeyBytes];
    if (derive_key(kek, password.c_str(), slot.salt, kdf) != 0) { wipe(kek, kKeyBytes); return false; }
    const uint8_t* nonce  = slot.wrapped;
    const uint8_t* mac    = slot.wrapped + kNonceBytes;
    const uint8_t* cipher = slot.wrapped + kNonceBytes + kMacBytes;
    int rc = aead_decrypt(master, mac, kek, nonce, nullptr, 0, cipher, kKeyBytes);
    wipe(kek, kKeyBytes);
    return rc == 0;
}

}  // namespace

struct Pack::Impl {
    std::string            path;
    std::unique_ptr<Store> store;
    Index                  index;
    uint8_t                key[kKeyBytes] = {0};  // random master key (unwrapped from a slot)
    int                    opened_slot = 0;       // which key slot the password opened
    mutable int            last_err = SEALPACK_OK;
    ~Impl() { wipe(key, sizeof key); }
};

Pack::Pack() : impl_(new Impl) {}
Pack::~Pack() = default;

std::unique_ptr<Pack> Pack::create(const std::string& path, const std::string& password) {
    uint8_t master[kKeyBytes];
    if (random_bytes(master, kKeyBytes) != 0) return nullptr;  // random master key
    KdfParams kdf;
    KeySlot slot0;
    if (!wrap_master(&slot0, master, password, kdf)) { wipe(master, kKeyBytes); return nullptr; }

    auto store = Store::create(path, master, kdf);
    if (!store || !store->write_slot(0, slot0)) { wipe(master, kKeyBytes); return nullptr; }

    std::unique_ptr<Pack> pk(new Pack);
    pk->impl_->path = path;
    pk->impl_->store = std::move(store);
    std::memcpy(pk->impl_->key, master, kKeyBytes);
    pk->impl_->opened_slot = 0;
    wipe(master, kKeyBytes);
    return pk;
}

std::unique_ptr<Pack> Pack::open(const std::string& path, const std::string& password) {
    KdfParams kdf;
    KeySlot slots[kNumKeySlots];
    if (!Store::read_meta(path, &kdf, slots)) return nullptr;

    uint8_t master[kKeyBytes];
    int opened = -1;
    for (int i = 0; i < kNumKeySlots; ++i)
        if (unwrap_master(master, slots[i], password, kdf)) { opened = i; break; }
    if (opened < 0) { wipe(master, kKeyBytes); return nullptr; }  // wrong password / no matching slot

    auto store = Store::open(path, master);
    if (!store) { wipe(master, kKeyBytes); return nullptr; }
    Index idx;
    if (!load_manifest(*store, master, &idx)) { wipe(master, kKeyBytes); return nullptr; }

    std::unique_ptr<Pack> pk(new Pack);
    pk->impl_->path = path;
    pk->impl_->store = std::move(store);
    std::memcpy(pk->impl_->key, master, kKeyBytes);
    pk->impl_->opened_slot = opened;
    wipe(master, kKeyBytes);
    pk->impl_->index = std::move(idx);
    return pk;
}

bool Pack::put(const std::string& path, const void* data, size_t size) {
    Impl& im = *impl_;
    std::string norm = normalize_path(path);
    if (norm.empty()) { im.last_err = SEALPACK_ERR_ARG; return false; }

    uint8_t hbuf[kHashBytes];
    content_hash(hbuf, static_cast<const uint8_t*>(data), size);
    std::string hash(reinterpret_cast<const char*>(hbuf), kHashBytes);

    auto bit = im.index.blobs.find(hash);
    if (bit == im.index.blobs.end()) {  // new content -> store one blob
        BlobRef ref;
        if (!encrypt_append(*im.store, im.key, data, size, &ref)) {
            im.last_err = SEALPACK_ERR_IO; return false;
        }
        bit = im.index.blobs.emplace(hash, ref).first;
    }
    // drop the old blob's refcount if this path was already taken
    auto pit = im.index.paths.find(norm);
    if (pit != im.index.paths.end()) {
        auto oldit = im.index.blobs.find(pit->second.hash);
        if (oldit != im.index.blobs.end() && oldit->second.refcount > 0)
            oldit->second.refcount--;
    }
    bit->second.refcount++;
    im.index.paths[norm] = PathEntry{hash, now_sec()};
    im.last_err = SEALPACK_OK;
    return true;
}

bool Pack::put(const std::string& path, const std::string& data) {
    return put(path, data.data(), data.size());
}

bool Pack::get(const std::string& path, std::string* out) const {
    Impl& im = *impl_;
    auto pit = im.index.paths.find(normalize_path(path));
    if (pit == im.index.paths.end()) { im.last_err = SEALPACK_ERR_NOTFOUND; return false; }
    auto bit = im.index.blobs.find(pit->second.hash);
    if (bit == im.index.blobs.end()) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }
    if (!read_decrypt(*im.store, im.key, bit->second, out)) {
        im.last_err = SEALPACK_ERR_AUTH; return false;
    }
    im.last_err = SEALPACK_OK;
    return true;
}

bool Pack::del(const std::string& path) {
    Impl& im = *impl_;
    auto pit = im.index.paths.find(normalize_path(path));
    if (pit == im.index.paths.end()) { im.last_err = SEALPACK_ERR_NOTFOUND; return false; }
    auto bit = im.index.blobs.find(pit->second.hash);
    if (bit != im.index.blobs.end() && bit->second.refcount > 0) bit->second.refcount--;
    im.index.paths.erase(pit);
    im.last_err = SEALPACK_OK;
    return true;
}

bool Pack::has(const std::string& path) const {
    return impl_->index.paths.count(normalize_path(path)) > 0;
}

bool Pack::move(const std::string& from, const std::string& to) {
    Impl& im = *impl_;
    std::string f = normalize_path(from), t = normalize_path(to);
    if (f.empty() || t.empty()) { im.last_err = SEALPACK_ERR_ARG; return false; }
    auto fit = im.index.paths.find(f);
    if (fit == im.index.paths.end()) { im.last_err = SEALPACK_ERR_NOTFOUND; return false; }
    if (im.index.paths.count(t)) { im.last_err = SEALPACK_ERR_EXISTS; return false; }
    im.index.paths[t] = fit->second;   // hash + mtime preserved; blob untouched
    im.index.paths.erase(fit);
    im.last_err = SEALPACK_OK;
    return true;
}

bool Pack::copy(const std::string& from, const std::string& to) {
    Impl& im = *impl_;
    std::string f = normalize_path(from), t = normalize_path(to);
    if (f.empty() || t.empty()) { im.last_err = SEALPACK_ERR_ARG; return false; }
    auto fit = im.index.paths.find(f);
    if (fit == im.index.paths.end()) { im.last_err = SEALPACK_ERR_NOTFOUND; return false; }
    if (im.index.paths.count(t)) { im.last_err = SEALPACK_ERR_EXISTS; return false; }
    auto bit = im.index.blobs.find(fit->second.hash);
    if (bit == im.index.blobs.end()) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }
    bit->second.refcount++;            // same blob, no bytes copied
    im.index.paths[t] = PathEntry{fit->second.hash, now_sec()};
    im.last_err = SEALPACK_OK;
    return true;
}

bool Pack::stat(const std::string& path, Entry* out) const {
    Impl& im = *impl_;
    auto pit = im.index.paths.find(normalize_path(path));
    if (pit == im.index.paths.end()) { im.last_err = SEALPACK_ERR_NOTFOUND; return false; }
    auto bit = im.index.blobs.find(pit->second.hash);
    if (bit == im.index.blobs.end()) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }
    out->path = pit->first;
    out->size = bit->second.plain_size;
    out->mtime = pit->second.mtime;
    im.last_err = SEALPACK_OK;
    return true;
}

std::vector<Pack::Entry> Pack::list() const {
    Impl& im = *impl_;
    std::vector<Entry> v;
    v.reserve(im.index.paths.size());
    for (const auto& kv : im.index.paths) {  // std::map -> sorted by path
        auto bit = im.index.blobs.find(kv.second.hash);
        uint64_t sz = bit != im.index.blobs.end() ? bit->second.plain_size : 0;
        v.push_back(Entry{kv.first, sz, kv.second.mtime});
    }
    return v;
}

bool Pack::commit() {
    Impl& im = *impl_;
    if (!flush_manifest(*im.store, im.key, im.index)) { im.last_err = SEALPACK_ERR_IO; return false; }
    im.last_err = SEALPACK_OK;
    return true;
}

bool Pack::compact() {
    Impl& im = *impl_;
    const std::string tmp = im.path + ".compact.tmp";
    os::remove_file(tmp.c_str());

    auto ns = Store::create(tmp, im.key, im.store->kdf());  // same master key, fresh file
    if (!ns) { im.last_err = SEALPACK_ERR_IO; return false; }
    for (int i = 0; i < kNumKeySlots; ++i) {  // carry over every password slot
        KeySlot s = im.store->slot(i);
        if (!s.empty() && !ns->write_slot(i, s)) { im.last_err = SEALPACK_ERR_IO; return false; }
    }

    Index nidx;
    for (const auto& kv : im.index.blobs) {
        if (kv.second.refcount == 0) continue;  // drop unreferenced garbage
        std::string rec(kv.second.enc_size, '\0');
        if (!im.store->read_at(kv.second.offset, &rec[0], rec.size())) {
            im.last_err = SEALPACK_ERR_IO; return false;
        }
        uint64_t noff = ns->append(rec.data(), rec.size());
        if (noff == 0) { im.last_err = SEALPACK_ERR_IO; return false; }
        BlobRef nref = kv.second;
        nref.offset = noff;
        nidx.blobs[kv.first] = nref;
    }
    for (const auto& kv : im.index.paths)
        if (nidx.blobs.count(kv.second.hash)) nidx.paths[kv.first] = kv.second;

    if (!flush_manifest(*ns, im.key, nidx)) { im.last_err = SEALPACK_ERR_IO; return false; }
    ns.reset();          // close the new file
    im.store.reset();    // close the old file

    if (!os::rename_replace(tmp.c_str(), im.path.c_str())) {  // atomic replace
        im.last_err = SEALPACK_ERR_IO; return false;
    }
    auto reopened = Store::open(im.path, im.key);
    if (!reopened) { im.last_err = SEALPACK_ERR_IO; return false; }
    im.store = std::move(reopened);
    im.index = std::move(nidx);
    im.last_err = SEALPACK_OK;
    return true;
}

bool Pack::verify_password(const std::string& password) const {
    Impl& im = *impl_;
    KeySlot s = im.store->slot(im.opened_slot);
    uint8_t m[kKeyBytes];
    // True only if `password` unwraps THIS handle's slot to the same master key.
    bool ok = unwrap_master(m, s, password, im.store->kdf()) &&
              ct_equal(m, im.key, kKeyBytes) == 1;
    wipe(m, kKeyBytes);
    return ok;
}

bool Pack::rekey(const std::string& new_password) {
    Impl& im = *impl_;
    KeySlot slot;
    if (!wrap_master(&slot, im.key, new_password, im.store->kdf()) ||
        !im.store->write_slot(im.opened_slot, slot)) {
        im.last_err = SEALPACK_ERR_IO; return false;
    }
    im.last_err = SEALPACK_OK;
    return true;
}

bool Pack::create_patch(const Pack& newer, std::string* out) const {
    Impl& base = *impl_;            // *this = old/base state
    Impl& tgt  = *newer.impl_;      // newer = target state

    // Logical delta: paths in `newer` that are new or point at different content
    // are "puts" (ship the blob once, deduped by hash); paths gone from `newer`
    // are "dels".
    std::vector<std::pair<std::string, std::string>> puts;   // (path, content hash)
    std::vector<std::string>                         dels;
    std::map<std::string, std::string>               blobs;  // hash -> plaintext (deduped)
    for (const auto& kv : tgt.index.paths) {
        const std::string& path = kv.first;
        const std::string& hash = kv.second.hash;
        auto bit = base.index.paths.find(path);
        if (bit != base.index.paths.end() && bit->second.hash == hash) continue;  // unchanged
        puts.emplace_back(path, hash);
        if (blobs.find(hash) == blobs.end()) {
            std::string plain;
            if (!newer.get(path, &plain)) { base.last_err = SEALPACK_ERR_IO; return false; }
            blobs.emplace(hash, std::move(plain));
        }
    }
    for (const auto& kv : base.index.paths)
        if (tgt.index.paths.find(kv.first) == tgt.index.paths.end())
            dels.push_back(kv.first);

    // META plaintext.
    uint8_t base_fp[kHashBytes];
    logical_fingerprint(base.index, base_fp);
    std::string meta;
    meta.append(reinterpret_cast<const char*>(base_fp), kHashBytes);
    put_u32(meta, static_cast<uint32_t>(blobs.size()));
    for (const auto& kv : blobs) { meta += kv.first; put_u64(meta, kv.second.size()); }
    put_u32(meta, static_cast<uint32_t>(puts.size()));
    for (const auto& pr : puts) { put_u32(meta, static_cast<uint32_t>(pr.first.size())); meta += pr.first; meta += pr.second; }
    put_u32(meta, static_cast<uint32_t>(dels.size()));
    for (const auto& d : dels) { put_u32(meta, static_cast<uint32_t>(d.size())); meta += d; }

    // Seal META + each blob under the BASE master key, in the same hash order.
    std::string meta_rec = seal_record(base.key, meta.data(), meta.size());
    if (meta_rec.empty()) { base.last_err = SEALPACK_ERR_IO; return false; }
    std::string body;
    body.append(kPatchMagic, 8);
    put_u32(body, kPatchVersion);
    put_u64(body, meta_rec.size());
    body += meta_rec;
    for (const auto& kv : blobs) {
        std::string rec = seal_record(base.key, kv.second.data(), kv.second.size());
        if (rec.empty()) { base.last_err = SEALPACK_ERR_IO; return false; }
        body += rec;
    }
    *out = std::move(body);
    base.last_err = SEALPACK_OK;
    return true;
}

bool Pack::apply_patch(const std::string& patch) {
    Impl& im = *impl_;
    const uint8_t* d = reinterpret_cast<const uint8_t*>(patch.data());
    const size_t   n = patch.size();

    size_t p = 0;
    uint32_t ver; uint64_t meta_len;
    if (n < 8 || std::memcmp(d, kPatchMagic, 8) != 0) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }
    p = 8;
    if (!get_u32(d, n, p, ver) || ver != kPatchVersion ||
        !get_u64(d, n, p, meta_len) || p + meta_len > n) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }

    std::string meta;   // wrong pack (master key mismatch) or tampering → AEAD fails
    if (!open_record(im.key, d + p, meta_len, &meta)) { im.last_err = SEALPACK_ERR_AUTH; return false; }
    p += meta_len;

    const uint8_t* m = reinterpret_cast<const uint8_t*>(meta.data());
    const size_t   mn = meta.size();
    size_t mp = 0;
    std::string base_fp;
    if (!get_bytes(m, mn, mp, kHashBytes, base_fp)) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }

    uint8_t cur_fp[kHashBytes];   // refuse unless our logical state == the patch's base
    logical_fingerprint(im.index, cur_fp);
    if (std::memcmp(base_fp.data(), cur_fp, kHashBytes) != 0) { im.last_err = SEALPACK_ERR_PATCH; return false; }

    uint32_t nblobs;
    if (!get_u32(m, mn, mp, nblobs)) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }
    std::vector<std::pair<std::string, uint64_t>> bloblist;
    for (uint32_t i = 0; i < nblobs; ++i) {
        std::string h; uint64_t len;
        if (!get_bytes(m, mn, mp, kHashBytes, h) || !get_u64(m, mn, mp, len)) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }
        bloblist.emplace_back(std::move(h), len);
    }
    uint32_t nputs;
    if (!get_u32(m, mn, mp, nputs)) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }
    std::vector<std::pair<std::string, std::string>> puts;
    for (uint32_t i = 0; i < nputs; ++i) {
        uint32_t plen; std::string path, h;
        if (!get_u32(m, mn, mp, plen) || !get_bytes(m, mn, mp, plen, path) ||
            !get_bytes(m, mn, mp, kHashBytes, h)) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }
        puts.emplace_back(std::move(path), std::move(h));
    }
    uint32_t ndels;
    if (!get_u32(m, mn, mp, ndels)) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }
    std::vector<std::string> dels;
    for (uint32_t i = 0; i < ndels; ++i) {
        uint32_t plen; std::string path;
        if (!get_u32(m, mn, mp, plen) || !get_bytes(m, mn, mp, plen, path)) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }
        dels.push_back(std::move(path));
    }

    // Decrypt the blob records (in `bloblist` order) and verify each matches its
    // declared content hash (the CAS invariant), so a corrupt patch can't slip in.
    std::map<std::string, std::string> blobs;
    for (const auto& b : bloblist) {
        const uint64_t enc_len = kRecOverhead + b.second;
        if (p + enc_len > n) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }
        std::string plain;
        if (!open_record(im.key, d + p, static_cast<size_t>(enc_len), &plain)) { im.last_err = SEALPACK_ERR_AUTH; return false; }
        p += enc_len;
        uint8_t hh[kHashBytes];
        content_hash(hh, reinterpret_cast<const uint8_t*>(plain.data()), plain.size());
        if (std::memcmp(hh, b.first.data(), kHashBytes) != 0) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }
        blobs.emplace(b.first, std::move(plain));
    }

    // Apply, then one atomic commit. (put/del buffer; commit is the crash-safe point.)
    for (const auto& pr : puts) {
        auto it = blobs.find(pr.second);
        if (it == blobs.end()) { im.last_err = SEALPACK_ERR_CORRUPT; return false; }  // put references an unshipped blob
        if (!put(pr.first, it->second)) return false;
    }
    for (const auto& path : dels)
        if (!del(path) && im.last_err != SEALPACK_ERR_NOTFOUND) return false;   // already-absent is fine
    if (!commit()) return false;
    im.last_err = SEALPACK_OK;
    return true;
}

int Pack::last_error() const { return impl_->last_err; }

}  // namespace sealpack
