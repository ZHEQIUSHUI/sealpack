#include "sealpack.hpp"

#include <cstdio>
#include <cstring>
#include <ctime>

#include <unistd.h>

#include "crypto.hpp"
#include "index.hpp"
#include "sealpack.h"  // status codes shared with the C API
#include "store.hpp"

namespace sealpack {
namespace {

uint64_t now_sec() { return static_cast<uint64_t>(::time(nullptr)); }

// A stored record = nonce | mac | ciphertext. So enc_size = 40 + plain_size.
constexpr size_t kRecOverhead = kNonceBytes + kMacBytes;

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
    ::unlink(tmp.c_str());

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

    if (std::rename(tmp.c_str(), im.path.c_str()) != 0) {  // atomic replace
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

int Pack::last_error() const { return impl_->last_err; }

}  // namespace sealpack
