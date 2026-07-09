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

}  // namespace

struct Pack::Impl {
    std::string            path;
    std::unique_ptr<Store> store;
    Index                  index;
    uint8_t                key[kKeyBytes] = {0};
    mutable int            last_err = SEALPACK_OK;
    ~Impl() { wipe(key, sizeof key); }
};

Pack::Pack() : impl_(new Impl) {}
Pack::~Pack() = default;

std::unique_ptr<Pack> Pack::create(const std::string& path, const std::string& password) {
    uint8_t salt[kSaltBytes];
    if (random_bytes(salt, kSaltBytes) != 0) return nullptr;
    KdfParams kdf;
    uint8_t key[kKeyBytes];
    if (derive_key(key, password.c_str(), salt, kdf) != 0) { wipe(key, kKeyBytes); return nullptr; }

    StoreHeader hdr{};
    std::memcpy(hdr.salt, salt, kSaltBytes);
    hdr.kdf = kdf;
    auto store = Store::create(path, hdr, key);
    if (!store) { wipe(key, kKeyBytes); return nullptr; }

    std::unique_ptr<Pack> pk(new Pack);
    pk->impl_->path = path;
    pk->impl_->store = std::move(store);
    std::memcpy(pk->impl_->key, key, kKeyBytes);
    wipe(key, kKeyBytes);
    return pk;
}

std::unique_ptr<Pack> Pack::open(const std::string& path, const std::string& password) {
    StoreHeader hdr{};
    if (!Store::read_header(path, &hdr)) return nullptr;
    uint8_t key[kKeyBytes];
    if (derive_key(key, password.c_str(), hdr.salt, hdr.kdf) != 0) { wipe(key, kKeyBytes); return nullptr; }
    auto store = Store::open(path, key);
    if (!store) { wipe(key, kKeyBytes); return nullptr; }  // wrong password
    Index idx;
    if (!load_manifest(*store, key, &idx)) { wipe(key, kKeyBytes); return nullptr; }

    std::unique_ptr<Pack> pk(new Pack);
    pk->impl_->path = path;
    pk->impl_->store = std::move(store);
    std::memcpy(pk->impl_->key, key, kKeyBytes);
    wipe(key, kKeyBytes);
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

    StoreHeader hdr = im.store->header();  // reuse salt/kdf → same key
    auto ns = Store::create(tmp, hdr, im.key);
    if (!ns) { im.last_err = SEALPACK_ERR_IO; return false; }

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

int Pack::last_error() const { return impl_->last_err; }

}  // namespace sealpack
