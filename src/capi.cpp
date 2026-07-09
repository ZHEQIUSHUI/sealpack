// C ABI wrapper over the C++ Pack. The handle owns a Pack plus small caches
// that keep list()/stat() path strings alive for the C `const char*` contract.

#include "sealpack.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <vector>

#include "sealpack.hpp"

struct sealpack_handle {
    std::unique_ptr<sealpack::Pack>    pack;
    std::vector<sealpack::Pack::Entry> list_cache;  // keeps list() paths alive
    std::string                        stat_path;   // keeps a stat() path alive
};

namespace {
thread_local int g_open_err = SEALPACK_OK;
}

extern "C" {

sealpack_t* sealpack_create(const char* path, const char* password) {
    if (!path || !password) { g_open_err = SEALPACK_ERR_ARG; return nullptr; }
    auto pack = sealpack::Pack::create(path, password);
    if (!pack) { g_open_err = SEALPACK_ERR_IO; return nullptr; }
    auto* h = new (std::nothrow) sealpack_handle;
    if (!h) { g_open_err = SEALPACK_ERR_NOMEM; return nullptr; }
    h->pack = std::move(pack);
    g_open_err = SEALPACK_OK;
    return h;
}

sealpack_t* sealpack_open(const char* path, const char* password) {
    if (!path || !password) { g_open_err = SEALPACK_ERR_ARG; return nullptr; }
    auto pack = sealpack::Pack::open(path, password);
    if (!pack) { g_open_err = SEALPACK_ERR_AUTH; return nullptr; }
    auto* h = new (std::nothrow) sealpack_handle;
    if (!h) { g_open_err = SEALPACK_ERR_NOMEM; return nullptr; }
    h->pack = std::move(pack);
    g_open_err = SEALPACK_OK;
    return h;
}

int  sealpack_open_error(void) { return g_open_err; }
void sealpack_close(sealpack_t* sp) { delete sp; }

int sealpack_put(sealpack_t* sp, const char* path, const void* data, size_t size) {
    if (!sp || !path || (!data && size)) return SEALPACK_ERR_ARG;
    return sp->pack->put(path, data, size) ? SEALPACK_OK : sp->pack->last_error();
}

int sealpack_get(sealpack_t* sp, const char* path, void** out, size_t* size) {
    if (!sp || !path || !out || !size) return SEALPACK_ERR_ARG;
    std::string buf;
    if (!sp->pack->get(path, &buf)) return sp->pack->last_error();
    void* m = std::malloc(buf.empty() ? 1 : buf.size());
    if (!m) return SEALPACK_ERR_NOMEM;
    std::memcpy(m, buf.data(), buf.size());
    *out = m;
    *size = buf.size();
    return SEALPACK_OK;
}

int sealpack_del(sealpack_t* sp, const char* path) {
    if (!sp || !path) return SEALPACK_ERR_ARG;
    return sp->pack->del(path) ? SEALPACK_OK : sp->pack->last_error();
}

int sealpack_has(sealpack_t* sp, const char* path) {
    return (sp && path && sp->pack->has(path)) ? 1 : 0;
}

int sealpack_move(sealpack_t* sp, const char* from, const char* to) {
    if (!sp || !from || !to) return SEALPACK_ERR_ARG;
    return sp->pack->move(from, to) ? SEALPACK_OK : sp->pack->last_error();
}

int sealpack_copy(sealpack_t* sp, const char* from, const char* to) {
    if (!sp || !from || !to) return SEALPACK_ERR_ARG;
    return sp->pack->copy(from, to) ? SEALPACK_OK : sp->pack->last_error();
}

int sealpack_commit(sealpack_t* sp) {
    if (!sp) return SEALPACK_ERR_ARG;
    return sp->pack->commit() ? SEALPACK_OK : sp->pack->last_error();
}

int sealpack_compact(sealpack_t* sp) {
    if (!sp) return SEALPACK_ERR_ARG;
    return sp->pack->compact() ? SEALPACK_OK : sp->pack->last_error();
}

int sealpack_rekey(sealpack_t* sp, const char* new_password) {
    if (!sp || !new_password) return SEALPACK_ERR_ARG;
    return sp->pack->rekey(new_password) ? SEALPACK_OK : sp->pack->last_error();
}

int sealpack_addkey(sealpack_t* sp, const char* new_password) {
    if (!sp || !new_password) return SEALPACK_ERR_ARG;
    int idx = sp->pack->addkey(new_password);
    return idx >= 0 ? idx : sp->pack->last_error();  // >=0 = new slot index, else error
}

int sealpack_rmkey(sealpack_t* sp, int slot_idx) {
    if (!sp) return SEALPACK_ERR_ARG;
    return sp->pack->rmkey(slot_idx) ? SEALPACK_OK : sp->pack->last_error();
}

int sealpack_num_keys(sealpack_t* sp) {
    if (!sp) return SEALPACK_ERR_ARG;
    return sp->pack->num_keys();
}

int sealpack_list(sealpack_t* sp, sealpack_entry** entries, size_t* count) {
    if (!sp || !entries || !count) return SEALPACK_ERR_ARG;
    sp->list_cache = sp->pack->list();
    const size_t n = sp->list_cache.size();
    auto* arr = static_cast<sealpack_entry*>(std::malloc((n ? n : 1) * sizeof(sealpack_entry)));
    if (!arr) return SEALPACK_ERR_NOMEM;
    for (size_t i = 0; i < n; ++i) {
        arr[i].path  = sp->list_cache[i].path.c_str();
        arr[i].size  = sp->list_cache[i].size;
        arr[i].mtime = sp->list_cache[i].mtime;
    }
    *entries = arr;
    *count = n;
    return SEALPACK_OK;
}

int sealpack_stat(sealpack_t* sp, const char* path, sealpack_entry* out) {
    if (!sp || !path || !out) return SEALPACK_ERR_ARG;
    sealpack::Pack::Entry e;
    if (!sp->pack->stat(path, &e)) return sp->pack->last_error();
    sp->stat_path = e.path;
    out->path  = sp->stat_path.c_str();
    out->size  = e.size;
    out->mtime = e.mtime;
    return SEALPACK_OK;
}

void sealpack_free(void* p) { std::free(p); }

const char* sealpack_strerror(int status) {
    switch (status) {
        case SEALPACK_OK:          return "ok";
        case SEALPACK_ERR_IO:      return "I/O error";
        case SEALPACK_ERR_AUTH:    return "wrong password or tampered data";
        case SEALPACK_ERR_CORRUPT: return "corrupt / bad format";
        case SEALPACK_ERR_NOTFOUND:return "path not found";
        case SEALPACK_ERR_NOMEM:   return "out of memory";
        case SEALPACK_ERR_ARG:     return "bad argument";
        case SEALPACK_ERR_EXISTS:  return "already exists";
        default:                   return "unknown error";
    }
}

}  // extern "C"
