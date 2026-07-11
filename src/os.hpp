#ifndef SEALPACK_OS_HPP
#define SEALPACK_OS_HPP

// Platform seam for the core library. Everything OS-specific that the core
// (store/pack) touches — file open/read/write/sync/rename/remove — lives behind
// this interface, so store.cpp/pack.cpp stay platform-agnostic. Two backends
// implement it: os_posix.cpp (Linux/macOS) and os_win32.cpp (Windows). RNG is
// its own seam in crypto.cpp (getrandom / BCryptGenRandom).
//
// Design notes:
//   - handle_t is a raw fd on POSIX, a HANDLE on Windows; treat it as opaque.
//   - All I/O is positional (pread/pwrite style) — the store addresses the file
//     by absolute offset and never relies on a shared seek cursor.
//   - pread_all/pwrite_all loop over short transfers and retry EINTR, so callers
//     get all-or-nothing semantics.
//   - sync_file is the durability barrier (fdatasync / F_FULLFSYNC /
//     FlushFileBuffers); the commit protocol's correctness depends on it.

#include <cstddef>
#include <cstdint>

namespace sealpack {
namespace os {

#ifdef _WIN32
using handle_t = void*;                       // Win32 HANDLE
inline handle_t invalid() { return reinterpret_cast<handle_t>(~static_cast<uintptr_t>(0)); }  // INVALID_HANDLE_VALUE
#else
using handle_t = int;                          // POSIX fd
inline handle_t invalid() { return -1; }
#endif

enum class OpenMode {
    CreateNew,   // create, fail if it already exists (O_CREAT|O_EXCL), mode 0600
    ReadWrite,   // open existing for read+write
    ReadOnly,    // open existing read-only
};

// Open/create `path`. Returns invalid() on error. Opened with close-on-exec
// (POSIX O_CLOEXEC / Win32 non-inheritable) so a forked child / spawned editor
// never inherits a handle to the decrypted-at-rest file.
handle_t open_file(const char* path, OpenMode mode);

inline bool valid(handle_t h) { return h != invalid(); }
void close_file(handle_t h);

// Positional all-or-nothing I/O. false on short/failed transfer.
bool pread_all(handle_t h, void* buf, size_t n, uint64_t off);
bool pwrite_all(handle_t h, const void* buf, size_t n, uint64_t off);

// Current end-of-file offset (the append position). -1 on error.
int64_t file_size(handle_t h);

// Durability barrier — flush this file's data to stable storage. false on error.
bool sync_file(handle_t h);

// Remove `path`. false on error (missing file is not treated specially).
bool remove_file(const char* path);

// Atomically replace `to` with `from` (rename that overwrites an existing
// target). POSIX rename() already does this; Win32 needs MOVEFILE_REPLACE_EXISTING.
bool rename_replace(const char* from, const char* to);

// Wall-clock unix seconds (for mtime). Not security-sensitive.
uint64_t now_seconds();

}  // namespace os
}  // namespace sealpack

#endif  // SEALPACK_OS_HPP
