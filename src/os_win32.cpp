// Windows backend for the os:: seam. Built only on Windows (see CMakeLists);
// the POSIX backend is os_posix.cpp. Mirrors that file's semantics exactly —
// positional all-or-nothing I/O, a real durability barrier, atomic replace —
// using Win32 handles. Validated on GitHub Actions' windows-latest runner
// (there is no local Windows build in the dev environment).

#ifdef _WIN32

#include "os.hpp"

#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace sealpack {
namespace os {
namespace {

inline HANDLE as_handle(handle_t h) { return reinterpret_cast<HANDLE>(h); }
inline handle_t from_handle(HANDLE h) { return reinterpret_cast<handle_t>(h); }

// Paths on disk are UTF-8 (that's what the C++/C API takes); widen to UTF-16 so
// non-ASCII pack paths work with the -W Win32 calls.
std::wstring widen(const char* s) {
    if (!s || !*s) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(static_cast<size_t>(n - 1), L'\0');  // n includes the NUL
    MultiByteToWideChar(CP_UTF8, 0, s, -1, &w[0], n);
    return w;
}

// Non-inheritable handle → not leaked to spawned children (the O_CLOEXEC analog).
SECURITY_ATTRIBUTES* no_inherit() {
    static SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE};
    return &sa;
}

}  // namespace

handle_t open_file(const char* path, OpenMode mode) {
    DWORD access, disposition;
    switch (mode) {
        case OpenMode::CreateNew: access = GENERIC_READ | GENERIC_WRITE; disposition = CREATE_NEW;    break;
        case OpenMode::ReadWrite: access = GENERIC_READ | GENERIC_WRITE; disposition = OPEN_EXISTING; break;
        case OpenMode::ReadOnly:  access = GENERIC_READ;                 disposition = OPEN_EXISTING; break;
        default: return invalid();
    }
    const std::wstring w = widen(path);
    HANDLE h = CreateFileW(w.c_str(), access,
                           FILE_SHARE_READ,          // allow concurrent readers, not writers
                           no_inherit(), disposition,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    return h == INVALID_HANDLE_VALUE ? invalid() : from_handle(h);
}

void close_file(handle_t h) {
    if (valid(h)) CloseHandle(as_handle(h));
}

bool pwrite_all(handle_t h, const void* buf, size_t n, uint64_t off) {
    const auto* p = static_cast<const unsigned char*>(buf);
    size_t done = 0;
    while (done < n) {
        // OVERLAPPED carries the absolute offset — the positional-write analog of
        // pwrite(); it does not disturb any implicit file pointer.
        OVERLAPPED ov = {};
        const uint64_t at = off + done;
        ov.Offset     = static_cast<DWORD>(at & 0xFFFFFFFFu);
        ov.OffsetHigh = static_cast<DWORD>(at >> 32);
        const DWORD chunk = static_cast<DWORD>(
            (n - done) > 0x7FFFFFFF ? 0x7FFFFFFF : (n - done));
        DWORD wrote = 0;
        if (!WriteFile(as_handle(h), p + done, chunk, &wrote, &ov) || wrote == 0)
            return false;
        done += wrote;
    }
    return true;
}

bool pread_all(handle_t h, void* buf, size_t n, uint64_t off) {
    auto* p = static_cast<unsigned char*>(buf);
    size_t done = 0;
    while (done < n) {
        OVERLAPPED ov = {};
        const uint64_t at = off + done;
        ov.Offset     = static_cast<DWORD>(at & 0xFFFFFFFFu);
        ov.OffsetHigh = static_cast<DWORD>(at >> 32);
        const DWORD chunk = static_cast<DWORD>(
            (n - done) > 0x7FFFFFFF ? 0x7FFFFFFF : (n - done));
        DWORD got = 0;
        if (!ReadFile(as_handle(h), p + done, chunk, &got, &ov) || got == 0)
            return false;   // got == 0 → short read (EOF before n bytes)
        done += got;
    }
    return true;
}

int64_t file_size(handle_t h) {
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(as_handle(h), &sz)) return -1;
    return static_cast<int64_t>(sz.QuadPart);
}

// FlushFileBuffers is the real barrier — it flushes the drive's write cache,
// like fdatasync/F_FULLFSYNC. This is what the commit protocol relies on.
bool sync_file(handle_t h) {
    return FlushFileBuffers(as_handle(h)) != 0;
}

bool remove_file(const char* path) {
    return DeleteFileW(widen(path).c_str()) != 0;
}

bool rename_replace(const char* from, const char* to) {
    // MOVEFILE_REPLACE_EXISTING overwrites `to`; MOVEFILE_WRITE_THROUGH makes the
    // rename durable before returning. Together this is the atomic-replace step
    // compact() needs (POSIX rename already replaces the target).
    return MoveFileExW(widen(from).c_str(), widen(to).c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

uint64_t now_seconds() {
    // Windows FILETIME is 100-ns ticks since 1601-01-01; convert to unix seconds.
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER t;
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    constexpr uint64_t kTicksPerSec = 10000000ull;
    constexpr uint64_t kEpochDiff   = 11644473600ull;  // seconds 1601→1970
    return t.QuadPart / kTicksPerSec - kEpochDiff;
}

}  // namespace os
}  // namespace sealpack

#endif  // _WIN32
