// POSIX backend for the os:: seam (Linux, macOS, Android). Built everywhere
// except Windows (see CMakeLists). The logic here was previously inline in
// store.cpp; extracting it kept behavior identical (the ctest suite is the
// regression) while making room for os_win32.cpp.

#ifndef _WIN32

#include "os.hpp"

#include <cerrno>
#include <cstdio>   // rename
#include <ctime>
#include <string>

#include <fcntl.h>
#include <unistd.h>

namespace sealpack {
namespace os {

handle_t open_file(const char* path, OpenMode mode) {
    int flags;
    switch (mode) {
        case OpenMode::CreateNew: flags = O_CREAT | O_EXCL | O_RDWR; break;
        case OpenMode::ReadWrite: flags = O_RDWR; break;
        case OpenMode::ReadOnly:  flags = O_RDONLY; break;
        default: return invalid();
    }
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;   // don't leak the fd to spawned editors / children
#endif
    return ::open(path, flags, 0600);
}

void close_file(handle_t h) {
    if (h >= 0) ::close(h);
}

bool pwrite_all(handle_t h, const void* buf, size_t n, uint64_t off) {
    const auto* p = static_cast<const unsigned char*>(buf);
    size_t done = 0;
    while (done < n) {
        ssize_t w = ::pwrite(h, p + done, n - done, static_cast<off_t>(off + done));
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; return false; }
        done += static_cast<size_t>(w);
    }
    return true;
}

bool pread_all(handle_t h, void* buf, size_t n, uint64_t off) {
    auto* p = static_cast<unsigned char*>(buf);
    size_t done = 0;
    while (done < n) {
        ssize_t r = ::pread(h, p + done, n - done, static_cast<off_t>(off + done));
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return false; }
        done += static_cast<size_t>(r);
    }
    return true;
}

int64_t file_size(handle_t h) {
    off_t end = ::lseek(h, 0, SEEK_END);
    return end < 0 ? -1 : static_cast<int64_t>(end);
}

// On macOS fsync only reaches the drive cache — F_FULLFSYNC hits the platter,
// which crash-durability needs there; Linux fdatasync is enough and cheaper.
bool sync_file(handle_t h) {
#if defined(__APPLE__)
    if (::fcntl(h, F_FULLFSYNC) == 0) return true;
    return ::fsync(h) == 0;
#elif defined(__linux__)
    return ::fdatasync(h) == 0;
#else
    return ::fsync(h) == 0;
#endif
}

bool remove_file(const char* path) { return ::unlink(path) == 0; }

bool rename_replace(const char* from, const char* to) {
    if (::rename(from, to) != 0) return false;   // atomic replace
    // ...but not durable on its own: a power loss right after rename() can lose the
    // new directory entry. fsync the containing directory to match Win32's
    // MOVEFILE_WRITE_THROUGH. (Best-effort — a failure here doesn't undo the rename.)
    std::string dir(to);
    const auto slash = dir.find_last_of('/');
    dir = (slash == std::string::npos) ? std::string(".")
        : (slash == 0 ? std::string("/") : dir.substr(0, slash));
    int flags = O_RDONLY;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int dfd = ::open(dir.c_str(), flags);
    if (dfd >= 0) { ::fsync(dfd); ::close(dfd); }
    return true;
}

uint64_t now_seconds() { return static_cast<uint64_t>(::time(nullptr)); }

}  // namespace os
}  // namespace sealpack

#endif  // !_WIN32
