// Windows backend for the CLI console/editor shim. Built only on Windows (see
// CMakeLists). Mirrors platform_posix.cpp: tty detection, no-echo password
// entry, and launching $EDITOR on a private temp file — via Win32 APIs.

#ifdef _WIN32

#include "platform.hpp"

#include <cstdio>
#include <cstdlib>
#include <cwctype>
#include <iostream>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h>       // _isatty
#include <process.h>  // _wsystem

namespace sealpack_cli {
namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(static_cast<size_t>(n - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

// Slurp a wide-path file into `out`. false on open/read error.
bool slurp(const std::wstring& path, std::string* out) {
    FILE* f = _wfopen(path.c_str(), L"rb");
    if (!f) return false;
    out->clear();
    char buf[65536];
    size_t r;
    while ((r = std::fread(buf, 1, sizeof buf, f)) > 0) out->append(buf, r);
    const bool ok = std::ferror(f) == 0;
    std::fclose(f);
    return ok;
}

}  // namespace

bool stdin_is_tty()  { return _isatty(_fileno(stdin)) != 0; }
bool stdout_is_tty() { return _isatty(_fileno(stdout)) != 0; }

std::string read_password(const char* prompt) {
    std::fprintf(stderr, "%s", prompt);
    std::fflush(stderr);
    HANDLE hin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    const bool console = GetConsoleMode(hin, &mode) != 0;  // false if input is a pipe
    if (console) SetConsoleMode(hin, mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
    std::string pw;
    std::getline(std::cin, pw);
    if (console) { SetConsoleMode(hin, mode); std::fprintf(stderr, "\n"); }
    return pw;
}

bool edit_in_editor(const std::string& name_hint, const std::string& data,
                    std::string* out) {
    std::string ext;
    const auto dot = name_hint.find_last_of('.'), slash = name_hint.find_last_of("/\\");
    if (dot != std::string::npos && (slash == std::string::npos || dot > slash))
        ext = name_hint.substr(dot);

    // Per-user temp dir (ACL'd), then a unique file created there by the OS.
    wchar_t tdir[MAX_PATH + 1];
    DWORD dn = GetTempPathW(MAX_PATH, tdir);
    if (dn == 0 || dn > MAX_PATH) return false;
    wchar_t tmpf[MAX_PATH + 1];
    if (GetTempFileNameW(tdir, L"spk", 0, tmpf) == 0) return false;  // creates a unique .tmp
    std::wstring path = tmpf;

    // Give it the original extension (GetTempFileName always makes ".tmp") so an
    // ext-aware editor picks the right syntax mode.
    if (!ext.empty()) {
        std::wstring base = path;
        if (base.size() >= 4) {
            std::wstring suf = base.substr(base.size() - 4);
            for (auto& c : suf) c = towlower(c);
            if (suf == L".tmp") base.resize(base.size() - 4);
        }
        std::wstring want = base + widen(ext);
        if (MoveFileExW(path.c_str(), want.c_str(), MOVEFILE_REPLACE_EXISTING))
            path = want;
    }

    // Write the plaintext to the temp file.
    bool wrote = false;
    if (FILE* f = _wfopen(path.c_str(), L"wb")) {
        wrote = std::fwrite(data.data(), 1, data.size(), f) == data.size();
        std::fclose(f);
    }

    bool ok = false;
    if (wrote) {
        const char* ed = std::getenv("VISUAL");
        if (!ed || !*ed) ed = std::getenv("EDITOR");
        if (!ed || !*ed) ed = "notepad";
        // _wsystem returns the command's exit code (0 = success), or -1 if the
        // command interpreter can't start. Only read back on a clean exit.
        const std::wstring cmd = widen(ed) + L" \"" + path + L"\"";
        const int rc = _wsystem(cmd.c_str());
        if (rc == 0) ok = slurp(path, out);
    }
    DeleteFileW(path.c_str());
    return ok;
}

}  // namespace sealpack_cli

#endif  // _WIN32
