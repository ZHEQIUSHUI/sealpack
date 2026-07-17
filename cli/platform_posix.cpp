// POSIX backend for the CLI console/editor shim (Linux, macOS). Built everywhere
// except Windows (see CMakeLists). Extracted from cli/main.cpp; behavior is the
// same, plus: the edit temp file now prefers $XDG_RUNTIME_DIR (usually a private
// tmpfs) so decrypted plaintext isn't written to a world-readable /tmp.

#ifndef _WIN32

#include "platform.hpp"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include <termios.h>
#include <sys/wait.h>
#include <unistd.h>

namespace sealpack_cli {

bool stdin_is_tty()  { return ::isatty(STDIN_FILENO) != 0; }
bool stdout_is_tty() { return ::isatty(STDOUT_FILENO) != 0; }

std::string read_password(const char* prompt) {
    std::fprintf(stderr, "%s", prompt);
    std::fflush(stderr);
    const bool tty = ::isatty(STDIN_FILENO);
    termios old{};
    if (tty) {
        ::tcgetattr(STDIN_FILENO, &old);
        termios ne = old;
        ne.c_lflag = static_cast<tcflag_t>(ne.c_lflag & ~ECHO);
        ::tcsetattr(STDIN_FILENO, TCSANOW, &ne);
    }
    std::string pw;
    std::getline(std::cin, pw);
    if (tty) { ::tcsetattr(STDIN_FILENO, TCSANOW, &old); std::fprintf(stderr, "\n"); }
    return pw;
}

namespace {
// Prefer a private, memory-backed dir for the plaintext temp file; fall back to
// $TMPDIR, then /tmp. $XDG_RUNTIME_DIR is per-user 0700 and usually tmpfs.
std::string temp_dir() {
    const char* d = ::getenv("XDG_RUNTIME_DIR");
    if (!d || !*d) d = ::getenv("TMPDIR");
    if (!d || !*d) d = "/tmp";
    return d;
}
}  // namespace

bool edit_in_editor(const std::string& name_hint, const std::string& data,
                    std::string* out) {
    // Keep the pack path's extension so the editor picks the right syntax mode —
    // but the path is UNTRUSTED (a hostile .spk can name a file anything), and it
    // ends up in a shell command below. Only accept a plain, short extension
    // (letters/digits/._-); anything else (e.g. a quote, ';', space) is dropped.
    std::string ext;
    const auto dot = name_hint.find_last_of('.'), slash = name_hint.find_last_of('/');
    if (dot != std::string::npos && (slash == std::string::npos || dot > slash)) {
        const std::string e = name_hint.substr(dot);
        bool safe = e.size() >= 2 && e.size() <= 16;
        for (char c : e)
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-')) { safe = false; break; }
        if (safe) ext = e;
    }

    std::string tmpl = temp_dir() + "/sealpack-edit-XXXXXX" + ext;
    std::vector<char> t(tmpl.begin(), tmpl.end());
    t.push_back('\0');
    const int fd = ext.empty() ? ::mkstemp(t.data())
                               : ::mkstemps(t.data(), static_cast<int>(ext.size()));
    if (fd < 0) { std::perror("mkstemp"); return false; }
    const std::string path(t.data());
    const bool wrote = ::write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
    ::close(fd);

    bool ok = false;
    if (wrote) {
        const char* ed = ::getenv("VISUAL");
        if (!ed || !*ed) ed = ::getenv("EDITOR");
        if (!ed || !*ed) ed = "vi";
        // Single-quote the path and escape any embedded ' as '\'' — never let the
        // path break out of the quoting into the shell (defense in depth on top of
        // the sanitized extension above; $EDITOR itself is trusted, may carry args).
        std::string q = "'";
        for (char c : path) q += (c == '\'') ? std::string("'\\''") : std::string(1, c);
        q += "'";
        const std::string cmd = std::string(ed) + " " + q;
        // Only read back on a clean editor exit — a crash / `:cq` abort (non-zero
        // exit) must not persist a truncated buffer into the pack.
        const int rc = ::system(cmd.c_str());
        if (rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0) {
            std::ifstream f(path, std::ios::binary);
            std::ostringstream ss;
            ss << f.rdbuf();
            *out = ss.str();
            ok = true;
        }
    }
    ::unlink(path.c_str());
    return ok;
}

}  // namespace sealpack_cli

#endif  // !_WIN32
