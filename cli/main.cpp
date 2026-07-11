// sealpack CLI.
//
// Interactive (recommended): open a pack, type the password once, then run
// commands in a mini shell. The pack stays open — one Argon2 unlock for the
// whole session, not one per command — so a batch of operations on a big pack
// is fast.
//
//   sealpack models.sealpack        # prompts for the password, drops into a shell
//   sealpack> ls
//   sealpack> add cfg/x.json /tmp/x.json
//   sealpack> rekey                 # asks for the new password twice
//   sealpack> quit
//
// One-shot (scriptable): a subcommand runs once and exits. On a terminal it
// prompts for the password; with no terminal it reads $SEALPACK_PASSWORD (CI).
//
//   sealpack create <pack>                 (prompts for a new password twice)
//   sealpack ls/add/get/rm/mv/cp/stat/compact/rekey <pack> ...
//   sealpack web    <pack> [port]

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "preview.hpp"
#include "sealpack.hpp"

using sealpack::Pack;

// defined in cli/web.cpp
int run_web(Pack* pack, const std::string& pack_path, const std::string& host, int port);

// ---- helpers ----------------------------------------------------------------

static bool read_file(const char* path, std::string* out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss; ss << f.rdbuf();
    *out = ss.str();
    return true;
}
static bool write_file(const char* path, const std::string& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    return f.good();
}

// Read one line from stdin, echo off if it's a terminal (so the password
// doesn't show or land in scrollback). On a pipe it just reads a line, which
// keeps scripting/CI working.
static std::string read_password(const char* prompt) {
    std::fprintf(stderr, "%s", prompt);
    std::fflush(stderr);
    const bool tty = ::isatty(STDIN_FILENO);
    termios old{};
    if (tty) {
        ::tcgetattr(STDIN_FILENO, &old);
        termios ne = old; ne.c_lflag = static_cast<tcflag_t>(ne.c_lflag & ~ECHO);
        ::tcsetattr(STDIN_FILENO, TCSANOW, &ne);
    }
    std::string pw;
    std::getline(std::cin, pw);
    if (tty) { ::tcsetattr(STDIN_FILENO, TCSANOW, &old); std::fprintf(stderr, "\n"); }
    return pw;
}

static std::vector<std::string> tokenize(const std::string& s) {
    std::vector<std::string> t; std::istringstream is(s); std::string w;
    while (is >> w) t.push_back(w);
    return t;
}

// Human-readable size like the web UI (512 B, 4.0 KB, 176.7 MB) — raw bytes are
// unreadable at model scale.
static std::string human_size(uint64_t n) {
    const char* u[] = {"B", "KB", "MB", "GB", "TB"};
    double v = static_cast<double>(n);
    int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; ++i; }
    char buf[32];
    std::snprintf(buf, sizeof buf, i == 0 ? "%.0f %s" : "%.1f %s", v, u[i]);
    return buf;
}

// Open `data` in $VISUAL/$EDITOR (default vi) via a temp file, returning the
// edited bytes in *out. Keeps the original extension so the editor picks the
// right syntax mode. The temp file is 0600 (mkstemp) and removed after.
static bool edit_in_editor(const std::string& name_hint, const std::string& data,
                           std::string* out) {
    std::string ext;
    const auto dot = name_hint.find_last_of('.'), slash = name_hint.find_last_of('/');
    if (dot != std::string::npos && (slash == std::string::npos || dot > slash))
        ext = name_hint.substr(dot);
    std::string tmpl = "/tmp/sealpack-edit-XXXXXX" + ext;
    std::vector<char> t(tmpl.begin(), tmpl.end()); t.push_back('\0');
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
        const std::string cmd = std::string(ed) + " '" + path + "'";
        // Only read the file back if the editor actually exited cleanly.
        // system() returns -1 when the child can't be spawned, otherwise a wait
        // status: a crashed editor, or a deliberate abort (vi `:cq` exits non-
        // zero), must NOT write a possibly-truncated buffer back into the pack.
        const int rc = ::system(cmd.c_str());
        if (rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0)
            ok = read_file(path.c_str(), out);
    }
    ::unlink(path.c_str());
    return ok;
}

// ---- command execution (shared by the shell and one-shot mode) --------------

// Run one command against an already-open pack. Prints its own errors; returns
// 0 on success. a[0] is the command, a[1..] its arguments. rekey/addkey prompt
// for the new password — the pack is already open, so opening it *was* the
// proof of the old password (no need to re-ask it).
static int do_command(Pack* pk, const std::vector<std::string>& a) {
    const std::string& c = a[0];

    if (c == "ls") {
        const std::string pre = a.size() >= 2 ? a[1] : "";
        for (const auto& e : pk->list())
            if (pre.empty() || e.path.rfind(pre, 0) == 0)
                std::printf("%10s  %s\n", human_size(e.size).c_str(), e.path.c_str());
        return 0;
    }
    if (c == "get" && a.size() >= 2) {
        std::string data;
        if (!pk->get(a[1], &data)) { std::fprintf(stderr, "not found: %s\n", a[1].c_str()); return 1; }
        if (a.size() >= 3) {
            if (!write_file(a[2].c_str(), data)) { std::fprintf(stderr, "write %s failed\n", a[2].c_str()); return 1; }
            std::fprintf(stderr, "wrote %s (%zu bytes)\n", a[2].c_str(), data.size());
            return 0;
        }
        if (::isatty(STDOUT_FILENO)) {  // don't spew a binary model into the terminal
            std::fprintf(stderr, "refusing to dump binary to the terminal — give an outfile: get %s <outfile>\n", a[1].c_str());
            return 1;
        }
        std::fwrite(data.data(), 1, data.size(), stdout);
        return 0;
    }
    if (c == "cat" && a.size() == 2) {
        std::string data;
        if (!pk->get(a[1], &data)) { std::fprintf(stderr, "not found: %s\n", a[1].c_str()); return 1; }
        if (!sealpack_preview::looks_text(data)) {
            std::fprintf(stderr, "cat: %s looks binary (%s) — use 'get %s <outfile>'\n",
                         a[1].c_str(), human_size(data.size()).c_str(), a[1].c_str());
            return 1;
        }
        std::fwrite(data.data(), 1, data.size(), stdout);
        if (!data.empty() && data.back() != '\n') std::fputc('\n', stdout);
        return 0;
    }
    if (c == "edit" && a.size() == 2) {
        if (!::isatty(STDIN_FILENO)) { std::fprintf(stderr, "edit: needs a terminal\n"); return 1; }
        std::string data;
        if (!pk->get(a[1], &data)) { std::fprintf(stderr, "not found: %s\n", a[1].c_str()); return 1; }
        if (!sealpack_preview::looks_text(data)) {
            std::fprintf(stderr, "edit: %s looks binary — refusing (use get/add)\n", a[1].c_str());
            return 1;
        }
        std::string edited;
        if (!edit_in_editor(a[1], data, &edited)) { std::fprintf(stderr, "edit: editor failed\n"); return 1; }
        if (edited == data) { std::fprintf(stderr, "unchanged\n"); return 0; }
        if (!pk->put(a[1], edited) || !pk->commit()) { std::fprintf(stderr, "edit: write-back failed\n"); return 1; }
        std::fprintf(stderr, "updated %s (%s)\n", a[1].c_str(), human_size(edited.size()).c_str());
        return 0;
    }
    if (c == "add" && a.size() == 3) {
        std::string data;
        if (!read_file(a[2].c_str(), &data)) { std::fprintf(stderr, "read %s failed\n", a[2].c_str()); return 1; }
        if (!pk->put(a[1], data) || !pk->commit()) { std::fprintf(stderr, "add failed\n"); return 1; }
        return 0;
    }
    if (c == "rm" && a.size() == 2) {
        if (!pk->del(a[1]) || !pk->commit()) { std::fprintf(stderr, "rm failed\n"); return 1; }
        return 0;
    }
    if (c == "mv" && a.size() == 3) {
        if (!pk->move(a[1], a[2]) || !pk->commit()) { std::fprintf(stderr, "mv failed\n"); return 1; }
        return 0;
    }
    if (c == "cp" && a.size() == 3) {
        if (!pk->copy(a[1], a[2]) || !pk->commit()) { std::fprintf(stderr, "cp failed\n"); return 1; }
        return 0;
    }
    if (c == "stat" && a.size() == 2) {
        Pack::Entry e;
        if (!pk->stat(a[1], &e)) { std::fprintf(stderr, "not found: %s\n", a[1].c_str()); return 1; }
        std::printf("%s  %s (%llu bytes)  mtime=%llu\n", e.path.c_str(), human_size(e.size).c_str(),
                    static_cast<unsigned long long>(e.size), static_cast<unsigned long long>(e.mtime));
        return 0;
    }
    if (c == "compact" && a.size() == 1) {
        if (!pk->compact()) { std::fprintf(stderr, "compact failed\n"); return 1; }
        std::fprintf(stderr, "compacted\n");
        return 0;
    }
    if (c == "rekey" && a.size() == 1) {
        const std::string n1 = read_password("new password: ");
        const std::string n2 = read_password("confirm new password: ");
        if (n1 != n2) { std::fprintf(stderr, "new passwords don't match\n"); return 1; }
        if (!pk->rekey(n1)) { std::fprintf(stderr, "rekey failed\n"); return 1; }
        std::fprintf(stderr, "password changed; the old one no longer opens this pack\n");
        return 0;
    }
    std::fprintf(stderr, "unknown or malformed command: %s (try 'help')\n", c.c_str());
    return 2;
}

// ---- interactive shell ------------------------------------------------------

static void shell_help() {
    std::fprintf(stderr,
        "commands (operate on the open pack):\n"
        "  ls [prefix]           list files (optionally under a path prefix)\n"
        "  get <path> [outfile]  extract a file\n"
        "  cat <path>            print a text file (refuses binary)\n"
        "  edit <path>           edit a text file in $EDITOR (vi), save back\n"
        "  add <path> <file>     add / overwrite from a local file\n"
        "  rm <path>             remove\n"
        "  mv <from> <to>        rename / move\n"
        "  cp <from> <to>        copy (dedup, 0 extra bytes)\n"
        "  stat <path>           size + mtime\n"
        "  compact               reclaim deleted space\n"
        "  rekey                 change the password (new password, twice)\n"
        "  help                  this list\n"
        "  quit | exit           close and leave\n");
}

static int shell(Pack* pk, const std::string& pack_path) {
    std::fprintf(stderr, "opened %s — 'help' for commands, 'quit' to exit.\n", pack_path.c_str());
    std::string line;
    while (true) {
        if (::isatty(STDIN_FILENO)) { std::fprintf(stderr, "sealpack> "); std::fflush(stderr); }
        if (!std::getline(std::cin, line)) { std::fprintf(stderr, "\n"); break; }  // Ctrl-D
        const auto a = tokenize(line);
        if (a.empty()) continue;
        if (a[0] == "quit" || a[0] == "exit") break;
        if (a[0] == "help" || a[0] == "?") { shell_help(); continue; }
        do_command(pk, a);  // errors are printed inside; the shell keeps going
    }
    return 0;
}

// ---- entry ------------------------------------------------------------------

static bool is_command(const std::string& s) {
    static const char* k[] = {"create","add","get","cat","edit","ls","rm","mv","cp","stat",
                              "compact","rekey","web"};
    for (auto c : k) if (s == c) return true;
    return false;
}

static int usage() {
    std::fprintf(stderr,
        "usage:\n"
        "  sealpack <pack>               open + interactive shell (prompts for password)\n"
        "  sealpack create <pack>        create a new pack (prompts for password twice)\n"
        "  sealpack <cmd> <pack> [args]  one-shot: ls/add/get/cat/edit/rm/mv/cp/\n"
        "                                stat/compact/rekey; or  web <pack> [port]\n"
        "  one-shot prompts for the password on a terminal, else uses $SEALPACK_PASSWORD\n");
    return 2;
}

// Password for one-shot mode: prompt on a terminal, else $SEALPACK_PASSWORD.
static bool batch_password(std::string* out) {
    if (::isatty(STDIN_FILENO)) { *out = read_password("password: "); return true; }
    const char* e = ::getenv("SEALPACK_PASSWORD");
    if (!e) { std::fprintf(stderr, "no terminal: set $SEALPACK_PASSWORD\n"); return false; }
    *out = e;
    return true;
}

int main(int argc, char** argv) {
    // Interactive: `sealpack <pack>` — a lone argument that isn't a subcommand.
    if (argc == 2 && !is_command(argv[1])) {
        const std::string pw = read_password("password: ");
        auto pk = Pack::open(argv[1], pw);
        if (!pk) { std::fprintf(stderr, "open failed (wrong password or missing file)\n"); return 1; }
        return shell(pk.get(), argv[1]);
    }

    if (argc < 3) return usage();
    const std::string cmd = argv[1];
    const char* pack = argv[2];

    if (cmd == "create") {
        const std::string p1 = read_password("new password: ");
        const std::string p2 = read_password("confirm password: ");
        if (p1 != p2) { std::fprintf(stderr, "passwords don't match\n"); return 1; }
        auto pk = Pack::create(pack, p1);
        if (!pk || !pk->commit()) { std::fprintf(stderr, "create failed (already exists?)\n"); return 1; }
        return 0;
    }

    std::string pw;
    if (!batch_password(&pw)) return 2;
    auto pk = Pack::open(pack, pw);
    if (!pk) { std::fprintf(stderr, "open failed (wrong password or missing file)\n"); return 1; }

    if (cmd == "web") {
        const int port = (argc >= 4) ? std::atoi(argv[3]) : 8777;
        return run_web(pk.get(), pack, "127.0.0.1", port);
    }

    // one-shot: run the single command and exit.
    std::vector<std::string> a; a.push_back(cmd);
    for (int i = 3; i < argc; ++i) a.push_back(argv[i]);
    return do_command(pk.get(), a);
}
