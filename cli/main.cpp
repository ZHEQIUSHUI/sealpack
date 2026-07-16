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
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "linenoise.h"    // vendored linenoise-ng: line editing + tab completion
#include "platform.hpp"   // tty / no-echo password / editor — POSIX+Windows
#include "preview.hpp"
#include "sealpack.h"     // status codes (SEALPACK_ERR_*)
#include "sealpack.hpp"

using sealpack::Pack;
using sealpack_cli::read_password;
using sealpack_cli::edit_in_editor;

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
        if (sealpack_cli::stdout_is_tty()) {  // don't spew a binary model into the terminal
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
        if (!sealpack_cli::stdin_is_tty()) { std::fprintf(stderr, "edit: needs a terminal\n"); return 1; }
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
    if (c == "patch" && a.size() == 2) {   // apply a .spkpatch to the open pack
        std::string blob;
        if (!read_file(a[1].c_str(), &blob)) { std::fprintf(stderr, "read %s failed\n", a[1].c_str()); return 1; }
        if (!pk->apply_patch(blob)) {
            const int e = pk->last_error();
            std::fprintf(stderr, "patch failed: %s\n",
                         e == SEALPACK_ERR_PATCH ? "this pack isn't the base the patch was built from"
                       : e == SEALPACK_ERR_AUTH  ? "patch is for a different pack (won't decrypt)"
                       : "corrupt or unreadable patch");
            return 1;
        }
        std::fprintf(stderr, "applied %s\n", a[1].c_str());
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
        "  patch <file>          apply a .spkpatch (incremental update)\n"
        "  rekey                 change the password (new password, twice)\n"
        "  help                  this list\n"
        "  quit | exit           close and leave\n"
        "(Tab completes commands and in-pack paths; ↑/↓ for history.)\n");
}

// ---- tab completion (commands + in-pack paths) ------------------------------

// The open pack the completion callback reads paths from. Single-threaded shell,
// one pack at a time, so a file-static pointer is enough (linenoise's callback
// takes no user-data argument).
static const Pack* g_completion_pack = nullptr;

// Commands whose arguments are in-pack paths (so we complete them from list()).
// `add`/`get` also take a *local* file arg, which we don't complete here.
static bool cmd_completes_paths(const std::string& c) {
    return c == "cat" || c == "get" || c == "edit" || c == "rm" ||
           c == "mv"  || c == "cp"  || c == "stat" || c == "ls";
}

// Tab handler. linenoise-ng breaks the line on whitespace AND '/', so it hands
// us only the current leaf word (e.g. "a" from "cat cfg/a") and rebuilds the
// line as <everything-before-the-word> + <our candidate>. We therefore return
// bare leaf segments. The command + parent folder we need for context come from
// linenoiseCompletionContext() (the full line before the cursor).
static void completion_cb(const char* word, linenoiseCompletions* lc) {
    static const char* const kCmds[] = {
        "ls", "get", "cat", "edit", "add", "rm", "mv", "cp", "stat",
        "compact", "patch", "rekey", "help", "quit", "exit"};

    const std::string leaf(word);                          // the segment being completed
    const std::string line(linenoiseCompletionContext());  // full text before cursor

    const size_t sp = line.find_last_of(" \t");
    if (sp == std::string::npos) {                         // first token → complete a command
        for (const char* c : kCmds)
            if (std::strncmp(c, line.c_str(), line.size()) == 0)
                linenoiseAddCompletion(lc, c);
        return;
    }
    const std::string cmd = line.substr(0, line.find_first_of(" \t"));
    if (!g_completion_pack || !cmd_completes_paths(cmd)) return;

    // The whole path typed so far is the last space-delimited token; its parent
    // folder is that token minus the leaf we're completing.
    const std::string arg    = line.substr(sp + 1);            // e.g. "cfg/a"
    const std::string parent = arg.substr(0, arg.size() - leaf.size());  // e.g. "cfg/"

    std::set<std::string> cands;                           // sorted + de-duped leaf segments
    for (const auto& e : g_completion_pack->list()) {
        const std::string& p = e.path;
        if (p.compare(0, parent.size(), parent) != 0) continue;   // must live under `parent`
        const std::string rest = p.substr(parent.size());         // path below the parent
        if (rest.compare(0, leaf.size(), leaf) != 0) continue;     // next segment matches the leaf
        const size_t slash = rest.find('/');
        cands.insert(slash == std::string::npos ? rest : rest.substr(0, slash + 1));  // file, or folder/
    }
    for (const auto& cand : cands) linenoiseAddCompletion(lc, cand.c_str());
}

static int shell(Pack* pk, const std::string& pack_path) {
    std::fprintf(stderr, "opened %s — 'help' for commands, 'quit' to exit.\n", pack_path.c_str());
    g_completion_pack = pk;
    linenoiseSetCompletionCallback(completion_cb);
    linenoiseHistorySetMaxLen(200);   // in-memory only — never persisted (paths are sensitive)
    while (true) {
        char* raw = linenoise("sealpack> ");   // handles editing + Tab; NULL on Ctrl-D/EOF
        if (!raw) { std::fprintf(stderr, "\n"); break; }
        const std::string line(raw);
        std::free(raw);
        const auto a = tokenize(line);
        if (a.empty()) continue;
        linenoiseHistoryAdd(line.c_str());
        if (a[0] == "quit" || a[0] == "exit") break;
        if (a[0] == "help" || a[0] == "?") { shell_help(); continue; }
        do_command(pk, a);  // errors are printed inside; the shell keeps going
    }
    g_completion_pack = nullptr;
    return 0;
}

// ---- entry ------------------------------------------------------------------

static bool is_command(const std::string& s) {
    static const char* k[] = {"create","add","get","cat","edit","ls","rm","mv","cp","stat",
                              "compact","patch","diff","rekey","web"};
    for (auto c : k) if (s == c) return true;
    return false;
}

static int usage() {
    std::fprintf(stderr,
        "usage:\n"
        "  sealpack <pack>               open + interactive shell (prompts for password)\n"
        "  sealpack create <pack>        create a new pack (prompts for password twice)\n"
        "  sealpack <cmd> <pack> [args]  one-shot: ls/add/get/cat/edit/rm/mv/cp/\n"
        "                                stat/compact/patch; or  web <pack> [port]\n"
        "  sealpack diff <old> <new> <out.spkpatch>   build an incremental update\n"
        "  sealpack patch <pack> <file.spkpatch>      apply one (only the delta)\n"
        "  one-shot prompts for the password on a terminal, else uses $SEALPACK_PASSWORD\n");
    return 2;
}

// Password for one-shot mode: prompt on a terminal, else $SEALPACK_PASSWORD.
static bool batch_password(std::string* out) {
    if (sealpack_cli::stdin_is_tty()) { *out = read_password("password: "); return true; }
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

    // diff opens TWO packs, so it can't go through the single-pack path below.
    if (cmd == "diff") {
        if (argc < 5) { std::fprintf(stderr, "usage: sealpack diff <old.spk> <new.spk> <out.spkpatch>\n"); return 2; }
        std::string pw_old, pw_new;
        if (sealpack_cli::stdin_is_tty()) {
            pw_old = read_password("password for old pack: ");
            pw_new = read_password("password for new pack: ");
        } else {
            const char* e = ::getenv("SEALPACK_PASSWORD");
            if (!e) { std::fprintf(stderr, "no terminal: set $SEALPACK_PASSWORD (used for both packs)\n"); return 2; }
            pw_old = pw_new = e;   // non-tty assumes both packs share the password
        }
        auto oldpk = Pack::open(argv[2], pw_old);
        if (!oldpk) { std::fprintf(stderr, "open %s failed (wrong password or missing)\n", argv[2]); return 1; }
        auto newpk = Pack::open(argv[3], pw_new);
        if (!newpk) { std::fprintf(stderr, "open %s failed (wrong password or missing)\n", argv[3]); return 1; }
        std::string patch;
        if (!oldpk->create_patch(*newpk, &patch)) { std::fprintf(stderr, "diff failed\n"); return 1; }
        if (!write_file(argv[4], patch)) { std::fprintf(stderr, "write %s failed\n", argv[4]); return 1; }
        std::fprintf(stderr, "wrote %s (%s)\n", argv[4], human_size(patch.size()).c_str());
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
