// sealpack CLI — thin wrapper over the C++ Pack API.
//   password comes from $SEALPACK_PASSWORD (keeps it out of argv/ps).
//
//   sealpack create  <pack>
//   sealpack add      <pack> <path> <file>
//   sealpack get      <pack> <path> [outfile]   (default: stdout)
//   sealpack ls       <pack>
//   sealpack rm       <pack> <path>
//   sealpack mv       <pack> <from> <to>
//   sealpack cp       <pack> <from> <to>
//   sealpack compact  <pack>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

#include "sealpack.hpp"

using sealpack::Pack;

// defined in cli/web.cpp
int run_web(Pack* pack, const std::string& pack_path, const std::string& host, int port);

static std::string password() {
    const char* e = ::getenv("SEALPACK_PASSWORD");
    return e ? std::string(e) : std::string();
}

static bool read_file(const char* path, std::string* out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    *out = ss.str();
    return true;
}

static bool write_file(const char* path, const std::string& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    return f.good();
}

static int usage() {
    std::fprintf(stderr,
        "usage: sealpack <cmd> <pack> [args]   (password from $SEALPACK_PASSWORD)\n"
        "  create  <pack>\n"
        "  add     <pack> <path> <file>\n"
        "  get     <pack> <path> [outfile]   (default: stdout)\n"
        "  ls      <pack>\n"
        "  rm      <pack> <path>\n"
        "  mv      <pack> <from> <to>\n"
        "  cp      <pack> <from> <to>\n"
        "  compact <pack>\n"
        "  web     <pack> [port]        file-manager UI in the browser (default 8777)\n");
    return 2;
}

int main(int argc, char** argv) {
    if (argc < 3) return usage();
    const std::string cmd = argv[1];
    const char* pack = argv[2];
    const std::string pw = password();
    if (pw.empty()) {
        std::fprintf(stderr, "set $SEALPACK_PASSWORD\n");
        return 2;
    }

    if (cmd == "create") {
        auto pk = Pack::create(pack, pw);
        if (!pk || !pk->commit()) { std::fprintf(stderr, "create failed\n"); return 1; }
        return 0;
    }

    auto pk = Pack::open(pack, pw);
    if (!pk) { std::fprintf(stderr, "open failed (wrong password or missing file)\n"); return 1; }

    if (cmd == "web") {
        const int port = (argc >= 4) ? std::atoi(argv[3]) : 8777;
        return run_web(pk.get(), pack, "127.0.0.1", port);
    }
    if (cmd == "add" && argc == 5) {
        std::string data;
        if (!read_file(argv[4], &data)) { std::fprintf(stderr, "read %s failed\n", argv[4]); return 1; }
        if (!pk->put(argv[3], data) || !pk->commit()) { std::fprintf(stderr, "add failed\n"); return 1; }
        return 0;
    }
    if (cmd == "get" && (argc == 4 || argc == 5)) {
        std::string data;
        if (!pk->get(argv[3], &data)) { std::fprintf(stderr, "not found: %s\n", argv[3]); return 1; }
        if (argc == 5) return write_file(argv[4], data) ? 0 : 1;
        std::fwrite(data.data(), 1, data.size(), stdout);
        return 0;
    }
    if (cmd == "ls" && argc == 3) {
        for (const auto& e : pk->list())
            std::printf("%12llu  %s\n", static_cast<unsigned long long>(e.size), e.path.c_str());
        return 0;
    }
    if (cmd == "rm" && argc == 4) {
        if (!pk->del(argv[3]) || !pk->commit()) { std::fprintf(stderr, "rm failed\n"); return 1; }
        return 0;
    }
    if (cmd == "mv" && argc == 5) {
        if (!pk->move(argv[3], argv[4]) || !pk->commit()) { std::fprintf(stderr, "mv failed\n"); return 1; }
        return 0;
    }
    if (cmd == "cp" && argc == 5) {
        if (!pk->copy(argv[3], argv[4]) || !pk->commit()) { std::fprintf(stderr, "cp failed\n"); return 1; }
        return 0;
    }
    if (cmd == "compact" && argc == 3) {
        if (!pk->compact()) { std::fprintf(stderr, "compact failed\n"); return 1; }
        return 0;
    }
    return usage();
}
