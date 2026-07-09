#include "check.hpp"
#include "sealpack.hpp"

#include <fstream>
#include <string>

#include <unistd.h>

using namespace sealpack;

// Superblock slots sit at fixed offsets (see the layout in src/store.cpp):
// header(24) + 8 key slots(8*88 = 704), then the two 64-byte superblocks.
//   728  Superblock A   792  Superblock B
static constexpr long kSbA = 728;
static constexpr long kSbB = 792;
static constexpr long kSbSize = 64;

static const char* kPath = "/tmp/sealpack_test_crash.sealpack";

// Overwrite `len` bytes at `off` with 0xFF — simulates a torn/garbage write.
static void corrupt(long off, long len) {
    std::fstream f(kPath, std::ios::in | std::ios::out | std::ios::binary);
    std::string junk(static_cast<size_t>(len), '\xFF');
    f.seekp(off);
    f.write(junk.data(), len);
}

// Build a pack committed twice: S1 has {A}, S2 has {A,B}. The two commits land
// in alternating superblock slots, so exactly one slot holds each state.
static void build_two_commits() {
    ::unlink(kPath);
    auto pk = Pack::create(kPath, "pw");
    pk->put("A", std::string("aaa"));
    pk->commit();  // S1: {A}
    pk->put("B", std::string("bbb"));
    pk->commit();  // S2: {A,B}
}

TEST_MAIN("crash") {
    // ---- corrupt superblock A: open must fall back to the other slot ----
    build_two_commits();
    corrupt(kSbA, kSbSize);
    {
        auto pk = Pack::open(kPath, "pw");
        CHECK(pk != nullptr);        // recovered from the intact superblock
        CHECK(pk->has("A"));         // A exists in every committed state
        std::string got;
        CHECK(pk->get("A", &got));
        CHECK(got == "aaa");         // data not damaged
    }

    // ---- corrupt superblock B: same guarantee, other slot ----
    build_two_commits();
    corrupt(kSbB, kSbSize);
    {
        auto pk = Pack::open(kPath, "pw");
        CHECK(pk != nullptr);
        CHECK(pk->has("A"));
        std::string got;
        CHECK(pk->get("A", &got));
        CHECK(got == "aaa");
    }

    // ---- both superblocks corrupt: refuse to open (never fabricate a state) ----
    build_two_commits();
    corrupt(kSbA, kSbSize);
    corrupt(kSbB, kSbSize);
    {
        auto pk = Pack::open(kPath, "pw");
        CHECK(pk == nullptr);
    }

    // ---- interrupted append (uncommitted tail): last commit stays intact ----
    // Simulate a crash mid-append after S2: extra bytes at EOF that no
    // superblock references. Reopen must ignore them and see exactly S2.
    build_two_commits();
    {
        std::ofstream f(kPath, std::ios::app | std::ios::binary);
        std::string junk(500, '\xAB');
        f.write(junk.data(), junk.size());
    }
    {
        auto pk = Pack::open(kPath, "pw");
        CHECK(pk != nullptr);
        CHECK(pk->has("A"));
        CHECK(pk->has("B"));         // S2 fully intact, junk ignored
        std::string got;
        CHECK(pk->get("B", &got));
        CHECK(got == "bbb");
    }

    ::unlink(kPath);
}
