#include "check.hpp"
#include "store.hpp"

#include <cstdio>   // std::remove — portable unlink
#include <cstring>
#include <string>

using namespace sealpack;

// Relative to the test's working dir (the build tree), so it's portable to
// Windows too — a hardcoded /tmp path doesn't exist there.
static const char* kPath = "sealpack_test_store.spk";

TEST_MAIN("store") {
    std::remove(kPath);

    // Store now works in terms of a random master key (Pack wraps it per
    // password). The test drives the master key directly.
    uint8_t master[kKeyBytes];
    for (size_t i = 0; i < kKeyBytes; ++i) master[i] = static_cast<uint8_t>(i);
    KdfParams kdf{};  // default cost

    uint64_t blob_off = 0, manifest_off = 0;
    const std::string blob = "the model bytes";
    const std::string manifest = "serialized manifest";

    // ---- create, append, commit ----
    {
        auto st = Store::create(kPath, master, kdf);
        CHECK(st != nullptr);
        CHECK_EQ(st->root().len, static_cast<uint64_t>(0));  // empty pack

        blob_off = st->append(blob.data(), blob.size());
        CHECK(blob_off >= 856);  // past header(24) + 8 key slots(704) + 2 superblocks(128)
        manifest_off = st->append(manifest.data(), manifest.size());
        CHECK(st->commit(manifest_off, manifest.size(), master));
        CHECK_EQ(st->root().offset, manifest_off);
        CHECK_EQ(st->root().len, manifest.size());

        std::string got(blob.size(), '\0');
        CHECK(st->read_at(blob_off, &got[0], blob.size()));
        CHECK(got == blob);
    }

    // ---- key slots: create leaves them empty; write/read one back ----
    {
        auto st = Store::open(kPath, master);
        CHECK(st != nullptr);
        CHECK(st->slot(0).empty());  // Pack fills slot 0; raw Store::create leaves all empty

        KeySlot s{};
        for (size_t i = 0; i < kSaltBytes; ++i)    s.salt[i]    = static_cast<uint8_t>(0xA0 + i);
        for (size_t i = 0; i < kWrappedBytes; ++i) s.wrapped[i] = static_cast<uint8_t>(i);
        CHECK(st->write_slot(3, s));
        CHECK(!st->slot(3).empty());
        KeySlot r = st->slot(3);
        CHECK(std::memcmp(r.salt, s.salt, kSaltBytes) == 0);
        CHECK(std::memcmp(r.wrapped, s.wrapped, kWrappedBytes) == 0);
        CHECK(st->slot(0).empty());  // neighbours untouched
    }

    // ---- reopen: kdf + slots readable WITHOUT the master key; root recovered ----
    {
        KdfParams k2{};
        KeySlot slots[kNumKeySlots];
        CHECK(Store::read_meta(kPath, &k2, slots));
        CHECK_EQ(k2.nb_blocks, kdf.nb_blocks);
        CHECK(!slots[3].empty());   // the slot we wrote survived
        CHECK(slots[0].empty());

        auto st = Store::open(kPath, master);
        CHECK(st != nullptr);
        CHECK_EQ(st->root().offset, manifest_off);
        CHECK_EQ(st->root().len, manifest.size());

        std::string got(manifest.size(), '\0');
        CHECK(st->read_at(st->root().offset, &got[0], st->root().len));
        CHECK(got == manifest);
    }

    // ---- second commit flips to the other superblock (seq advances) ----
    {
        auto st = Store::open(kPath, master);
        CHECK(st != nullptr);
        const std::string m2 = "second manifest, larger";
        uint64_t off2 = st->append(m2.data(), m2.size());
        CHECK(st->commit(off2, m2.size(), master));
        CHECK_EQ(st->root().len, m2.size());
    }
    {
        auto st = Store::open(kPath, master);  // must pick the newer superblock
        CHECK(st != nullptr);
        CHECK_EQ(st->root().len, static_cast<uint64_t>(std::string("second manifest, larger").size()));
    }

    // ---- wrong master key: superblocks won't decrypt -> open fails ----
    {
        uint8_t bad[kKeyBytes];
        for (size_t i = 0; i < kKeyBytes; ++i) bad[i] = static_cast<uint8_t>(i + 1);
        auto st = Store::open(kPath, bad);
        CHECK(st == nullptr);
    }

    std::remove(kPath);
}
