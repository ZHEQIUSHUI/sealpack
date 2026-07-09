#include "check.hpp"
#include "store.hpp"

#include <cstring>
#include <string>

#include <unistd.h>

using namespace sealpack;

static const char* kPath = "/tmp/sealpack_test_store.sealpack";

TEST_MAIN("store") {
    ::unlink(kPath);

    uint8_t key[kKeyBytes];
    for (size_t i = 0; i < kKeyBytes; ++i) key[i] = static_cast<uint8_t>(i);
    StoreHeader hdr{};
    for (size_t i = 0; i < kSaltBytes; ++i) hdr.salt[i] = static_cast<uint8_t>(0xA0 + i);
    hdr.kdf = KdfParams{};

    uint64_t blob_off = 0, manifest_off = 0;
    const std::string blob = "the model bytes";
    const std::string manifest = "serialized manifest";

    // ---- create, append, commit ----
    {
        auto st = Store::create(kPath, hdr, key);
        CHECK(st != nullptr);
        CHECK_EQ(st->root().len, static_cast<uint64_t>(0));  // empty pack

        blob_off = st->append(blob.data(), blob.size());
        CHECK(blob_off >= 168);  // past the fixed front matter
        manifest_off = st->append(manifest.data(), manifest.size());
        CHECK(st->commit(manifest_off, manifest.size(), key));
        CHECK_EQ(st->root().offset, manifest_off);
        CHECK_EQ(st->root().len, manifest.size());

        std::string got(blob.size(), '\0');
        CHECK(st->read_at(blob_off, &got[0], blob.size()));
        CHECK(got == blob);
    }

    // ---- reopen: header + root recovered, data intact ----
    {
        StoreHeader h2{};
        CHECK(Store::read_header(kPath, &h2));
        CHECK(std::memcmp(h2.salt, hdr.salt, kSaltBytes) == 0);

        auto st = Store::open(kPath, key);
        CHECK(st != nullptr);
        CHECK_EQ(st->root().offset, manifest_off);
        CHECK_EQ(st->root().len, manifest.size());

        std::string got(manifest.size(), '\0');
        CHECK(st->read_at(st->root().offset, &got[0], st->root().len));
        CHECK(got == manifest);
    }

    // ---- second commit flips to the other superblock (seq advances) ----
    {
        auto st = Store::open(kPath, key);
        CHECK(st != nullptr);
        const std::string m2 = "second manifest, larger";
        uint64_t off2 = st->append(m2.data(), m2.size());
        CHECK(st->commit(off2, m2.size(), key));
        CHECK_EQ(st->root().len, m2.size());
    }
    {
        auto st = Store::open(kPath, key);  // must pick the newer superblock
        CHECK(st != nullptr);
        CHECK_EQ(st->root().len, static_cast<uint64_t>(std::string("second manifest, larger").size()));
    }

    // ---- wrong key: superblocks won't decrypt -> open fails ----
    {
        uint8_t bad[kKeyBytes];
        for (size_t i = 0; i < kKeyBytes; ++i) bad[i] = static_cast<uint8_t>(i + 1);
        auto st = Store::open(kPath, bad);
        CHECK(st == nullptr);
    }

    ::unlink(kPath);
}
