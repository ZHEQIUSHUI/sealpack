#include "check.hpp"
#include "index.hpp"

#include <string>

using namespace sealpack;

static std::string h(uint8_t b) { return std::string(32, static_cast<char>(b)); }

TEST_MAIN("index") {
    // ---- normalize_path: fs-style + no escape ----
    CHECK(normalize_path("yolo/v2.axmodel") == "yolo/v2.axmodel");
    CHECK(normalize_path("/yolo//v2.axmodel/") == "yolo/v2.axmodel");  // collapse
    CHECK(normalize_path("a/./b") == "a/b");                            // drop "."
    CHECK(normalize_path("../etc/passwd") == "");                       // no escape
    CHECK(normalize_path("a/../b") == "");                              // any ".."
    CHECK(normalize_path("") == "");
    CHECK(normalize_path("///") == "");

    // ---- serialize round-trip with dedup + per-path mtime ----
    Index idx;
    idx.blobs[h(1)] = BlobRef{100, 50, 42, 2};
    idx.blobs[h(2)] = BlobRef{200, 60, 55, 1};
    idx.paths["yolo/v1.axmodel"] = PathEntry{h(1), 1700000000};
    idx.paths["yolo/v2.axmodel"] = PathEntry{h(1), 1700000100};  // same blob, own mtime
    idx.paths["depth.axmodel"]   = PathEntry{h(2), 1700000200};

    std::string bytes = serialize(idx);
    CHECK(!bytes.empty());

    Index got;
    CHECK(deserialize(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(), &got));
    CHECK_EQ(got.blobs.size(), static_cast<size_t>(2));
    CHECK_EQ(got.paths.size(), static_cast<size_t>(3));
    CHECK(got.blobs[h(1)] == (BlobRef{100, 50, 42, 2}));
    CHECK(got.blobs[h(2)] == (BlobRef{200, 60, 55, 1}));
    // two paths dedup to one blob, each keeps its own mtime
    CHECK(got.paths["yolo/v1.axmodel"] == (PathEntry{h(1), 1700000000}));
    CHECK(got.paths["yolo/v2.axmodel"].hash == h(1));
    CHECK(got.paths["yolo/v2.axmodel"].mtime == static_cast<uint64_t>(1700000100));

    // ---- defensive: truncated / garbage input rejected ----
    CHECK(!deserialize(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size() / 2, &got));
    uint8_t junk[4] = {0, 0, 0, 0};
    CHECK(!deserialize(junk, sizeof junk, &got));
}
