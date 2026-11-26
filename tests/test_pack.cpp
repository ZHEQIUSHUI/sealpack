#include "check.hpp"
#include "sealpack.hpp"

#include <cstdio>   // std::remove — portable unlink
#include <string>

using namespace sealpack;

// CWD-relative so it's portable to Windows (no /tmp there).
static const char* kPath = "sealpack_test_pack.spk";

TEST_MAIN("pack") {
    std::remove(kPath);

    // ---- create, put (with dedup), commit ----
    {
        auto pk = Pack::create(kPath, "hunter2");
        CHECK(pk != nullptr);
        CHECK(pk->put("yolo/v1.axmodel", std::string("MODEL-A-BYTES")));
        CHECK(pk->put("yolo/v2.axmodel", std::string("MODEL-B-BYTES")));
        CHECK(pk->put("backup/v1.axmodel", std::string("MODEL-A-BYTES")));  // dedup
        CHECK(pk->commit());

        std::string got;
        CHECK(pk->get("yolo/v1.axmodel", &got));
        CHECK(got == "MODEL-A-BYTES");
        CHECK(pk->has("yolo/v2.axmodel"));
        CHECK(!pk->has("nope"));
    }

    // ---- reopen: persisted; wrong password rejected (THE guarantee) ----
    {
        CHECK(Pack::open(kPath, "wrong-password") == nullptr);
        auto pk = Pack::open(kPath, "hunter2");
        CHECK(pk != nullptr);
        std::string got;
        CHECK(pk->get("yolo/v2.axmodel", &got));
        CHECK(got == "MODEL-B-BYTES");
        CHECK(pk->get("backup/v1.axmodel", &got));
        CHECK(got == "MODEL-A-BYTES");            // dedup content intact

        auto ls = pk->list();
        CHECK_EQ(ls.size(), static_cast<size_t>(3));
        CHECK(ls[0].path == "backup/v1.axmodel");  // sorted by path
    }

    // ---- move / copy / overwrite / delete (path layer) ----
    {
        auto pk = Pack::open(kPath, "hunter2");
        CHECK(pk != nullptr);

        CHECK(pk->move("yolo/v1.axmodel", "archive/old.axmodel"));
        CHECK(!pk->has("yolo/v1.axmodel"));
        CHECK(pk->has("archive/old.axmodel"));

        CHECK(pk->copy("yolo/v2.axmodel", "yolo/v2-copy.axmodel"));  // 0 extra bytes
        std::string a, b;
        CHECK(pk->get("yolo/v2.axmodel", &a));
        CHECK(pk->get("yolo/v2-copy.axmodel", &b));
        CHECK(a == b);

        CHECK(pk->put("yolo/v2.axmodel", std::string("MODEL-B-V2")));  // overwrite
        CHECK(pk->get("yolo/v2.axmodel", &a));
        CHECK(a == "MODEL-B-V2");
        CHECK(pk->get("yolo/v2-copy.axmodel", &b));
        CHECK(b == "MODEL-B-BYTES");              // copy still points at old blob

        CHECK(pk->del("archive/old.axmodel"));
        CHECK(!pk->has("archive/old.axmodel"));
        CHECK(pk->commit());
    }

    // ---- compact: garbage dropped, data intact, stat correct ----
    {
        auto pk = Pack::open(kPath, "hunter2");
        CHECK(pk != nullptr);
        CHECK(pk->compact());
        std::string got;
        CHECK(pk->get("yolo/v2.axmodel", &got));
        CHECK(got == "MODEL-B-V2");
        Pack::Entry e;
        CHECK(pk->stat("yolo/v2.axmodel", &e));
        CHECK_EQ(e.size, static_cast<uint64_t>(10));  // "MODEL-B-V2"
    }

    // ---- reopen after compact ----
    {
        auto pk = Pack::open(kPath, "hunter2");
        CHECK(pk != nullptr);
        std::string got;
        CHECK(pk->get("yolo/v2.axmodel", &got));
        CHECK(got == "MODEL-B-V2");
    }

    // ---- rekey: change the password without re-encrypting the blobs ----
    {
        auto pk = Pack::open(kPath, "hunter2");
        CHECK(pk != nullptr);
        CHECK(pk->verify_password("hunter2"));            // the current password verifies
        CHECK(!pk->verify_password("nope"));
        CHECK(pk->rekey("hunter3"));
        pk.reset();
        CHECK(Pack::open(kPath, "hunter2") == nullptr);   // old password no longer opens
        auto d = Pack::open(kPath, "hunter3");
        CHECK(d != nullptr);
        std::string got;
        CHECK(d->get("yolo/v2.axmodel", &got));
        CHECK(got == "MODEL-B-V2");                        // blobs intact — rekey only rewrote the slot
    }

    std::remove(kPath);

    // ---- empty password: allowed, but protects nothing ----
    {
        const char* kEmpty = "sealpack_test_empty.spk";
        std::remove(kEmpty);
        auto pk = Pack::create(kEmpty, "");
        CHECK(pk != nullptr);
        CHECK(pk->put("m", std::string("X")));
        CHECK(pk->commit());
        pk.reset();

        auto ro = Pack::open(kEmpty, "");          // empty password opens it
        CHECK(ro != nullptr);
        std::string got;
        CHECK(ro->get("m", &got));
        CHECK(got == "X");
        ro.reset();
        CHECK(Pack::open(kEmpty, "not-empty") == nullptr);  // a non-empty pw does NOT
        std::remove(kEmpty);
    }
    // ---- more than one key: a second password, a recipient (X25519) ----
    {
        static const char* kMulti = "sealpack_test_multikey.spk";
        std::remove(kMulti);
        uint8_t sk[32], pk[32], other_sk[32], other_pk[32], again[32];
        CHECK(Pack::new_keypair(sk, pk));
        CHECK(Pack::new_keypair(other_sk, other_pk));
        Pack::public_key_of(sk, again);
        CHECK(std::string(reinterpret_cast<char*>(pk), 32) == std::string(reinterpret_cast<char*>(again), 32));
        {
            auto p = Pack::create(kMulti, "first");
            CHECK(p != nullptr);
            CHECK(p->put("m", std::string("X")));
            CHECK(p->commit());
            CHECK(p->key_count() == 1);
            CHECK(!p->has_recipient());
            CHECK(p->add_password("second"));
            CHECK(p->add_recipient(pk));
            CHECK(p->key_count() == 3);
            CHECK(p->has_recipient());
        }
        std::string got;
        for (const char* pw : {"first", "second"}) {
            auto p = Pack::open(kMulti, pw);
            CHECK(p != nullptr);
            CHECK(p->get("m", &got));
            CHECK(got == "X");
        }
        CHECK(Pack::open(kMulti, "third") == nullptr);
        CHECK(Pack::open(kMulti, "") == nullptr);
        // The secret key opens it; another key, or the public key as a password, does not.
        CHECK(Pack::open_with_key(kMulti, other_sk) == nullptr);
        CHECK(Pack::open(kMulti, std::string(reinterpret_cast<char*>(pk), 32)) == nullptr);
        {
            auto p = Pack::open_with_key(kMulti, sk);
            CHECK(p != nullptr);
            CHECK(p->get("m", &got));
            CHECK(got == "X");
        }
        // rekey changes the slot the pack was opened with and leaves the others.
        {
            auto p = Pack::open(kMulti, "second");
            CHECK(p != nullptr);
            CHECK(p->rekey("second-2"));
        }
        CHECK(Pack::open(kMulti, "second") == nullptr);
        CHECK(Pack::open(kMulti, "second-2") != nullptr);
        CHECK(Pack::open(kMulti, "first") != nullptr);
        CHECK(Pack::open_with_key(kMulti, sk) != nullptr);
        // Eight slots, no more.
        {
            auto p = Pack::open(kMulti, "first");
            CHECK(p != nullptr);
            for (int k = 3; k < 8; ++k) CHECK(p->add_password("pw" + std::to_string(k)));
            CHECK(p->key_count() == 8);
            CHECK(!p->add_password("one too many"));
            CHECK(!p->add_recipient(other_pk));
        }
        CHECK(Pack::open(kMulti, "pw7") != nullptr);
        std::remove(kMulti);
    }
}
