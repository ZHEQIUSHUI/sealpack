#include "check.hpp"
#include "sealpack.hpp"

#include <string>

#include <unistd.h>

using namespace sealpack;

static const char* kPath = "/tmp/sealpack_test_pack.sealpack";

TEST_MAIN("pack") {
    ::unlink(kPath);

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

    // ---- key slots: addkey / rekey / rmkey (data blobs never re-encrypted) ----
    {
        auto pk = Pack::open(kPath, "hunter2");
        CHECK(pk != nullptr);
        CHECK_EQ(pk->num_keys(), 1);
        CHECK_EQ(pk->opened_slot(), 0);

        // a second password opens the SAME pack (multi-key)
        CHECK_EQ(pk->addkey("second-pw"), 1);
        CHECK_EQ(pk->num_keys(), 2);
        pk.reset();  // slots persist immediately — no commit needed

        auto b = Pack::open(kPath, "second-pw");
        CHECK(b != nullptr);
        CHECK_EQ(b->opened_slot(), 1);
        std::string got;
        CHECK(b->get("yolo/v2.axmodel", &got));
        CHECK(got == "MODEL-B-V2");        // second password decrypts the same data
        b.reset();

        // rekey slot 0: old password dies, new one works, blobs intact
        auto c = Pack::open(kPath, "hunter2");
        CHECK(c != nullptr);
        CHECK(c->rekey("hunter3"));
        c.reset();
        CHECK(Pack::open(kPath, "hunter2") == nullptr);   // old password no longer opens
        auto d = Pack::open(kPath, "hunter3");
        CHECK(d != nullptr);
        CHECK(d->get("yolo/v2.axmodel", &got));
        CHECK(got == "MODEL-B-V2");
        d.reset();

        // rmkey: revoke slot 1 from slot 0; can't remove the in-use / last slot
        auto e = Pack::open(kPath, "hunter3");
        CHECK(e != nullptr);
        CHECK_EQ(e->opened_slot(), 0);
        CHECK(e->rmkey(1));
        CHECK_EQ(e->num_keys(), 1);
        CHECK(!e->rmkey(0));              // refuse: in use AND last remaining
        e.reset();
        CHECK(Pack::open(kPath, "second-pw") == nullptr);  // revoked password is dead
        CHECK(Pack::open(kPath, "hunter3") != nullptr);
    }

    ::unlink(kPath);

    // ---- empty password: allowed, but protects nothing ----
    {
        const char* kEmpty = "/tmp/sealpack_test_empty.sealpack";
        ::unlink(kEmpty);
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
        ::unlink(kEmpty);
    }
}
