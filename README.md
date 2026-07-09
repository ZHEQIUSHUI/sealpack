# sealpack

A single-file, password-encrypted, content-addressed blob store with crash-safe
atomic commits. Think "an encrypted git packfile you can add/move/delete files
in" — one file on disk, many logical files inside, nothing readable without the
password.

**Zero external dependencies** — [monocypher](https://monocypher.org) is
vendored (two files), so `git clone && cmake` just works, on device too.

## Why

Shipping an encrypted bundle of models/files that gets updated over time.
LevelDB almost fits but sprays many small files and isn't encrypted. sealpack is
one file, encrypted, deduplicated, and safe across power loss.

## Properties

| | |
|---|---|
| **Single file** | header + append-only blobs + manifest + dual superblock |
| **Encrypted** | random master key + XChaCha20-Poly1305; each password wraps the master key via Argon2id. No password, no plaintext; no backdoor, no recovery key |
| **Key slots** | up to 8 passwords open one pack (LUKS-style). `rekey`/`addkey`/`rmkey` rewrite an 88B slot — blobs never move, so rotation is instant on a multi-GB pack |
| **Deduplicated** | content-addressed (BLAKE2b): identical bytes stored once; `move`/`copy` are O(1) |
| **Crash-safe** | append-only + atomic double-superblock commit — a power loss leaves the old state or the new one, never half-written |
| **Two APIs** | C++ `Pack` class (core) + C ABI (`sealpack.h`) wrapper for FFI |
| **File-manager ready** | filesystem-style paths, `move`/`copy`/`list`(size+mtime)/`stat` — a UI splits paths on `/` into a folder tree |

## Use it

**C++**
```cpp
#include "sealpack.hpp"
auto pk = sealpack::Pack::create("models.sealpack", "hunter2");
pk->put("yolo/v2.axmodel", bytes);
pk->commit();                          // durable + atomic here

auto ro = sealpack::Pack::open("models.sealpack", "hunter2");  // null on bad pw
std::string data;
ro->get("yolo/v2.axmodel", &data);     // decrypts just this blob
```

**C**
```c
#include "sealpack.h"
sealpack_t* sp = sealpack_open("models.sealpack", "hunter2");
void* out; size_t n;
sealpack_get(sp, "yolo/v2.axmodel", &out, &n);
sealpack_free(out);
sealpack_close(sp);
```

**CLI** (password from `$SEALPACK_PASSWORD`)
```bash
sealpack create  models.sealpack
sealpack add     models.sealpack yolo/v2.axmodel model.bin
sealpack cp      models.sealpack yolo/v2.axmodel backup/v2.axmodel   # 0 extra bytes
sealpack ls      models.sealpack
sealpack get     models.sealpack yolo/v2.axmodel out.bin
sealpack web     models.sealpack                         # browser file-manager (+ Keys panel)

# passwords / key slots
sealpack keys    models.sealpack                         # how many slots are in use
SEALPACK_NEW_PASSWORD=… sealpack rekey  models.sealpack  # change this password
SEALPACK_NEW_PASSWORD=… sealpack addkey models.sealpack  # add another password
sealpack rmkey   models.sealpack 1                       # revoke slot 1
```

## On-disk format

```
0    Header       "SEALPACK" + version + Argon2 params (plaintext)
24   KeySlot[8]   88B each: salt + AEAD-wrapped master key. Empty slot = all-zero salt
728  Superblock A ┐ 64B each, AEAD{seq, manifest_off, manifest_len} under the master key.
792  Superblock B ┘ active = larger seq with a valid MAC.
856  Data region  append-only: encrypted blobs + encrypted manifests (nonce|mac|cipher)
```

## Encryption — safe even with the source public

The data is encrypted under a **random master key**, never a password directly.
Each password only *wraps* that master key into one of 8 key slots:
`password + slot salt → Argon2id → key-encryption key → wrap(master key)`. On
disk there's just the public salts, KDF parameters, ciphertext, and MACs — no
secret at rest. Security rests on the master key, not on hiding the algorithm
(Kerckhoffs's principle), so publishing this source changes nothing, and every
brute-force guess must pay a full Argon2id (memory-hard) run. A wrong password
unwraps to garbage → the AEAD MAC fails → open is refused.

**Key slots — multiple passwords, instant rotation.** Because the master key is
wrapped (not derived), up to 8 passwords can open one pack, each in its own slot:

- `rekey`  — change the password in the slot you opened with (the old one stops working)
- `addkey` — wrap the master key under another password (both now open the pack)
- `rmkey`  — revoke a slot (never the one in use, never the last remaining)

Each rewrites just an 88-byte slot — the data blobs are never re-encrypted, so
rotating a password on a multi-GB pack is instant. An **empty password** (`""`)
is accepted but wraps the key under a public salt only, i.e. anyone can open it —
use it solely for deliberately unprotected/public packs.

## Crash safety

Blobs are **append-only** (committed bytes are never overwritten). A commit:

1. `fsync` the appended blobs + manifest,
2. write the *inactive* superblock with `seq+1` pointing at the new manifest,
3. `fsync` it — this fsync is the single commit point.

Crash before step 3 finishes → the old superblock still wins (old state). A torn
superblock write → its MAC fails → the other slot is used. So open always sees a
fully-committed state; `tests/test_crash.cpp` corrupts superblocks and appends
junk tails to prove it.

## Build & test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure   # crypto / index / store / pack / crash / capi
```

## License

The sealpack code is BSD-3-Clause. Vendored monocypher is CC0/BSD-2 (see
`third_party/monocypher`).
