# sealpack — design & maintenance notes

Audience: whoever maintains sealpack (not end users — for usage see `README.md`).
This is the "how it's built and why, and what will bite you" reference.

---

## 1. What it is / goals

A single-file, encrypted, content-addressed blob store. Think "an encrypted git
packfile you can `add`/`get`/`rm`/`mv`/`cp` files into", used to ship a set of
model files (and now also small config/text files) as **one password-protected
`.spk`**.

Design goals, in priority order:

1. **Confidential at rest** — no password, no plaintext. The source being public
   must not weaken it (Kerckhoffs).
2. **Crash-safe** — a power loss mid-write leaves either the old state or the new
   state, never a half-written pack.
3. **Cheap password change** — re-keying a multi-GB pack must be instant.
4. **Zero-dependency, portable** — vendored crypto, builds on Linux/macOS and
   cross-compiles for Android/AX with no system libs.
5. **Embeddable** — a clean C++ core + stable C ABI so a runtime can open a pack
   and load blobs straight from memory (no plaintext on disk).

Non-goals: concurrent multi-writer access, network serving (the `web` UI is a
localhost convenience, not a server), per-file passwords.

---

## 2. Module map

Layered, each with its own `ctest` target (CMake registers them via `foreach`):

```
crypto   monocypher wrapper: derive_key (Argon2id), AEAD (XChaCha20-Poly1305),
         BLAKE2b-256 content hash, OS RNG. No hand-rolled crypto — ever.
index    in-memory manifest: blobs[] (hash→offset/len) + paths[] (path→hash,
         +mtime). serialize/parse. normalize_path() rejects `..` escapes.
os       platform seam (os.hpp): file open/pread/pwrite/sync/rename/remove +
         now_seconds, behind one interface. Backends: os_posix.cpp (Linux/macOS/
         Android) and os_win32.cpp (Windows). store/pack call only os::.
store    on-disk file layout + I/O: header, key slots, double superblock,
         append-only data region, atomic commit (sync via os::sync_file).
pack     the Pack class — ties crypto+index+store together. CRUD, move/copy
         (O(1), CAS), compact, rekey, verify_password. This is the core API.
capi     extern "C" wrapper over Pack (opaque handle) for non-C++ hosts.
```

CLI/UI sits on top (in `cli/`, only linked into the `sealpack` executable — the
core library never touches HTTP or a terminal). Cross-platform on all three OSes;
the console/editor specifics sit behind the `cli/platform.hpp` shim (§14).

```
cli/main.cpp          arg parsing, interactive shell (tab completion), one-shot
cli/web.cpp           `sealpack web` — localhost file-manager UI + REST API
cli/preview.hpp       shared text-vs-binary sniffing + MIME guess (cat + web)
cli/platform.hpp      console/editor seam: tty, no-echo password, $EDITOR launch
  platform_posix.cpp    termios / mkstemp / system+sys/wait
  platform_win32.cpp    SetConsoleMode / GetTempFileNameW / _wsystem
```

The shell's line editing + Tab completion come from vendored **linenoise-ng**
(`third_party/linenoise`, BSD, cross-platform — used only by the CLI, never the
core). See §15 for the completion design and the one local patch it needed.

Public headers: `include/sealpack.hpp` (C++ `Pack`) and `include/sealpack.h`
(C ABI). Nothing in `src/` is a public header.

---

## 3. On-disk format (v2)

Fixed-offset front matter, then an append-only data region. Authoritative
constants live in `src/store.cpp` (`kHeaderSize` … `kDataStart`).

```
off   size            what
0     24              Header:  "SEALPACK" magic(8) + version u32(=2) + Argon2 params(3×u32)
24    88 × 8 = 704    KeySlot[8]: each = salt(16) + AEAD-wrapped master key(72)
728   64              Superblock A ┐ AEAD{seq u64, root_off u64, root_len u64}
792   64              Superblock B ┘ under the MASTER key (nonce24+mac16+cipher24)
856   …               Data region: append-only encrypted blobs + manifests
```

- **Master key** is a random 32 bytes, generated at `create`. It — not the
  password — encrypts the superblocks and every data blob.
- Each **KeySlot** holds `AEAD_wrap(master_key)` under a KEK =
  `Argon2id(password, slot.salt)`. Opening tries each non-empty slot until one
  unwraps. (The 8-slot array is a LUKS-style holdover from a multi-password
  phase — see WORKLOG. Today only **slot 0** is used, but the on-disk shape kept
  the array so the format didn't churn.)
- **root_off/root_len** in the active superblock point at the current serialized
  manifest (index) in the data region.

Wrapped-key size = `kNonceBytes(24) + kMacBytes(16) + kKeyBytes(32) = 72`.
Slot size = `kSaltBytes(16) + 72 = 88`.

### v1 → v2 is NOT compatible

v1 derived the data key directly from the password (no master key, no slots).
v2 (`kVersion = 2`) inserted the 704-byte slot array, so **every offset moved**
(superblocks 40/104 → 728/792, data 168 → 856). There is no in-place upgrade;
v1 packs must be re-created. Any test or tool that hardcodes offsets must use the
v2 numbers (this bit `test_crash` once — it had 40/104 baked in).

---

## 4. Key-wrapping & rekey

Why: re-deriving and re-encrypting a multi-GB pack on every password change is
unacceptable. With key-wrapping the data is encrypted under the master key, which
never changes; the password only protects the *wrapped copy* of it.

`rekey(new_password)`:
1. Unwrap the master key from an existing slot (proves the caller's authority —
   in practice the pack is already open, so opening *was* the proof).
2. Fresh random salt → `Argon2id(new_password, salt)` → KEK.
3. `AEAD_wrap(master_key)` under the new KEK → write the single 88-byte slot 0
   (one `pwrite` + `fsync`). **The data region is never touched** → instant.

`verify_password` just attempts an unwrap. Empty password is allowed (wraps under
a KEK derived from ""), which means *no protection* — the CLI/web warn about it.

---

## 5. Crash safety

Invariant: **either the old committed state or the new one, never a mix.**

- **Data blobs are append-only.** A new blob is written past the end; nothing
  in-place is ever overwritten. A crash mid-append just leaves junk past the last
  committed superblock, which is ignored on next open (the manifest doesn't
  reference it).
- **Double superblock, alternating.** Commit writes the *inactive* superblock
  (A/B) with `seq = active.seq + 1`, then fsyncs. Open picks the superblock with
  the **larger seq and a valid MAC**. The superblock fsync is the single atomic
  commit point: before it, the old superblock is still active; after it, the new
  one is. A torn superblock write fails its MAC → the other (older) one wins.
- **`durable_sync` is platform-split** (`src/store.cpp`):
  - Linux: `fdatasync` (data-only, faster).
  - macOS: **`fcntl(F_FULLFSYNC)`** — plain `fsync` on macOS only pushes to the
    drive cache, not the platter; `fdatasync` doesn't exist. `F_FULLFSYNC` is the
    real barrier. (Fixed in `e2e2792` after macOS CI surfaced it.)

`test_crash` exercises this: truncated/corrupt superblocks, junk tails → verifies
the pack still opens to the last good state.

---

## 6. Content addressing / dedup

Blobs are keyed by **BLAKE2b-256(content)**. Identical content is stored once.
`move`/`copy` are O(1): they only edit the path→hash map, never the blob. This is
the CAS sweet spot and why `cp` of a 400 MB model is free. `compact` walks live
hashes and rewrites the data region without the garbage (the only O(n) op).

---

## 7. CLI surface

`cli/main.cpp`. Two entry modes share one `do_command(Pack*, args)`:

- **Interactive shell** — `sealpack <pack>`: prompt for the password once
  (termios echo off, never in argv/history), open, drop into a mini shell that
  reuses the open pack (one Argon2 for the whole session).
- **One-shot** — `sealpack <cmd> <pack> [args]`: on a TTY prompts for the
  password; non-TTY reads `$SEALPACK_PASSWORD` (for scripts/CI).

Commands: `create add get cat edit ls rm mv cp stat compact rekey web`.
`ls`/`stat` print human-readable sizes (`human_size`). `is_command()` and both
help texts (`shell_help`, `usage`) must be kept in sync when adding a command.

- **`cat <path>`** — decrypt + print, but only if `looks_text` (§9); binary is
  refused with a pointer to `get`.
- **`edit <path>`** — decrypt to a 0600 temp file (kept with the original
  extension so the editor gets syntax mode), launch `$VISUAL`/`$EDITOR`
  (default `vi`), read back, and if changed `put`+`commit`. No change → no
  rewrite. Binary or non-TTY is refused. `edit_in_editor()` uses `mkstemps` for
  the suffix.

---

## 8. Web UI

`sealpack web <pack> [port]` → localhost file manager. The C++ side holds the
open pack + master key; the browser only draws UI and calls a REST API.

- **Bound to 127.0.0.1 only.** Every `/api/*` call must carry a per-start session
  **token** (header `X-Sealpack-Token` or `?t=`), so another site (CSRF) or a
  stray same-host process can't drive it.
- REST: `GET /api/list`, `GET /api/get` (download, attachment),
  `GET /api/view` (inline preview, §9), `POST /api/put|del|move|copy|rekey`.
  Every mutating call auto-commits.
- Front-end is one embedded HTML/JS string (`kIndexHtml`), vanilla, no build
  step. `%%TOKEN%%` is replaced per server start. Folder-tree navigation +
  breadcrumb over the flat path list; a **right-docked preview/edit panel**.

The core library never links httplib — it's `cli/`-only. httplib is vendored in
`third_party/httplib`.

---

## 9. Human-readable preview & edit

Shared logic in `cli/preview.hpp` (used by both `cat` and the web `/api/view`)
so terminal and browser agree on what's safe to render.

- **`looks_text(bytes)`** — scans the head (≤8 KiB): a NUL byte → binary;
  >5% C0 control chars (excluding tab/newline/CR) → binary; bytes ≥ 0x80 are
  **not** counted, so UTF-8 stays text.
- **`mime_by_ext(path)`** — for inline rendering. Only image types are meant to
  be *rendered*; `html/svg/js/css` deliberately map to `text/plain` so the
  browser shows their **source** rather than executing them (the pack could hold
  a hostile `.svg`/`.html`, and the web UI is same-origin with the token).

`GET /api/view`:
- image ext → served inline with its `image/*` type;
- known-text ext **or** sniffed text → `text/plain; charset=utf-8`, inline,
  capped at 1 MiB (a giant log can't hang the tab); when capped it sets
  **`X-Sealpack-Truncated: 1`**;
- otherwise → **415** ("binary — not previewable").

Web edit flow: view → **Edit** swaps `<pre>` for `<textarea>` → **Save** POSTs the
buffer to `/api/put` → back to view + list refresh. **Editing is disabled when
`X-Sealpack-Truncated` is set** — otherwise saving would persist the truncated
copy and destroy the file. Images are view-only.

---

## 10. Runtime integration (noqi-vision-runtime)

sealpack is a **git submodule** of that repo (`third_party/sealpack`). Details
live there, but the contract sealpack must not break:

- `Pack::get(path, &blob)` returns raw bytes → the runtime's `ModelBase::Load`
  loads models from memory (`Runner::LoadMem`), no plaintext on disk.
- **ncnn is two files** (`.param` + `.bin`) stored as siblings; the runtime
  merges them into `[param_len:u64][param][bin]`. Gotcha it hit: ncnn's
  `load_model(mem)` is **zero-copy** — it keeps the pointer, so the caller must
  own the bin buffer for the model's lifetime (a temp blob → segfault). Not a
  sealpack bug, but sealpack's memory-load API is what surfaces it.
- The runtime also pulls **non-model** blobs now: `events/config.yaml`
  (broadcast-text templates) is bundled into every pack, and the runtime loads
  it via `Pack::get` → a `.spk` is self-contained (models + text).

---

## 11. Build & test

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
ctest --test-dir build          # crypto/index/store/pack/patch/crash/capi
```

The CLI binary is `build/sealpack` (target `sealpack-cli`,
`OUTPUT_NAME sealpack`). CI runs on ubuntu + macos with zero system deps.

---

## 12. Invariants & gotchas (read before you touch things)

- **Never hand-roll crypto.** All primitives go through monocypher. RNG is OS
  `getrandom`/`/dev/urandom`, never anything derived.
- **Android NDK (API < 28)**: the `getrandom` libc wrapper is undeclared → call
  `syscall(SYS_getrandom, …)` directly (`crypto.cpp`, fixed in `a084594`).
- **C ABI struct tag** can't be `sealpack` (collides with the C++ namespace) —
  it's `sealpack_handle`.
- **Format offsets are v2.** Don't hardcode superblock/data offsets; use the
  `store.cpp` constants. v1↔v2 are incompatible.
- **macOS durability** needs `F_FULLFSYNC`, not `fsync`.
- **Adding a CLI command** = edit `do_command` + `is_command` + `shell_help` +
  `usage` + the `kCmds[]`/`cmd_completes_paths` list in `completion_cb` (so Tab
  completes it too) — five places. A command that opens no pack or is otherwise
  special (like `create`, `web`) is instead a special case in `main()`, not a
  `do_command` verb. (`merge` opens a *second* pack but is still a normal verb —
  the target is the already-open pack, the source is just an argument it opens.)
- **`cat`/`edit`/web preview must refuse binary** via `looks_text` — dumping a
  model into a terminal or an editor is the failure mode we're guarding.
- **Web is localhost + token only.** Don't add a bind-address option that
  defaults to `0.0.0.0`, and don't render pack-controlled HTML/SVG.
- **Pack-controlled strings are untrusted — everywhere they leave the pack.** A
  `.spk` may be hostile and `normalize_path` allows any byte except `/`/`..` (incl.
  NUL/CR/LF/quotes). So: the web front-end builds rows with `textContent` +
  `addEventListener` closures (never a pack name in `innerHTML` or `on*="…"` — that
  was a stored XSS); an HTTP header value built from a pack path must be scrubbed
  (`safe_filename()` for `Content-Disposition` — raw CR/LF/NUL there was header
  injection); and the CLI `edit` only accepts a plain `[A-Za-z0-9._-]` extension
  and shell-escapes the temp path (a `'` in the name was `system()` injection).
  `esc()`/`safe_filename()` are for these sinks; never skip them.
- **The plaintext header is parsed before authentication.** `read_header_kdf`
  validates the Argon2 params (`nb_lanes` ≥ 1, `nb_passes` ≥ 1,
  `8·nb_lanes ≤ nb_blocks ≤ 4 GiB`) — a crafted `nb_lanes=0` divided-by-zero in
  monocypher (SIGFPE on `open`, pre-auth). Any new plaintext-header field must be
  range-checked there before it reaches crypto.
- **`edit` only writes back on a clean editor exit** (`WIFEXITED && WEXITSTATUS==0`
  / a 0 return from `_wsystem` on Windows). A crash or a deliberate `:cq` abort
  must not persist a truncated buffer.
- **All OS calls in the core go through `os::`** (`src/os.hpp`). Don't reintroduce
  a raw `::open`/`::pread`/`std::rename` in store/pack — add it to the seam so
  both backends stay in sync. Keep os_posix.cpp and os_win32.cpp semantically
  identical (the ctest suite is the cross-backend contract).
- **CLI terminal/editor calls go through `cli/platform.hpp`.** No `termios` /
  `isatty` / `mkstemp` / `sys/wait` directly in `main.cpp`/`web.cpp` — route them
  through the shim so Windows keeps building. Same for tests: no `<unistd.h>`,
  `std::remove` over `::unlink`, CWD-relative pack paths (§14).
- **Don't open the same pack file twice concurrently.** `os_win32` opens with
  `FILE_SHARE_READ` only, so a second read-write open of a file already open R/W
  fails on Windows (POSIX permissively allows it — a test that did this passed on
  Linux and crashed under wine). Concurrent multi-writer is a non-goal anyway;
  `diff` opens two *different* packs, which is fine.
- **The 8 key slots are load-bearing format, not a feature.** Single-password is
  the product decision; keep the array on disk.

---

## 13. Known gaps / TODO (for the maintenance session)

- Only slot 0 is used; multi-password was intentionally cut. If it ever comes
  back, `addkey`/`rmkey` + slot notes/labels were the sketched design.
- `web` has no auth beyond the session token and no TLS (localhost only by
  design). Revisit if it ever needs to bind non-loopback.
- `compact` is O(n) and single-shot; no incremental GC.
- No streaming API — `get` returns the whole blob in memory. Fine for models
  today; a multi-GB single blob would want chunking.
- Web edit has no concurrency guard: two tabs editing the same file → last-write
  wins (the pack mutex serializes the writes, but there's no conflict detection).
- `looks_text` is a heuristic; a UTF-16/BOM text file reads as binary. Add BOM
  sniffing if that comes up.

---

## 14. Portability (Linux / macOS / Windows)

Goal: the **whole tool** (core library + CLI + web UI) builds and the full ctest
suite passes on Linux, macOS, and Windows. Two seams isolate the OS specifics;
everything else is portable C++17.

- **Core I/O seam: `src/os.hpp`.** Everything OS-specific the core touches — file
  open/read/write/sync/rename/remove + wall-clock — is declared there and
  implemented once per platform:
  - `os_posix.cpp` — Linux/macOS/Android. `open(O_CLOEXEC)`, `pread`/`pwrite`,
    `fdatasync`/`F_FULLFSYNC`, `rename`, `unlink`.
  - `os_win32.cpp` — Windows. `CreateFileW` (non-inheritable), `ReadFile`/
    `WriteFile` with `OVERLAPPED` for positional I/O, `FlushFileBuffers` (the
    durability barrier), `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`. Paths are
    widened UTF-8 → UTF-16.
- **CLI console/editor seam: `cli/platform.hpp`.** tty detection, no-echo
  password entry, and `$EDITOR` launch on a temp file — `platform_posix.cpp`
  (termios / `mkstemp` / `system`+`sys/wait`) vs `platform_win32.cpp`
  (`SetConsoleMode` / `GetTempFileNameW` / `_wsystem`). httplib is header-only and
  already cross-platform (link `ws2_32` on Windows).
- **Tests must stay portable** — no `<unistd.h>`, use `std::remove` not
  `::unlink`, and CWD-relative pack paths (a hardcoded `/tmp/...` doesn't exist on
  Windows). ctest runs in the build tree, so relative paths are fine.
- **RNG is the other seam**, inside `crypto.cpp`: `getrandom`/`/dev/urandom` on
  POSIX, `BCryptGenRandom` on Windows (link `bcrypt`).
- **CMake** picks each backend by `WIN32`, links `bcrypt`+`ws2_32` on Windows, and
  skips `-Wall/-Wextra` on MSVC. The CLI (with linenoise) builds on all three.
- **CI** (`.github/workflows/ci.yml`) runs ubuntu + macos + windows. Windows uses
  MSVC's multi-config generator, so build/test pass `--config`/`-C Release`.
- **Local Windows check without a Windows box**: cross-compile with mingw-w64 and
  run the exes under `wine64`. Use the **posix-thread** variant
  (`x86_64-w64-mingw32-g++-posix`) — the default win32-thread one lacks
  `std::thread`, which httplib needs. This is how the Win32 backend + CLI were
  first validated; CI's `windows-latest` is the real-MSVC confirmation (mingw ≠
  MSVC, so CI still catches MSVC-only issues).

---

## 15. Shell tab completion

The interactive shell's line editing, history, and Tab completion come from
vendored **linenoise-ng** (`third_party/linenoise`, BSD, cross-platform — the
successor to antirez's linenoise with Windows + UTF-8 support). Linked into the
CLI only; the core library and `web` don't touch it. History is **in-memory
only** — never written to disk, since a pack's paths are sensitive.

Completion (`completion_cb` in `cli/main.cpp`):
- **first token** → the command list (`cat`, `get`, `ls`, …);
- **a path argument** of a path-taking command (`cat/get/edit/rm/mv/cp/stat/ls`)
  → in-pack paths from `Pack::list()`, **one folder level at a time** (typing
  `cat mo`⇥ → `cat models/`, then `s`⇥ → `models/sub/`), just like a shell walks
  a directory tree. `add`/`get`'s *local* file arg isn't completed.

**The one local patch to the vendored lib.** linenoise-ng hands the completion
callback only the *current word* (text after the last break char, and `/` is a
break char) — too little to know the command or the parent folder. So a 6-line
patch publishes the full line-before-cursor via `linenoiseCompletionContext()`
(new function in `linenoise.h`, backed by a global set in `completeLine()` in
`linenoise.cpp`). Both patch sites are tagged `[sealpack local patch]`. If you
ever re-vendor a newer linenoise-ng, **re-apply those two hunks** or completion
goes back to word-only (commands would leak into argument completion). The
callback returns bare leaf segments; linenoise rebuilds `<prefix> + <candidate>`.

---

## 16. Incremental update — a patch is just a pack you `merge`

Ship a small pack of the changed files, not the whole thing. **A "patch" is not a
special format — it's an ordinary `.spk`** containing the files you want to update.
`merge target update.spk` overlays it: same path overwrites, new path is added,
everything else is untouched. This is the on-device path (the runtime downloads a
small pack and calls `sealpack_merge`) — no re-pushing a multi-GB `.spk`.

Why an ordinary pack rather than a bespoke `.spkpatch` format (which an earlier
cut had): building a patch is then just `create` + `add` (no new tooling), the
patch is inspectable with every existing command (`ls`/`cat`/`web` it), and the
core shrinks to one small `merge`. (History: it went `.spkpatch` + `diff`/`apply`
→ this, on the maintainer's call that "the patch should just be an spk.")

**File-level, deliberately — not byte/char-level.** The payload is opaque binary
models (`.axmodel` etc.) re-exported wholesale on every update: a new version is
~entirely different bytes, so a byte-level (bsdiff/git-style) delta would be ≈ the
full file — no gain — while breaking the content-addressed model and adding a
heavy dependency. The win is at file granularity: update 1 of N models → ship a
pack with 1. (Fine-tunes with mostly-identical bytes would call for *content-
defined chunking*, not char-diff; not the workload here.)

**Overlay semantics** (`Pack::merge` in `pack.cpp`): for each path in the source,
`put` it into the target (reusing all the normal dedup/commit machinery); the
source is read as plaintext and re-encrypted under the target's key, so the two
packs need not share a key or password. It's base-independent (applies to any
version of the target) and **idempotent**. Buffered like `put`/`del`; the caller
commits once (the crash-safe point).

**Deletions ride in the patch** via a reserved control file: if the source pack
contains **`.spkdel`**, each of its lines is a path to delete from the target
(blank lines and `#` comments ignored). That file is *consumed* — deleted paths
removed — not merged as content, so an update pack fully self-describes its update
(the runtime gets deletions for free). Build it with `add …/.spkdel <listfile>` or
`edit …/.spkdel`. The CLI `merge` also takes ad-hoc `-d <path>` flags on top.

**Confidentiality**: the update pack is itself an encrypted `.spk`, so it's
confidential in transit like any pack. (Unlike the old `.spkpatch`, it is *not*
sealed to the target's master key — merge works cross-key — so there's no
automatic "wrong pack" rejection; merging an unrelated pack would just overlay its
files. The producer controls what they ship.) Give the update pack the **same
password** as the target and the operator types one password; different passwords
work too (two prompts). No baseline/master-key lineage to preserve — updates chain
freely because merge is plaintext-level.

**Building the update pack: by hand, or `diff`.** You can just `create` + `add`
the files you changed. Or, when you have two *full* packs (old + new), let the tool
compute the delta: `sealpack diff <old.spk> <new.spk> [<update.spk>]` prints the
changed files (`+` added, `~` modified, `-` deleted) and, if given an output, writes
a mergeable update pack — the added/modified files plus a `.spkdel` of the deletions,
under the OLD pack's password (so `merge` reuses it). Omit the output for a dry-run
diff. It's cheap: `Pack::diff` compares the path→content-hash maps, reading no
blobs. (This is *not* the old bespoke `.spkpatch` — the output is an ordinary,
inspectable, mergeable `.spk`.)

CLI: `merge` is a normal `do_command` verb — `merge <update.spk> [-d <path>]…` in
the shell (against the open pack), or `sealpack merge <target> <update.spk> [-d …]`
one-shot. It opens the source pack, and **tries the target's password on it first**
(a patch usually shares it) so the same-password case needs no extra prompt; only
if that fails does it prompt for the source's password (TTY) — a different-password
source therefore needs a terminal. `diff` opens two packs, so it's one-shot only
(a producer op). C ABI: `sealpack_merge(target, source)` (device side) — buffered,
call `sealpack_commit`.
