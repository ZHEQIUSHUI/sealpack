# sealpack — worklog

Chronological record of what was built and *why* (and where the direction
changed). Newest first. Pairs with `docs/DESIGN.md` (the current-state
reference). Commit hashes are on `ZHEQIUSHUI/sealpack`.

---

## 2026-07-11 — human-readable read/edit (`cat` + `edit`, web preview + edit)

- **`60d85bd` cat + web inline preview.** Added `cli/preview.hpp` (shared
  `looks_text` + `mime_by_ext`), `cat <path>` (print text, refuse binary), and
  `GET /api/view` (text/image inline, binary → 415) with a preview panel in the
  web UI. Motivation: a `.spk` now carries small config/text files (see the
  runtime's `events/config.yaml`), so you want to *read* them without extracting.
  Security call: `html/svg/js/css` are served as `text/plain` (show source, don't
  execute) because the web UI is same-origin with the token.
- **`094bb90` edit (vi) + web edit panel.** `edit <path>` opens the blob in
  `$VISUAL`/`$EDITOR` (default vi) via a temp file and saves back on change.
  Web preview became a **right-docked panel** (user asked for "click a file →
  text box on the right → Edit to modify"); Edit swaps to a `<textarea>`, Save
  POSTs to `/api/put`. Guard: files truncated by the 1 MiB preview cap
  (`X-Sealpack-Truncated`) are **view-only** so a save can't persist the
  truncated copy.
- Testing note for later: `edit` needs a TTY, so headless tests drive it through
  a pty — `printf 'pw\n' | script -qec "EDITOR=/tmp/fake.sh sealpack edit …" /dev/null`
  (one-shot mode still prompts for the password on a TTY, so feed it via the pty
  stdin). Verified round-trip updates the encrypted pack (`cat` confirms), no-op
  edits report `unchanged`, binaries are refused.

---

## 2026-07-10 — Android build fix

- **`a084594` getrandom via syscall.** The `getrandom()` libc wrapper is
  undeclared on Android NDK API < 28 → cross-compile failed. Switched to
  `syscall(SYS_getrandom, …)` directly. This is what lets the runtime build
  sealpack into an Android `.so`.

---

## 2026-07-09 — the big day: v2 key-wrapping, CLI shell, web UI, submodule

Ordered as it happened:

- **`dd3686a` initial sealpack.** Encrypted single-file content-addressed store.
  Rationale for building rather than reusing: leveldb had the features but a
  fragmented LSM layout and no encryption → an "encrypted git packfile" fit
  better. Four pillars: single file, AEAD encryption (monocypher, no hand-rolled
  crypto), BLAKE2b content-addressed dedup, double-superblock crash safety.
- **`e2e2792` cross-platform durable_sync.** macOS CI caught that `fdatasync`
  doesn't exist there and `fsync` doesn't hit the platter → `F_FULLFSYNC` on
  macOS, `fdatasync` on Linux.
- **`adafd5d` + `860e92e` web UI.** `sealpack web` — localhost file manager
  (cpp-httplib vendored, REST + embedded vanilla front-end, session token for
  CSRF), then folder-tree navigation + breadcrumb instead of a flat list. The
  web layer lives only in the CLI; the core library never touches HTTP.
- **`d127114` submodule-friendly CMake.** `CMAKE_CURRENT_SOURCE_DIR` so the repo
  works when embedded as `third_party/sealpack` in the runtime.
- **`1da1c5e` + `afad023` key-wrapping (v2 format).** Random master key encrypts
  the data; the password only wraps the master key into an 8-slot LUKS-style
  array. Payoff: **rekey rewrites one 88-byte slot, the data region never moves**
  → instant on multi-GB packs. This changed the on-disk format (v1 → v2, all
  offsets moved) — incompatible, no in-place upgrade.
- **`7c502d3` interactive shell.** `sealpack <pack>` prompts for the password
  once and drops into a mini shell reusing the open pack — one Argon2 per
  session, password never in argv/history. (User disliked the
  `$SEALPACK_PASSWORD` env-var-per-command flow; env var kept only for non-TTY
  scripting.)
- **`a27f451` human-readable sizes.** `ls`/`stat` show KB/MB/GB, not raw bytes.
- **`0852c1d` cut multi-password → single password.** The key-wrapping work had
  briefly grown `addkey`/`rmkey` for multiple passwords. Product decision:
  shipping model packs never needs more than one password, so it was cut back to
  single-password + `rekey`. **The 8-slot array stayed on disk** (only slot 0
  used) so the format didn't churn again — that's why the format still looks
  multi-slot.

---

## Direction changes worth remembering

- **Multi-password → single.** Built, then deliberately removed. Don't
  reintroduce `addkey`/`rmkey` without a real use case; the slots are kept only
  as format ballast.
- **Env-var password → interactive shell.** `$SEALPACK_PASSWORD` is the
  scripting fallback, not the primary UX.
- **Preview modal → right-docked panel.** Per explicit user preference; edit
  lives in the panel, not a popup.
- **`.spk` grew from models-only to models + text.** The preview/edit and `cat`
  features exist because packs now hold human-readable config too.

## Naming convention

`.spk` = the encrypted pack **file**. "sealpack" (no suffix) = this repo / the
library / the CLI. Keep them distinct in docs and messages.
