# Cross-platform CLI smoke test — drives the real `sealpack` binary end to end so
# CLI regressions (arg parsing, merge, one-shot password handling) get caught in
# CI, not just the library. Invoked from CMake as:
#   cmake -DEXE=<sealpack> -DWORK=<scratch dir> -P tests/cli_smoke.cmake
#
# One-shot commands read $SEALPACK_PASSWORD when stdin isn't a TTY (which it isn't
# under execute_process); `create` reads the password twice from stdin instead.

if(NOT EXE OR NOT WORK)
  message(FATAL_ERROR "need -DEXE=<sealpack binary> -DWORK=<scratch dir>")
endif()

set(PACK "${WORK}/smoke.spk")
set(UPD  "${WORK}/update.spk")
file(REMOVE "${PACK}" "${UPD}")

# `create` prompts twice; feed both from a file.
set(PWFILE "${WORK}/pw.txt")
file(WRITE "${PWFILE}" "pw\npw\n")

# Run: cmake -E env SEALPACK_PASSWORD=pw <EXE> <args...>. Fails the test on nonzero
# rc. Optional INPUT feeds stdin (for `create`). Sets OUT in the parent scope.
function(run)
  cmake_parse_arguments(A "" "INPUT;EXPECT" "ARGS" ${ARGN})
  set(extra "")
  if(A_INPUT)
    set(extra INPUT_FILE "${A_INPUT}")
  endif()
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "SEALPACK_PASSWORD=pw" "${EXE}" ${A_ARGS}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err ${extra})
  if(NOT rc EQUAL 0)
    message(FATAL_ERROR "rc=${rc} for: ${A_ARGS}\n--stdout--\n${out}\n--stderr--\n${err}")
  endif()
  # Status lines ("merged …") go to stderr; content (ls/cat) to stdout — match both.
  if(A_EXPECT AND NOT "${out}${err}" MATCHES "${A_EXPECT}")
    message(FATAL_ERROR "output of ${A_ARGS} missing '${A_EXPECT}':\n--stdout--\n${out}\n--stderr--\n${err}")
  endif()
  set(OUT "${out}" PARENT_SCOPE)
endfunction()

# 1) create + add + ls + cat round-trip
file(WRITE "${WORK}/x.txt" "hello from the cli\n")
run(ARGS create "${PACK}" INPUT "${PWFILE}")
run(ARGS add "${PACK}" cfg/x.txt "${WORK}/x.txt")
run(ARGS ls  "${PACK}" EXPECT "cfg/x\\.txt")
run(ARGS cat "${PACK}" cfg/x.txt EXPECT "hello from the cli")

# get to a file and compare bytes
run(ARGS get "${PACK}" cfg/x.txt "${WORK}/x.out")
file(READ "${WORK}/x.txt" a)
file(READ "${WORK}/x.out" b)
if(NOT a STREQUAL b)
  message(FATAL_ERROR "get round-trip mismatch")
endif()

# 2) build an update pack (overwrite cfg/x.txt, add cfg/new.txt, delete via .spkdel)
file(WRITE "${WORK}/x2.txt" "updated by merge\n")
file(WRITE "${WORK}/new.txt" "brand new\n")
file(WRITE "${WORK}/del.txt" "cfg/gone.txt\n")
run(ARGS add "${PACK}" cfg/gone.txt "${WORK}/new.txt")           # a file we'll delete
run(ARGS create "${UPD}" INPUT "${PWFILE}")
run(ARGS add "${UPD}" cfg/x.txt "${WORK}/x2.txt")
run(ARGS add "${UPD}" cfg/new.txt "${WORK}/new.txt")
run(ARGS add "${UPD}" .spkdel "${WORK}/del.txt")

# 3) merge (same password → no extra prompt) and verify the overlay + deletion
run(ARGS merge "${PACK}" "${UPD}" EXPECT "merged")
run(ARGS cat "${PACK}" cfg/x.txt EXPECT "updated by merge")     # overwritten
run(ARGS cat "${PACK}" cfg/new.txt EXPECT "brand new")         # added
run(ARGS ls  "${PACK}" EXPECT "cfg/new\\.txt")
# cfg/gone.txt must be gone and .spkdel must not have landed
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "SEALPACK_PASSWORD=pw" "${EXE}" ls "${PACK}"
  OUTPUT_VARIABLE lsout)
if(lsout MATCHES "cfg/gone\\.txt")
  message(FATAL_ERROR ".spkdel deletion didn't take: cfg/gone.txt still present")
endif()
if(lsout MATCHES "\\.spkdel")
  message(FATAL_ERROR ".spkdel control file leaked into the pack")
endif()

# 4) diff two full packs: print the changes, and (with an output) write a
#    mergeable update pack; then apply it and confirm it matches.
set(DA "${WORK}/da.spk")
set(DB "${WORK}/db.spk")
set(DU "${WORK}/du.spk")
file(REMOVE "${DA}" "${DB}" "${DU}")
file(WRITE "${WORK}/f1.txt" "keep me\n")
file(WRITE "${WORK}/f2.txt" "before\n")
file(WRITE "${WORK}/f2b.txt" "after the change\n")
file(WRITE "${WORK}/f3.txt" "a third file\n")
run(ARGS create "${DA}" INPUT "${PWFILE}")
run(ARGS add "${DA}" keep.txt "${WORK}/f1.txt")
run(ARGS add "${DA}" mod.txt "${WORK}/f2.txt")
run(ARGS add "${DA}" gone.txt "${WORK}/f3.txt")
run(ARGS create "${DB}" INPUT "${PWFILE}")
run(ARGS add "${DB}" keep.txt "${WORK}/f1.txt")     # unchanged
run(ARGS add "${DB}" mod.txt "${WORK}/f2b.txt")     # modified
run(ARGS add "${DB}" new.txt "${WORK}/f3.txt")      # added (gone.txt is dropped)

# diff-only (no output path) prints the change list
run(ARGS diff "${DA}" "${DB}" EXPECT "~ mod\\.txt")
run(ARGS diff "${DA}" "${DB}" EXPECT "3 change")

# diff → update pack, then merge it into DA and verify it becomes DB's content
run(ARGS diff "${DA}" "${DB}" "${DU}" EXPECT "wrote")
run(ARGS merge "${DA}" "${DU}" EXPECT "merged")
run(ARGS cat "${DA}" mod.txt EXPECT "after the change")   # modified applied
run(ARGS cat "${DA}" new.txt EXPECT "a third file")       # added applied
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "SEALPACK_PASSWORD=pw" "${EXE}" ls "${DA}"
  OUTPUT_VARIABLE dls)
if(dls MATCHES "gone\\.txt")
  message(FATAL_ERROR "diff/merge didn't delete gone.txt")
endif()
if(NOT dls MATCHES "keep\\.txt")
  message(FATAL_ERROR "diff/merge dropped the unchanged keep.txt")
endif()

file(REMOVE "${PACK}" "${UPD}" "${DA}" "${DB}" "${DU}")
message(STATUS "cli_smoke: OK")
