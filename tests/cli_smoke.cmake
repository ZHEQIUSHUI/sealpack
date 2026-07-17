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

file(REMOVE "${PACK}" "${UPD}")
message(STATUS "cli_smoke: OK")
