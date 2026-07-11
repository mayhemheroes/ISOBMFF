#!/usr/bin/env bash
#
# mayhem/build.sh — build both ISOBMFF fuzz targets + their oracles.
#
#   build/fuzz_parser          sanitized + libFuzzer  -> target `parser` (in-memory box-parser fuzzer)
#   build/dump                 sanitized + DWARF      -> target `dump`   (file box-parser fuzzer)
#   build/fuzz_Pad             sanitized + libFuzzer  -> target `pad`    (original Utils::Pad fuzzer)
#   build-oracle/oracle_parser normal flags           -> structural oracle for the parsed box tree
#   build-oracle/dump          normal flags           -> end-to-end functional oracle for the Parser
# The fork's original `pad` target only fuzzed the trivial ISOBMFF::Utils::Pad string helper; it is
# preserved (target parity), but the primary work is now `parser`, an in-process libFuzzer harness
# driving the library's actual box parser (and `dump`, the end-to-end file parser).
# ISOBMFF is a header+source C++ library; we compile ISOBMFF/source/*.cpp straight in (upstream's
# Makefile builds the same TU set). No network, no upstream edits.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CXX:=clang++}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "${SRC:-/mayhem}"

STD="-std=c++17"
INC="-I ISOBMFF/include"
LIB=(ISOBMFF/source/*.cpp)          # the whole ISOBMFF library (instrumented, so bugs inside it show)

mkdir -p build build-oracle

# Each target links the whole library in one clang++ call; the four are independent, so run them in
# parallel (the library is single-TU-per-file but we compile-and-link per target) to stay within the
# build-time budget. $DEBUG_FLAGS after the sanitizer flags so -gdwarf-3 wins (DWARF < 4); -w silences
# upstream warnings. Targets 1-2 are sanitized (ASan/UBSan instrument the parser/utils); the two
# build-oracle/* binaries are clean (no sanitizers/fuzzer) so mayhem/test.sh is an honest oracle.
pids=()
# shellcheck disable=SC2086
$CXX $STD $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -w $INC mayhem/fuzz_parser.cpp "${LIB[@]}" -o build/fuzz_parser & pids+=($!)
# shellcheck disable=SC2086
$CXX $STD $SANITIZER_FLAGS $DEBUG_FLAGS -w $INC ISOBMFF-Dump/main.cpp "${LIB[@]}" -o build/dump & pids+=($!)
# shellcheck disable=SC2086
$CXX $STD $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -w $INC mayhem/fuzz_Pad.cpp "${LIB[@]}" -o build/fuzz_Pad & pids+=($!)
# shellcheck disable=SC2086
$CXX $STD -O2 $COVERAGE_FLAGS -w $INC mayhem/oracle_parser.cpp "${LIB[@]}" -o build-oracle/oracle_parser & pids+=($!)
# shellcheck disable=SC2086
$CXX $STD -O2 $COVERAGE_FLAGS -w $INC ISOBMFF-Dump/main.cpp "${LIB[@]}" -o build-oracle/dump & pids+=($!)

rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
[ "$rc" -eq 0 ] || { echo "build.sh: a target failed to build" >&2; exit 1; }

echo "build.sh: built build/fuzz_parser, build/dump, build/fuzz_Pad and oracle binaries"
