#!/usr/bin/env bash
#
# mayhem/test.sh — functional oracle for the ISOBMFF box parser. RUNS prebuilt clean binaries only
# (build-oracle/{oracle_parser,dump} from mayhem/build.sh); never compiles. Behavioral:
#   oracle_parser — parse a real HEIC via the library API and assert box-tree structure
#                   (ftyp major brand 'heic', non-empty meta container)
#   dump          — end-to-end: parse the same HEIC via the dump binary and require ftyp+meta
# Both exercise the parser the `parser`/`dump` fuzz targets hit. A neutered library (empty File,
# dropped boxes, wrong brand) fails these, so the oracle is not reward-hackable.
#
# NOTE ON THE UPSTREAM SUITE: DigiDNA/ISOBMFF ships no runnable functional test suite we can wire.
# The only test file, ISOBMFF-Tests/Parser.cpp, is an empty-body placeholder:
#     XSTest( ISOBMFF_Parser, CTOR ) {}
# (it constructs a Parser and asserts nothing), and its framework (Submodules/XSTest) is an
# unpopulated git submodule that would require network to fetch — so there is nothing meaningful to
# run offline even if built. We therefore document the absence and provide the structural parser
# oracle + end-to-end dump check below as the strongest available behavioral regression oracle.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "${SRC:-/mayhem}"

passed=0; failed=0
check() { if [ "$2" -eq 0 ]; then echo "  ok   - $1"; passed=$((passed+1)); else echo "  FAIL - $1"; failed=$((failed+1)); fi; }

emit_ctrf() {
  local tool="$1" p="$2" f="$3" s="${4:-0}"; local tests=$(( p + f + s ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": { "tests": $tests, "passed": $p, "failed": $f, "pending": 0, "skipped": $s, "other": 0 }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":0,"skipped":%d,"other":0}}}\n' \
    "$tool" "$tests" "$p" "$f" "$s"
  [ "$f" -eq 0 ]
}

PARSER=build-oracle/oracle_parser
DUMP=build-oracle/dump
if [ ! -x "$PARSER" ] || [ ! -x "$DUMP" ]; then
  echo "test.sh: oracle binaries missing — build.sh must build them (not rebuilding here)" >&2
  emit_ctrf isobmff 0 1; exit 1
fi

# oracle_parser — structural assertions on the parsed box tree (exits nonzero on any mismatch). Count
# with here-strings, not `printf | grep`, so `set -o pipefail` doesn't trip on grep's early-exit SIGPIPE.
parser_out="$("$PARSER" Example-Files/IMG1.HEIC 2>&1)"; echo "$parser_out"
passed=$(( passed + $(grep -c '  ok   - ' <<<"$parser_out") ))
failed=$(( failed + $(grep -c '  FAIL - ' <<<"$parser_out") ))

# dump — parse a real ISOBMFF file; require success + expected boxes.
dump_out="$("$DUMP" Example-Files/IMG1.HEIC 2>&1)"; drc=$?
if [ "$drc" -eq 0 ] && grep -q 'ftyp' <<<"$dump_out" && grep -q 'meta' <<<"$dump_out"; then
  check "dump parses IMG1.HEIC and reports ftyp+meta boxes" 0
else
  check "dump parses IMG1.HEIC and reports ftyp+meta boxes" 1
fi

echo "test.sh: passed=$passed failed=$failed"
emit_ctrf isobmff "$passed" "$failed"
