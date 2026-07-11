/*
 * mayhem/fuzz_parser.cpp — in-process libFuzzer harness for the ISOBMFF box parser (the library's
 * actual purpose). Feeds the raw fuzz input straight into ISOBMFF::Parser via its in-memory
 * std::vector<uint8_t> constructor path — no file I/O, so it runs orders of magnitude faster than the
 * file-based `dump` binary while exercising the same box-tree parser. After a successful parse we walk
 * the resulting box tree (GetFile()->GetBoxes()) so box construction / accessors are covered too.
 *
 * Parse() throws std::runtime_error on malformed input by design; that is expected fuzzer behaviour,
 * not a defect, so we swallow it. ASan/UBSan still halt on genuine memory-safety / UB bugs inside the
 * parser regardless of the catch.
 */
#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>

#include "ISOBMFF/Parser.hpp"
#include "ISOBMFF/File.hpp"
#include "ISOBMFF/Container.hpp"

static void walk(const std::shared_ptr<ISOBMFF::Box> &box) {
    if (!box) return;
    // Container is the child-bearing interface (ContainerBox, META, MOOV, ... all implement it).
    auto container = std::dynamic_pointer_cast<ISOBMFF::Container>(box);
    if (!container) return;
    for (const auto &child : container->GetBoxes()) {
        walk(child);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::vector<uint8_t> bytes(data, data + size);

    ISOBMFF::Parser parser;
    try {
        parser.Parse(bytes);
    } catch (const std::runtime_error &) {
        return 0;   /* malformed input rejected cleanly — not a bug */
    } catch (...) {
        return 0;
    }

    /* Exercise the parsed tree so accessors/box construction are covered. */
    std::shared_ptr<ISOBMFF::File> file = parser.GetFile();
    if (file) {
        for (const auto &box : file->GetBoxes()) {
            walk(box);
        }
    }
    return 0;
}
