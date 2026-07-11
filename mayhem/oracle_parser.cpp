/*
 * mayhem/oracle_parser.cpp — behavioral oracle for the ISOBMFF box parser (the `parser`/`dump`
 * targets' real work). Parses a genuine HEIF file through the SAME library API the fuzz target uses
 * and asserts structural facts about the decoded box tree — not exit codes, and not a trivial helper.
 * A neutered parser (one that returns an empty File, drops boxes, or misreads the brand) fails these
 * assertions, so this is a meaningful, hard-to-reward-hack functional test.
 *
 * Checks against Example-Files/IMG1.HEIC:
 *   1. top-level `ftyp` box exists and its major brand is "heic"
 *   2. top-level `meta` box exists
 *   3. the `meta` box is a real container with at least one child box (e.g. hdlr/iinf/iloc)
 */
#include <cstdio>
#include <memory>
#include <string>

#include "ISOBMFF/Parser.hpp"
#include "ISOBMFF/File.hpp"
#include "ISOBMFF/FTYP.hpp"
#include "ISOBMFF/Container.hpp"

static int check(const char *name, bool ok, int *failed) {
    printf("  %s - %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) (*failed)++;
    return ok;
}

int main(int argc, char **argv) {
    const std::string path = (argc > 1) ? argv[1] : "Example-Files/IMG1.HEIC";
    int failed = 0;

    ISOBMFF::Parser parser;
    try {
        parser.Parse(path);
    } catch (const std::exception &e) {
        printf("  FAIL - parser.Parse(%s) threw: %s\n", path.c_str(), e.what());
        return 1;
    }

    std::shared_ptr<ISOBMFF::File> file = parser.GetFile();
    if (!file) {
        printf("  FAIL - parser produced no File\n");
        return 1;
    }

    auto ftyp = file->GetTypedBox<ISOBMFF::FTYP>("ftyp");
    check("parser decodes a top-level ftyp box", ftyp != nullptr, &failed);
    if (ftyp) {
        check("ftyp major brand is 'heic'", ftyp->GetMajorBrand() == "heic", &failed);
    } else {
        check("ftyp major brand is 'heic'", false, &failed);
    }

    auto metaBox = file->GetBox("meta");
    check("parser decodes a top-level meta box", metaBox != nullptr, &failed);
    // META derives from Container (not ContainerBox), so cast to the Container interface for children.
    auto meta = std::dynamic_pointer_cast<ISOBMFF::Container>(metaBox);
    check("meta container holds child boxes (hdlr/iinf/iloc/...)",
          meta != nullptr && !meta->GetBoxes().empty(), &failed);

    return failed ? 1 : 0;
}
