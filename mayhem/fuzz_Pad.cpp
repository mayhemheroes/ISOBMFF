#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

#include "ISOBMFF/Utils.hpp"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string s = provider.ConsumeRandomLengthString();
    size_t length = provider.ConsumeIntegralInRange(0, 1000);

    ISOBMFF::Utils::Pad(s, length);
    return 0;
}
