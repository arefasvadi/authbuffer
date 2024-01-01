#include <gtest/gtest.h>

#include <SgxAuthBuffer.hpp>
#include <cassert>
#include <cstddef>
#include <iostream>
#include <optional>
#include <tuple>

#include "common.h"

size_t SgxAuthBufferBase::global_id = 0;

uint8_t cmac_key[CMAC_KEY_SIZE_BYTES] = {};
