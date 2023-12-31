#include <SgxAuthBuffer.h>
#include <gtest/gtest.h>

#include <cassert>
#include <cstddef>
#include <iostream>
#include <optional>
#include <tuple>

#include "common.h"

size_t SgxAuthBufferBase::global_id = 0;
