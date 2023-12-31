#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

constexpr size_t DEFAULT_BLOCK_SIZE_BYTES = 4096;
constexpr size_t SHA256_SIZE_BYTES = 32;
constexpr size_t CMAC_SIZE_BYTES = 16;
constexpr size_t CMAC_KEY_SIZE_BYTES = 16;

typedef struct _Sha256 {
  uint8_t sha[SHA256_SIZE_BYTES]{};
} Sha256;

typedef struct _Cmac128 {
  uint8_t cmac[CMAC_SIZE_BYTES]{};
} Cmac128;

typedef struct _PulledBlocks {
  std::vector<size_t> neighbor_ids;
  std::vector<Sha256> neighbor_shas;
  std::vector<uint8_t> blocks;
} PulledBlocks;

typedef struct _PushedBlocks {
  std::vector<size_t> updated_sha_ids;
  std::vector<Sha256> updated_shas;
  std::vector<uint8_t> updated_blocks;
} PushedBlocks;
