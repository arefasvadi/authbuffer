#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <m-lib/m-array.h>
#include <m-lib/m-buffer.h>
#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SHA256_SIZE_BYTES (32)
#define CMAC_SIZE_BYTES (16)
#define CMAC_KEY_SIZE_BYTES (16)
/**
 * Length of the data that a block can contain in bytes.
 * This block size should always configured so that it at least allows one
 * element for a given item to be stored in a block
 */
#define BLOCK_SIZE_BYTES (4096)

/**
 * Types
 */
enum BufferStatus {
  Ok = 0,
  UnknownError = 1,
  AllocationError = 2,
  InvalidBufferIndex = 3,
  CmacAllocationError = 4,
  CmacInitError = 5,
  CmacUpdateError = 6,
  CmacFinalError = 7,
  Sha256AllocationError = 8,
  Sha256InitError = 9,
  Sha256UpdateError = 10,
  Sha256FinalError = 11,
  NeighborNotFound = 12,
};

typedef struct {
  size_t n_bytes;
  size_t elem_size;
  void *data;
} Range;

typedef struct {
  uint8_t hash[SHA256_SIZE_BYTES];
} Index;

typedef struct {
  uint8_t sha[SHA256_SIZE_BYTES];
} MKNode;

typedef struct {
  size_t n_nodes;
  MKNode *nodes;
} MkTree;

typedef struct {
  uint8_t cmac[CMAC_SIZE_BYTES];
  void *data;
} BufferBlock;

typedef struct {
  // number of items in total
  size_t n_elems;
  // number of items in a block
  size_t n_block_elems;
  // if padding is needed, the value would be greater than 0 for each blcok
  size_t block_pad_size;
  // size of each item in bytes
  size_t elem_size;
  // total number of blocks (usually the leaf of the tree where the actual data
  // reside)
  size_t n_blocks;
  // total number of items in the last block
  size_t last_block_n_elems;
} BufferMeta;

typedef struct {
  BufferMeta meta_data;
  BufferBlock *blocks; // an array of blocks
  MkTree *tree;        // merkle tree of the buffer
} Buffer;

/**
 * variables and globals
 */

const uint8_t cmac_key[CMAC_KEY_SIZE_BYTES] = {};

/*
 * Function prototypes
 */

Buffer *init_buffer(size_t n_elems, size_t elem_size, void *default_value,
                    BufferStatus *status);
static BufferMeta create_buffer_meta(size_t n_elems, size_t element_size);

static size_t count_mk_tree_len(size_t block_n);
static MkTree *init_tree(size_t nodes_len, BufferStatus *status);
static void destroy_tree(MkTree *tree);
static void destroy_buffer_block_data(BufferBlock *block);
void destroy_range(Range *range);

Range *get_range(const Buffer *buf, const size_t i, const size_t j,
                 BufferStatus *status);
void set_range(Buffer *buf, const size_t i, const size_t j, const Range *range,
               BufferStatus *status);
Range *get_item(const Buffer *buf, const size_t i, BufferStatus *status);
void set_item(Buffer *buf, const size_t i, const Range *range,
              BufferStatus *status);
static void make_MkTree(Buffer *buf, BufferStatus *status, const uint8_t *key);
static void compute_cmac128(const uint8_t *key, const void *data,
                            const size_t nbytes, uint8_t *cmac,
                            BufferStatus *status);
static void compute_sha256(const void *data, const size_t nbytes, uint8_t *hash,
                           BufferStatus *status);
void print_hex(const uint8_t *v, const size_t len, const char *msg);

void get_merkle_neighbors(const Buffer *buf, size_t block_idx,
                          MKNode **neighbors, size_t *neighbors_size,
                          BufferStatus *status);
static void destroy_buffer_block_data(BufferBlock *block) {
  if (block == NULL) {
    return;
  }
  free(block->data);
}

void destroy_range(Range *range) {
  if (range == NULL) {
    return;
  }
  free(range->data);
  free(range);
}

static void destroy_tree(MkTree *tree) {
  if (tree == NULL) {
    return;
  }
  free(tree->nodes);
  free(tree);
}

void destroy_buffer(Buffer *buf) {
  if (buf == NULL) {
    return;
  }
  if (buf->blocks != NULL) {
    for (size_t i = 0; i < buf->meta_data.n_blocks; ++i) {
      destroy_buffer_block_data(&buf->blocks[i]);
    }
    free(buf->blocks);
  }
  if (buf->tree != NULL) {
    destroy_tree(buf->tree);
  }
  free(buf);
}

static BufferMeta create_buffer_meta(const size_t n_elems,
                                     const size_t elem_size) {
  assert(elem_size <= BLOCK_SIZE_BYTES);
  // const size_t total_useful_bytes = n_elems * elem_size;
  const size_t n_block_elems = BLOCK_SIZE_BYTES / elem_size;
  assert(n_block_elems != 0);
  const size_t n_block_padding_bytes = BLOCK_SIZE_BYTES % elem_size;
  const size_t n_blocks =
      n_elems / n_block_elems + (n_elems % n_block_elems == 0 ? 0 : 1);
  size_t last_block_n_elements = n_elems % n_block_elems;
  if (last_block_n_elements == 0) {
    last_block_n_elements = n_block_elems;
  }
  return BufferMeta{n_elems,   n_block_elems, n_block_padding_bytes,
                    elem_size, n_blocks,      last_block_n_elements};
}

static MkTree *init_tree(const size_t n_nodes, BufferStatus *status) {
  MkTree *tree = (MkTree *)malloc(sizeof(MkTree));
  if (tree == NULL) {
    *status = AllocationError;
    return NULL;
  }
  tree->n_nodes = n_nodes;
  MKNode *nodes = (MKNode *)malloc(sizeof(MKNode) * n_nodes);
  if (nodes == NULL) {
    *status = AllocationError;
    destroy_tree(tree);
    return NULL;
  }
  memset(nodes, 0, sizeof(MKNode) * n_nodes);
  tree->nodes = nodes;
  *status = Ok;
  return tree;
}

/**
 * counts the length of the merkle tree nodes given the length of
 * its leaves.
 */
static inline size_t count_mk_tree_len(size_t n_leaves) {
  return 2 * n_leaves - 1;
  // size_t current_level_nodes = n_leaves;
  // size_t n_nodes = n_leaves;
  // // size_t n_nodes = 0;
  // while (current_level_nodes > 1) {
  //   size_t next_level_nodes = (current_level_nodes + 1) / 2;
  //   n_nodes += next_level_nodes;
  //   current_level_nodes = next_level_nodes;
  // }
  // return n_nodes;
}

Buffer *init_buffer(size_t n_elems, size_t elem_size, void *default_value,
                    BufferStatus *status) {
  Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
  if (buf == NULL) {
    *status = AllocationError;
    return NULL;
  }
  buf->meta_data = create_buffer_meta(n_elems, elem_size);
  const size_t total_blocks = buf->meta_data.n_blocks;
  const size_t n_block_elems = buf->meta_data.n_block_elems;
  const size_t padding_size = buf->meta_data.block_pad_size;
  BufferBlock *blocks =
      (BufferBlock *)malloc(sizeof(BufferBlock) * total_blocks);
  if (blocks == NULL) {
    destroy_buffer(buf);
    *status = AllocationError;
    return NULL;
  }
  buf->blocks = blocks;
  for (size_t i = 0; i < total_blocks; ++i) {
    blocks[i].data = malloc(BLOCK_SIZE_BYTES);
    if (blocks[i].data == NULL) {
      destroy_buffer(buf);
      *status = AllocationError;
      return NULL;
    }
    memset(blocks[i].cmac, 0, sizeof(blocks[i].cmac));
    if (default_value != NULL) {
      for (size_t j = 0; j < n_block_elems; ++j) {
        memcpy((uint8_t *)blocks[i].data + j * elem_size, default_value,
               elem_size);
      }
    } else {
      memset((uint8_t *)blocks[i].data, 0, n_block_elems * elem_size);
    }
    // zero the padding bytes.
    memset((uint8_t *)blocks[i].data + n_block_elems * elem_size, 0,
           padding_size);
  }
  size_t tree_nodes_len = count_mk_tree_len(total_blocks);
  MkTree *tree = init_tree(tree_nodes_len, status);
  if (*status != Ok) {
    destroy_buffer(buf);
    return NULL;
  }
  buf->tree = tree;
  make_MkTree(buf, status, cmac_key);
  if (*status != Ok) {
    destroy_buffer(buf);
    return NULL;
  }
  *status = Ok;
  return buf;
}

static void compute_cmac128(const uint8_t *key, const void *data,
                            const size_t nbytes, uint8_t *cmac,
                            BufferStatus *status) {
  // maybe later make this static, if not used in parallel
  CMAC_CTX *ctx = CMAC_CTX_new();
  if (ctx == NULL) {
    *status = CmacAllocationError;
    return;
  }
  if (!CMAC_Init(ctx, key, CMAC_KEY_SIZE_BYTES, EVP_aes_128_cbc(), NULL)) {
    *status = CmacInitError;
    CMAC_CTX_free(ctx);
    return;
  }
  if (!CMAC_Update(ctx, data, nbytes)) {
    *status = CmacUpdateError;
    CMAC_CTX_free(ctx);
    return;
  }
  size_t final_len = 0;
  if (!CMAC_Final(ctx, cmac, &final_len)) {
    *status = CmacFinalError;
    CMAC_CTX_free(ctx);
    return;
  }
  CMAC_CTX_free(ctx);
  *status = Ok;
}

static void compute_sha256(const void *data, const size_t nbytes, uint8_t *hash,
                           BufferStatus *status) {
  SHA256_CTX ctx;
  if (!SHA256_Init(&ctx)) {
    *status = Sha256InitError;
    return;
  }
  if (!SHA256_Update(&ctx, data, nbytes)) {
    *status = Sha256UpdateError;
    return;
  }
  if (!SHA256_Final(hash, &ctx)) {
    *status = Sha256FinalError;
    return;
  }
  *status = Ok;
}

static void make_MkTree(Buffer *buf, BufferStatus *status, const uint8_t *key) {
  const size_t total_blocks = buf->meta_data.n_blocks;
  MkTree *tree = buf->tree;
  const size_t tree_nnodes = tree->n_nodes;
  uint8_t stash[2 * SHA256_SIZE_BYTES];
  // compute the cmac then sha256 for each leaf block
  for (size_t i = 0; i < total_blocks; ++i) {
    BufferBlock *block = &buf->blocks[i];
    compute_cmac128(key, block->data, BLOCK_SIZE_BYTES, block->cmac, status);
    if (*status != Ok) {
      return;
    }
    // build the hash for the leaves of the tree. We have to do this since the
    // cmac digest len we are using is different, otherwise there is really no
    // reason to double digest for the leaves.
    compute_sha256(block->cmac, CMAC_KEY_SIZE_BYTES,
                   tree->nodes[tree_nnodes - total_blocks + i].sha, status);
    if (*status != Ok) {
      return;
    }
  }

  for (size_t idx = tree_nnodes - total_blocks - 1; idx > 0; idx--) {
    memcpy(stash, tree->nodes[2 * idx + 1].sha, SHA256_SIZE_BYTES);
    memcpy(stash + SHA256_SIZE_BYTES, tree->nodes[2 * idx + 2].sha,
           SHA256_SIZE_BYTES);
    compute_sha256(stash, 2 * SHA256_SIZE_BYTES, tree->nodes[idx].sha, status);
    if (*status != Ok) {
      return;
    }
  }
}

void get_merkle_neighbors(const Buffer *buf, size_t block_idx,
                          MKNode **neighbors, size_t *neighbors_size,
                          BufferStatus *status) {
  const size_t total_blocks = buf->meta_data.n_blocks;
  if (block_idx >= total_blocks) {
    *status = InvalidBufferIndex;
  }
  const size_t tree_nnodes = buf->tree->n_nodes;
  size_t tree_idx = tree_nnodes - total_blocks + block_idx;
  size_t levels = 0;
  while ((1 << levels) < total_blocks) {
    levels++;
  }

  *neighbors = (MKNode *)malloc(sizeof(MKNode) * (levels));
  if (*neighbors == NULL) {
    *status = AllocationError;
    return;
  }

  size_t neighbor_idx = 0;
  while (tree_idx > 0) {
    size_t sibling_idx;
    if (tree_idx % 2 == 0) {
      sibling_idx = tree_idx - 1;
    } else {
      sibling_idx = tree_idx + 1;
    }

    (*neighbors)[neighbor_idx++] = buf->tree->nodes[sibling_idx];
    tree_idx = (tree_idx - 1) / 2;
  }
  *neighbors_size = neighbor_idx;
  *status = Ok;
}

void test_single_block() {
  const size_t len = 10;
  char default_val = 0;
  BufferStatus status = Ok;
  Buffer *buf = init_buffer(len, sizeof(char), &default_val, &status);
  assert(status == Ok);
  assert(memcmp(cmac_key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                CMAC_KEY_SIZE_BYTES) == 0);
  assert(buf->meta_data.n_elems == len);
  assert(buf->meta_data.n_blocks == 1);
  // printf("n_block_elems = {%zu}\n", buf->meta_data.n_block_elems);
  assert(buf->meta_data.n_block_elems == 4096);
  assert(buf->meta_data.block_pad_size == 0);
  assert(buf->meta_data.last_block_n_elems == len);
  // print_hex(buf->blocks[0].cmac, CMAC_SIZE_BYTES,
  //           "cmac for the leaf of one single block scenario");
  uint8_t cmac_expected[CMAC_SIZE_BYTES] = {
      193, 251, 75, 220, 198, 105, 208, 93, 150, 68, 159, 125, 3, 105, 96, 226};
  assert(memcmp(buf->blocks[0].cmac, cmac_expected, CMAC_SIZE_BYTES) == 0);

  assert(buf->tree->n_nodes == 1);
  uint8_t expected[SHA256_SIZE_BYTES] = {
      130, 20, 32,  154, 53, 10,  89, 227, 90,  215, 103,
      178, 33, 118, 93,  32, 113, 40, 227, 145, 108, 59,
      99,  32, 245, 197, 98, 62,  18, 120, 179, 251};

  // print_hex(buf->tree->nodes[0].sha, SHA256_SIZE_BYTES,
  //           "sha for the root of one single block scenario");
  assert(memcmp(buf->tree->nodes[0].sha, expected, SHA256_SIZE_BYTES) == 0);
  destroy_buffer(buf);
}

void test_one_full_block_one_non_full() {
  const size_t len = 4096 + 2048;
  char default_val = 0;
  BufferStatus status = Ok;
  Buffer *buf = init_buffer(len, sizeof(char), &default_val, &status);
  assert(status == Ok);
  assert(memcmp(cmac_key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                CMAC_KEY_SIZE_BYTES) == 0);
  assert(buf->meta_data.n_elems == len);
  assert(buf->meta_data.n_blocks == 2);
  assert(buf->meta_data.n_block_elems == 4096);
  assert(buf->meta_data.block_pad_size == 0);
  assert(buf->meta_data.last_block_n_elems == 2048);

  uint8_t cmac_expected[CMAC_SIZE_BYTES] = {
      193, 251, 75, 220, 198, 105, 208, 93, 150, 68, 159, 125, 3, 105, 96, 226};
  assert(memcmp(buf->blocks[0].cmac, cmac_expected, CMAC_SIZE_BYTES) == 0);
  assert(memcmp(buf->blocks[1].cmac, cmac_expected, CMAC_SIZE_BYTES) == 0);

  assert(buf->tree->n_nodes == 3);
  uint8_t expected[SHA256_SIZE_BYTES] = {
      130, 20, 32,  154, 53, 10,  89, 227, 90,  215, 103,
      178, 33, 118, 93,  32, 113, 40, 227, 145, 108, 59,
      99,  32, 245, 197, 98, 62,  18, 120, 179, 251};
  uint8_t expected_double[SHA256_SIZE_BYTES] = {
      150, 155, 51,  149, 226, 58,  26,  106, 144, 189, 5,
      19,  3,   237, 18,  7,   221, 185, 176, 241, 7,   180,
      158, 65,  97,  70,  180, 56,  157, 166, 96,  125};
  assert(memcmp(buf->tree->nodes[1].sha, expected, SHA256_SIZE_BYTES) == 0);
  assert(memcmp(buf->tree->nodes[2].sha, expected, SHA256_SIZE_BYTES) == 0);
  // print_hex(buf->tree->nodes[0].sha, SHA256_SIZE_BYTES,
  //           "root of the mk tree with two leaves");
  assert(memcmp(buf->tree->nodes[0].sha, expected_double, SHA256_SIZE_BYTES) ==
         0);
  destroy_buffer(buf);
}

void test_two_full_blocks() {
  const size_t len = 4096 * 2;
  char default_val = 0;
  BufferStatus status = Ok;
  Buffer *buf = init_buffer(len, sizeof(char), &default_val, &status);
  assert(status == Ok);
  assert(memcmp(cmac_key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                CMAC_KEY_SIZE_BYTES) == 0);
  assert(buf->meta_data.n_elems == len);
  assert(buf->meta_data.n_blocks == 2);
  assert(buf->meta_data.n_block_elems == 4096);
  assert(buf->meta_data.block_pad_size == 0);
  // printf("last_block_n_elems: %zu\n", buf->meta_data.last_block_n_elems);
  assert(buf->meta_data.last_block_n_elems == 4096);

  destroy_buffer(buf);
}

void test_verification_path() {
  typedef struct Foo {
    float vals[300];
  } Foo;

  const size_t len = 13;
  BufferStatus status = Ok;
  // printf("type size: %zu\n", sizeof(Foo));
  Buffer *buf = init_buffer(len, sizeof(Foo), NULL, &status);
  assert(status == Ok);
  assert(memcmp(cmac_key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                CMAC_KEY_SIZE_BYTES) == 0);
  assert(buf->meta_data.n_elems == len);
  // printf("total blocks %zu\n", buf->meta_data.n_blocks);
  assert(buf->meta_data.n_blocks == 5);
  assert(buf->meta_data.n_block_elems == 3);
  assert(buf->meta_data.block_pad_size == 4096 - (3 * 300 * sizeof(float)));
  assert(buf->meta_data.last_block_n_elems == 1);

  MKNode *neighbors = NULL;
  size_t neighbors_size = 0;
  // get_merkle_neighbors(buf, 1, &neighbors, &neighbors_size, &status);
  // printf("neighbor size: %uz\n", neighbors_size);

  free(neighbors);
  destroy_buffer(buf);
}

void print_hex(const uint8_t *v, const size_t len, const char *msg) {
  printf("%s\n", msg);
  for (int i = 0; i < len; ++i) {
    printf("%02x", v[i]);
  }
  printf("\n");
}

int main() {
  // test_single_block();
  // test_one_full_block_one_non_full();
  // test_two_full_blocks();
  test_verification_path();
  return 0;
}
