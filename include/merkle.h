#pragma once

#include <cstddef>
#include <cstdint>
#include <stdint.h>

typedef uint8_t merkle_hash_t[32];

typedef struct _merkle_node {
    struct _merkle_node *left;
    struct _merkle_node *right;
    merkle_hash_t hash;
} merkle_node;

typedef struct _merkle_tree {
    merkle_node *root;
} merkle_tree;

merkle_tree *create_merkle_tree(uint8_t *data, std::size_t len, std::size_t block_size);