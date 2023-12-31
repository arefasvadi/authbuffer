#pragma once
#include <BufferStore.h>
#include <common.h>

#include <cstddef>
#include <cstdint>

void instantiate_new_buffer(const size_t buff_id, const size_t n_elems,
                            const size_t n_blocks, const size_t elem_size,
                            const size_t block_size_bytes);

void persist_authbuff(const size_t buff_id, const size_t start_block_idx,
                      const size_t end_block_idx, const uint8_t *block_bytes,
                      const size_t block_bytes_len,
                      const size_t *tree_node_indices,
                      const size_t tree_nodes_indices_len, const Sha256 *shas);

void persist_blocks(AuthBufferStore::Inner &auth_buffer,
                    const size_t start_block_idx, const size_t end_block_idx,
                    const uint8_t *block_bytes, const size_t block_bytes_len);

void persist_blocks_with_buff_id(const size_t buff_id,
                                 const size_t start_block_idx,
                                 const size_t end_block_idx,
                                 const uint8_t *block_bytes,
                                 const size_t block_bytes_len);

void persist_shas(AuthBufferStore::Inner &auth_buffer,
                  const size_t *tree_node_indices,
                  const size_t tree_nodes_indices_len, const Sha256 *shas);

void persist_shas_with_buff_id(const size_t buff_id,
                               const size_t *tree_node_indices,
                               const size_t tree_nodes_indices_len,
                               const Sha256 *shas);

void pull_block_segments_from_buffer_store(const size_t buff_id,
                                           const size_t start_block_idx,
                                           const size_t end_block_idx,
                                           uint8_t *block_bytes,
                                           const size_t *neighbor_ids,
                                           Sha256 *neighbor_shas,
                                           const size_t neighbors_len);

void pull_raw_blocks_from_buffer_store(AuthBufferStore::Inner &auth_buffer,
                                       const size_t start_block_idx,
                                       const size_t end_block_idx,
                                       uint8_t *block_bytes);

void pull_raw_neighbor_shas_from_buffer_store(
    AuthBufferStore::Inner &auth_buffer, const size_t *neighbor_ids,
    Sha256 *neighbor_shas, const size_t neighbors_len);
