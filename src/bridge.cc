#include <bridge.h>

#include <boost/format.hpp>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <utility>

#include "BufferStore.h"
#include "common.h"

void instantiate_new_buffer(const size_t buff_id, const size_t n_elems,
                            const size_t n_blocks, const size_t elem_size,
                            const size_t block_size_bytes) {
  if (AuthBufferStore::keyExists(buff_id, AuthBufferStore::lookup_table)) {
    throw std::runtime_error(
        (boost::format("Buffer with id %1% is already in use.") % buff_id)
            .str());
  }
  AuthBufferStore::lookup_table.insert(
      {buff_id, AuthBufferStore::Inner(buff_id, n_elems, n_blocks, elem_size,
                                       block_size_bytes)});
}

void persist_authbuff(const size_t buff_id, const size_t start_block_idx,
                      const size_t end_block_idx, const uint8_t *block_bytes,
                      const size_t block_bytes_len,
                      const size_t *tree_node_indices,
                      const size_t tree_nodes_indices_len, const Sha256 *shas) {
  if (!AuthBufferStore::keyExists(buff_id, AuthBufferStore::lookup_table)) {
    throw std::runtime_error(
        (boost::format("Buffer with id %1% not found.") % buff_id).str());
  }
  auto &auth_buffer = AuthBufferStore::lookup_table.at(buff_id);
  persist_blocks(auth_buffer, start_block_idx, end_block_idx, block_bytes,
                 block_bytes_len);
  persist_shas(auth_buffer, tree_node_indices, tree_nodes_indices_len, shas);
}

void persist_blocks(AuthBufferStore::Inner &auth_buffer,
                    const size_t start_block_idx, const size_t end_block_idx,
                    const uint8_t *block_bytes, const size_t block_bytes_len) {
  assert(block_bytes != nullptr);
  assert(start_block_idx >= 0 && start_block_idx <= end_block_idx);
  assert((block_bytes_len) == ((end_block_idx - start_block_idx + 1) *
                               auth_buffer._block_size_bytes));
  std::memmove(
      &auth_buffer._content[start_block_idx * (auth_buffer._block_size_bytes)],
      block_bytes, block_bytes_len);
}

void persist_blocks_with_buff_id(const size_t buff_id,
                                 const size_t start_block_idx,
                                 const size_t end_block_idx,
                                 const uint8_t *block_bytes,
                                 const size_t block_bytes_len) {
  if (!AuthBufferStore::keyExists(buff_id, AuthBufferStore::lookup_table)) {
    throw std::runtime_error(
        (boost::format("Buffer with id %1% not found.") % buff_id).str());
  }
  auto &auth_buffer = AuthBufferStore::lookup_table.at(buff_id);
  persist_blocks(auth_buffer, start_block_idx, end_block_idx, block_bytes,
                 block_bytes_len);
}

void persist_shas(AuthBufferStore::Inner &auth_buffer,
                  const size_t *tree_node_indices,
                  const size_t tree_nodes_indices_len, const Sha256 *shas) {
  assert(tree_node_indices != nullptr);
  assert(tree_nodes_indices_len >= 0 &&
         tree_nodes_indices_len <= auth_buffer._mk_tree.size());
  for (size_t i = 0; i < tree_nodes_indices_len; ++i) {
    auth_buffer._mk_tree[tree_node_indices[i]] = shas[i];
  }
}

void persist_shas_with_buff_id(const size_t buff_id,
                               const size_t *tree_node_indices,
                               const size_t tree_nodes_indices_len,
                               const Sha256 *shas) {
  if (!AuthBufferStore::keyExists(buff_id, AuthBufferStore::lookup_table)) {
    throw std::runtime_error(
        (boost::format("Buffer with id %1% not found.") % buff_id).str());
  }
  auto &auth_buffer = AuthBufferStore::lookup_table.at(buff_id);
  persist_shas(auth_buffer, tree_node_indices, tree_nodes_indices_len, shas);
}

void pull_block_segments_from_buffer_store(const size_t buff_id,
                                           const size_t start_block_idx,
                                           const size_t end_block_idx,
                                           uint8_t *block_bytes,
                                           const size_t *neighbor_ids,
                                           Sha256 *neighbor_shas,
                                           const size_t neighbors_len) {
  if (!AuthBufferStore::keyExists(buff_id, AuthBufferStore::lookup_table)) {
    throw std::runtime_error(
        (boost::format("Buffer with id %1% not found.") % buff_id).str());
  }
  auto &auth_buffer = AuthBufferStore::lookup_table.at(buff_id);
  pull_raw_blocks_from_buffer_store(auth_buffer, start_block_idx, end_block_idx,
                                    block_bytes);
  pull_raw_neighbor_shas_from_buffer_store(auth_buffer, neighbor_ids,
                                           neighbor_shas, neighbors_len);
}

void pull_raw_blocks_from_buffer_store(AuthBufferStore::Inner &auth_buffer,
                                       const size_t start_block_idx,
                                       const size_t end_block_idx,
                                       uint8_t *block_bytes) {
  assert(start_block_idx >= 0 && start_block_idx <= end_block_idx);
  assert(end_block_idx <= auth_buffer._n_blocks);
  std::memmove(
      block_bytes,
      &auth_buffer._content[(start_block_idx * auth_buffer._block_size_bytes)],
      (end_block_idx - start_block_idx + 1) * auth_buffer._block_size_bytes);
}

void pull_raw_neighbor_shas_from_buffer_store(
    AuthBufferStore::Inner &auth_buffer, const size_t *neighbor_ids,
    Sha256 *neighbor_shas, const size_t neighbors_len) {
  for (size_t i = 0; i < neighbors_len; ++i) {
    neighbor_shas[i] = auth_buffer._mk_tree[neighbor_ids[i]];
  }
}

void persist_snapshot(const size_t buff_id, const SnapshotMeta &meta,
                      const uint8_t *cmac) {
  if (!AuthBufferStore::keyExists(buff_id, AuthBufferStore::lookup_table)) {
    throw std::runtime_error(
        (boost::format("Buffer with id %1% not found.") % buff_id).str());
  }
  auto &auth_buffer = AuthBufferStore::lookup_table.at(buff_id);
  if (!AuthBufferStore::keyExists(buff_id,
                                  AuthBufferStore::lookup_snapshot_table)) {
    AuthBufferStore::lookup_snapshot_table[buff_id] = {};
  }
  auto &auth_buffer_snapshots =
      AuthBufferStore::lookup_snapshot_table.at(buff_id);
  // throws if it exists
  auth_buffer_snapshots.emplace(
      std::make_pair(meta, AuthBufferStore::Snapshot{meta, auth_buffer, cmac}));
}
