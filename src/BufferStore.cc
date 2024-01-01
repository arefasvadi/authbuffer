#include <BufferStore.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "common.h"

using namespace std;
AuthBufferStore::TLookUpTable AuthBufferStore::lookup_table;
AuthBufferStore::TSnapshotTable AuthBufferStore::lookup_snapshot_table;

AuthBufferStore::Inner::Inner(size_t buff_id, size_t n_elems, size_t n_blocks,
                              size_t elem_size, size_t block_size_bytes)
    : _content(n_blocks * block_size_bytes),
      _mk_tree((2 * n_blocks - 1)),
      _buff_id{buff_id},
      _n_elems{n_elems},
      _n_blocks{n_blocks},
      _elem_size{elem_size},
      _block_size_bytes{block_size_bytes} {};

AuthBufferStore::Inner::Inner(const AuthBufferStore::Inner &other)
    : _content(other._content),
      _mk_tree(other._mk_tree),
      _buff_id(other._buff_id),
      _n_elems(other._n_elems),
      _n_blocks(other._n_blocks),
      _elem_size(other._elem_size),
      _block_size_bytes(other._block_size_bytes) {}

AuthBufferStore::Inner &AuthBufferStore::Inner::operator=(
    const AuthBufferStore::Inner &other) {
  if (this != &other) {
    _content = other._content;
    _mk_tree = other._mk_tree;
    _buff_id = other._buff_id;
    _n_elems = other._n_elems;
    _n_blocks = other._n_blocks;
    _elem_size = other._elem_size;
    _block_size_bytes = other._block_size_bytes;
  }
  return *this;
}

AuthBufferStore::Inner::Inner(AuthBufferStore::Inner &&other) noexcept
    : _content(std::move(other._content)),
      _mk_tree(std::move(other._mk_tree)),
      _buff_id(other._buff_id),
      _n_elems(other._n_elems),
      _n_blocks(other._n_blocks),
      _elem_size(other._elem_size),
      _block_size_bytes(other._block_size_bytes) {}

AuthBufferStore::Inner &AuthBufferStore::Inner::operator=(
    AuthBufferStore::Inner &&other) noexcept {
  if (this != &other) {
    _content = std::move(other._content);
    _mk_tree = std::move(other._mk_tree);
    _buff_id = other._buff_id;
    _n_elems = other._n_elems;
    _n_blocks = other._n_blocks;
    _elem_size = other._elem_size;
    _block_size_bytes = other._block_size_bytes;
  }
  return *this;
}

AuthBufferStore::Snapshot::Snapshot(const SnapshotMeta &meta,
                                    const Inner &inner,
                                    const uint8_t *root_cmac)
    : _inner{inner}, _meta{meta} {
  std::memmove(this->_root_cmac.cmac, root_cmac, CMAC_SIZE_BYTES);
};

bool AuthBufferStore::keyExists(const size_t &key,
                                const AuthBufferStore::TLookUpTable &t) {
  return t.count(key) != 0;
}

bool AuthBufferStore::keyExists(const size_t &key,
                                const AuthBufferStore::TSnapshotTable &t) {
  return t.count(key) != 0;
}

bool AuthBufferStore::keyExists(const SnapshotMeta &key,
                                const AuthBufferStore::TSnapshotTableValue &t) {
  return t.count(key) != 0;
}

bool operator==(const SnapshotMeta &lhs, const SnapshotMeta &rhs) {
  return lhs.ts == rhs.ts;
}
