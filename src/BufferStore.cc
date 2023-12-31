#include <BufferStore.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "common.h"

using namespace std;
AuthBufferStore::TLookUpTable AuthBufferStore::lookup_table{};
AuthBufferStore::TSnapshotTable AuthBufferStore::lookup_snapshot_table{};

AuthBufferStore::Inner::Inner(const size_t buff_id, const size_t n_elems,
                              const size_t n_blocks, const size_t elem_size,
                              const size_t block_size_bytes)
    : _content(n_blocks * block_size_bytes),
      _mk_tree((2 * n_blocks - 1)),
      _buff_id{buff_id},
      _n_elems{n_elems},
      _n_blocks{n_blocks},
      _elem_size{elem_size},
      _block_size_bytes{block_size_bytes} {};

AuthBufferStore::Snapshot::Snapshot(const Meta meta, const Inner &inner,
                                    uint8_t *root_cmac)
    : _inner{inner}, _meta{meta} {
  std::memmove(this->_root_cmac.cmac, root_cmac, CMAC_SIZE_BYTES);
};
