#pragma once

#include <common.h>

#include <boost/container_hash/extensions.hpp>
#include <boost/functional/hash.hpp>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

struct SnapshotMetaHash {
  std::size_t operator()(const SnapshotMeta &meta) const {
    std::size_t seed = 0;
    boost::hash_combine(seed, meta.ts);
    return seed;
  }
};

bool operator==(const SnapshotMeta &lhs, const SnapshotMeta &rhs);

/**
 * Static helper class
 */
struct AuthBufferStore {
  using TMerkletTree = std::vector<Sha256>;
  using TBytes = std::vector<uint8_t>;

  struct Inner {
    TBytes _content{};
    TMerkletTree _mk_tree{};

    const size_t _buff_id{};
    const size_t _n_elems{};
    const size_t _n_blocks{};
    const size_t _elem_size{};
    const size_t _block_size_bytes{};

    explicit Inner(const size_t buff_id, const size_t n_elems,
                   const size_t n_blocks, const size_t elem_size,
                   const size_t block_size_bytes);
  };

  struct Snapshot {
    Inner _inner;
    SnapshotMeta _meta;
    Cmac128 _root_cmac{};
    explicit Snapshot(const SnapshotMeta &meta, const Inner &inner,
                      const uint8_t *root_cmac);
  };

  using TLookUpTable = std::unordered_map<size_t, Inner>;
  using TSnapshotTableValue =
      std::unordered_map<SnapshotMeta, Snapshot, SnapshotMetaHash>;
  using TSnapshotTable = std::unordered_map<size_t, TSnapshotTableValue>;

  static bool keyExists(const size_t &key, const TLookUpTable &t);

  static bool keyExists(const size_t &key, const TSnapshotTable &t);

  static bool keyExists(const SnapshotMeta &key, const TSnapshotTableValue &t);

  static TLookUpTable lookup_table;
  static TSnapshotTable lookup_snapshot_table;

  friend AuthBufferStore &get_auth_buffer_signleton();

 private:
  AuthBufferStore() = default;
};
