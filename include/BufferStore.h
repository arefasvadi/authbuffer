#pragma once

#include <common.h>

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

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

   private:
    inline void setInited() noexcept;

    inline bool isInited() const noexcept;
  };

  struct Snapshot {
    struct Meta {
      const size_t ts{};
    };
    Inner _inner;
    Cmac128 _root_cmac{};
    const Meta _meta{};
    explicit Snapshot(const Meta meta, const Inner &inner, uint8_t *root_cmac);
  };

  template <typename Tv>
  using TLookUp = std::unordered_map<size_t, Tv>;

  using TLookUpTable = TLookUp<Inner>;
  using TSnapshotTable = TLookUp<std::vector<Snapshot>>;

  template <typename Tv>
  inline static bool keyExists(size_t key, const TLookUp<Tv> &t) noexcept {
    return t.count(key) != 0;
  }

  static TLookUpTable lookup_table;
  static TSnapshotTable lookup_snapshot_table;

  friend AuthBufferStore &get_auth_buffer_signleton();

 private:
  AuthBufferStore() = default;
};
