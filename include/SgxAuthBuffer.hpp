#pragma once

#include <BufferStore.h>
#include <bridge.h>
#include <common.h>
#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

typedef struct _CmacContent {
  Sha256 sha;
  SnapshotMeta meta;
} CmacContent;

static inline std::tuple<size_t, size_t, size_t, size_t, size_t, bool>
calculate_meta(const size_t n_elems, const size_t elem_size,
               const size_t block_size_bytes) noexcept {
  assert(elem_size <= block_size_bytes);
  const size_t n_block_elems = block_size_bytes / elem_size;
  assert(n_block_elems != 0);
  const size_t n_block_padding_bytes = block_size_bytes % elem_size;
  const auto temp = n_elems % n_block_elems;
  const bool last_fully_occupied = temp == 0;
  const size_t last_block_n_elems = last_fully_occupied ? n_block_elems : temp;
  const size_t n_blocks =
      n_elems / n_block_elems + (last_fully_occupied ? 0 : 1);
  const size_t last_block_padding_size_bytes =
      (last_fully_occupied)
          ? n_block_padding_bytes
          : block_size_bytes - (elem_size * last_block_n_elems);
  return std::make_tuple(n_blocks, n_block_elems, n_block_padding_bytes,
                         last_block_n_elems, last_block_padding_size_bytes,
                         last_fully_occupied);
}

template <typename T>
static inline std::vector<uint8_t> make_inited_block(
    const T& default_val, const size_t block_id, const size_t block_size_bytes,
    const size_t n_blocks, const size_t non_last_block_elems_per_block,
    const size_t non_last_block_padding_bytes,
    const size_t last_block_elems_per_block,
    const size_t last_block_padding_bytes

) {
  const auto elem_size = sizeof(T);
  size_t n_block_elems = non_last_block_elems_per_block;
  size_t block_padding_bytes = non_last_block_padding_bytes;
  if (block_id == n_blocks - 1) {
    n_block_elems = last_block_elems_per_block;
    block_padding_bytes = last_block_padding_bytes;
  }
  auto buff = std::vector<uint8_t>(block_size_bytes);
  for (size_t j = 0; j < n_block_elems; j++) {
    std::memmove(&buff[0] + j * elem_size, &default_val, elem_size);
  }
  // zero init the padding bytes if any
  std::memset(&buff[0] + (n_block_elems * elem_size), 0, block_padding_bytes);
  return buff;
}

static inline std::tuple<Sha256, bool> calculate_sha256(const uint8_t* buff,
                                                        const size_t buff_len) {
  bool success = true;
  Sha256 s;
  SHA256_CTX ctx;
  if (!SHA256_Init(&ctx)) {
    success = false;
    return std::make_tuple(s, success);
  }
  if (!SHA256_Update(&ctx, buff, buff_len)) {
    success = false;
    return std::make_tuple(s, success);
  }
  if (!SHA256_Final(s.sha, &ctx)) {
    success = false;
    return std::make_tuple(s, success);
  }
  return std::make_tuple(s, success);
}

static inline std::tuple<Cmac128, bool> calculate_cmac128(
    const uint8_t* buff, const size_t buff_len) {
  bool success = true;
  Cmac128 c;
  CMAC_CTX* ctx = CMAC_CTX_new();
  if (!ctx) {
    success = false;
  } else {
    if (CMAC_Init(ctx, cmac_key, CMAC_KEY_SIZE_BYTES, EVP_aes_128_cbc(),
                  NULL) != 1) {
      success = false;
    } else {
      if (CMAC_Update(ctx, buff, buff_len) != 1) {
        success = false;
      } else {
        size_t result_len = 0;
        if (CMAC_Final(ctx, c.cmac, &result_len) != 1) {
          success = false;
        }
      }
    }
  }
  CMAC_CTX_free(ctx);
  return std::make_tuple(c, success);
}

static inline PulledBlocks pull_blocks(
    const size_t buffer_id, const size_t block_size_bytes,
    const size_t start_block_id, const size_t end_block_id,
    const std::unordered_set<size_t>& sha_neighbors) {
  PulledBlocks pb;
  const auto neighbors_len = sha_neighbors.size();
  pb.neighbor_ids.reserve(neighbors_len);
  pb.neighbor_shas.resize(neighbors_len);
  pb.blocks.resize((end_block_id - start_block_id + 1) * block_size_bytes);
  for (const auto& neighbor_id : sha_neighbors) {
    pb.neighbor_ids.push_back(neighbor_id);
  }
  pull_block_segments_from_buffer_store(buffer_id, start_block_id, end_block_id,
                                        &pb.blocks[0], &pb.neighbor_ids[0],
                                        &pb.neighbor_shas[0], neighbors_len);
  return pb;
}

static void inline push_blocks(const size_t buffer_id, PushedBlocks&& psb,
                               const size_t start_block_id,
                               const size_t end_block_id) {
  persist_authbuff(buffer_id, start_block_id, end_block_id,
                   &psb.updated_blocks[0], psb.updated_blocks.size(),
                   &psb.updated_sha_ids[0], psb.updated_sha_ids.size(),
                   &psb.updated_shas[0]);
}

struct SgxAuthBufferBase {
 protected:
  static size_t global_id;
};

template <typename T>
struct SgxAuthBuffer : private virtual SgxAuthBufferBase {
  static_assert(std::is_trivial<T>::value, "Type T must be a trivial type.");
  static_assert(std::is_standard_layout<T>::value,
                "Type T must have a standard layout.");

  static constexpr size_t elem_size = sizeof(T);

  struct Segment {
    using TAuthBuffer = SgxAuthBuffer<T>;
    using TItemContainer = std::vector<T>;
    using TShaContainer = std::unordered_map<size_t, Sha256>;
    using TIdContainer = std::unordered_set<size_t>;

    TAuthBuffer& _auth_buffer{};
    const size_t _start_idx{};
    const size_t _end_idx{};
    const size_t _block_start_id{};
    const size_t _block_start_in_block_first_idx{};
    const size_t _block_end_id{};
    const size_t _block_end_in_block_last_idx{};

    TItemContainer _segment_items{};
    TIdContainer _neighbor_node_ids{};
    TIdContainer _parent_node_ids{};

    explicit Segment(TAuthBuffer& auth_buffer, const size_t start_idx,
                     const size_t end_idx)
        : _auth_buffer{auth_buffer},
          _start_idx{start_idx},
          _end_idx{end_idx},
          _block_start_id{_start_idx / _auth_buffer._n_elems_per_block},
          _block_start_in_block_first_idx{_start_idx %
                                          _auth_buffer._n_elems_per_block},
          _block_end_id{_end_idx / _auth_buffer._n_elems_per_block},
          _block_end_in_block_last_idx{_end_idx %
                                       _auth_buffer._n_elems_per_block},
          _segment_items(end_idx - start_idx + 1) {
      // claculate the blocks to be fetched
      assert(_start_idx >= 0 && _end_idx < _auth_buffer._n_elems &&
             _start_idx <= _end_idx);
      assert(_block_end_id < _auth_buffer._n_blocks);
      // claculate the necessary neighbor ids to bring in their Sha256s for
      // verification, in addition to the parent indices that could be updated
      this->calculate_merkle_neighbors_and_parents();
      // bring in the blocks in scope, plus the neighbor Sha256s that are in
      // scope for verification
      PulledBlocks pb = pull_blocks(
          this->_auth_buffer._id, this->_auth_buffer._block_size_bytes,
          _block_start_id, _block_end_id, this->_neighbor_node_ids);
      // verify the validity of the blocks
      if (!this->isValidSegment(pb, _block_start_id, _block_end_id)) {
        throw std::runtime_error("validation failed for segment.");
      }

      // make a contigouous buffer from the items in range. Effectively,
      // eliminating the paddings and the block boundaries.
      this->fillContiguous(pb.blocks);
    }

    TShaContainer getUpdatedShas() { return {}; }

    T& operator[](size_t index) {
      assert(index >= _start_idx && index <= _end_idx);
      return _segment_items[index - _start_idx];
    }

    const T& operator[](size_t index) const {
      return const_cast<Segment*>(this)->operator[](index);
    }

    size_t size() const noexcept { return this->_segment_items.size(); }

    std::tuple<T*, size_t> ptr(size_t index) {
      return {&this->operator[](index),
              this->size() - (index - this->_start_idx)};
    }

    Segment(const Segment&) = delete;
    Segment& operator=(const Segment&) = delete;

    Segment(Segment&&) = delete;
    Segment& operator=(Segment&&) = delete;

    ~Segment() {
      PushedBlocks psb;
      PulledBlocks pb = pull_blocks(
          this->_auth_buffer._id, this->_auth_buffer._block_size_bytes,
          _block_start_id, _block_end_id, this->_neighbor_node_ids);
      psb.updated_blocks = std::move(pb.blocks);
      // just updating the ranges that are in scope of this segment
      overWriteBlocks(psb.updated_blocks);
      // also updates auth_buffer's root sha
      updateShas(psb, pb);
      // write back to bufferstore
      push_blocks(this->_auth_buffer._id, std::move(psb), this->_block_start_id,
                  this->_block_end_id);
    }

   private:
    /**
     * pb.blocks has been moved!
     */
    void updateShas(PushedBlocks& psb, PulledBlocks& pb) {
      TShaContainer updated_shas;
      TShaContainer neighbor_shas;
      for (size_t i = 0; i < pb.neighbor_shas.size(); ++i) {
        neighbor_shas[pb.neighbor_ids[i]] = pb.neighbor_shas[i];
      }
      for (size_t i = this->_block_start_id; i <= this->_block_end_id; i++) {
        bool is_success = false;
        std::tie(updated_shas[this->_auth_buffer._n_blocks - 1 + i],
                 is_success) =
            calculate_sha256(
                &psb.updated_blocks[(i - this->_block_start_id) *
                                    this->_auth_buffer._block_size_bytes],
                this->_auth_buffer._block_size_bytes);
        assert(is_success);
      }
      for (size_t i = this->_block_start_id; i <= this->_block_end_id; i++) {
        this->updatePathShas(i, updated_shas, neighbor_shas);
      }
      const size_t update_size = updated_shas.size();
      psb.updated_shas.resize(update_size);
      psb.updated_sha_ids.resize(update_size);
      size_t i = 0;
      for (const auto& [node_id, sha] : updated_shas) {
        psb.updated_shas[i] = sha;
        psb.updated_sha_ids[i] = node_id;
        ++i;
      };

      this->_auth_buffer._root_sha = updated_shas[0];
    }

    void updatePathShas(const size_t block_id, TShaContainer& updated_shas,
                        TShaContainer& neighbor_shas) {
      size_t current_id = (this->_auth_buffer._n_blocks + block_id - 1);
      Sha256 current_sha = updated_shas[current_id];
      std::vector<Sha256> sha_buffer(2);
      while (current_id > 0) {
        size_t parent_id = (current_id - 1) / 2;
        size_t neighbor_id = 0;
        size_t is_even = false;
        if ((current_id & 1) == 0) {
          neighbor_id = current_id - 1;
          sha_buffer[1] = current_sha;
          is_even = true;
        } else {
          neighbor_id = current_id + 1;
          sha_buffer[0] = current_sha;
        }
        if (updated_shas.count(neighbor_id) != 0) {
          sha_buffer[is_even ? 0 : 1] = updated_shas[neighbor_id];
        } else {
          sha_buffer[is_even ? 0 : 1] = neighbor_shas[neighbor_id];
        }
        bool is_success = false;
        std::tie(current_sha, is_success) = calculate_sha256(
            (const uint8_t*)&sha_buffer[0], 2 * sizeof(Sha256));
        updated_shas[parent_id] = current_sha;
        current_id = parent_id;
      }
    }

    void overWriteBlocks(std::vector<uint8_t>& block_bytes) {
      // signle block
      if (this->_block_start_id == this->_block_end_id) {
        T* pointer = (T*)&block_bytes[0];
        for (size_t i = this->_block_start_in_block_first_idx;
             i <= this->_block_end_in_block_last_idx; ++i) {
          pointer[i] =
              this->_segment_items[i - this->_block_start_in_block_first_idx];
        }
        return;
      }
      // more than one block
      T* pointer = (T*)&block_bytes[0];
      const T* segement_pointer = &this->_segment_items[0];
      // first block
      for (size_t i = this->_block_start_in_block_first_idx;
           i < this->_auth_buffer._n_elems_per_block; i++) {
        *(pointer++) = *(segement_pointer++);
      }
      // middle blocks
      for (size_t b = this->_block_start_id + 1; b < this->_block_end_id; b++) {
        T* pointer = (T*)&block_bytes[b * this->_auth_buffer._block_size_bytes];
        for (size_t i = 0; i < this->_auth_buffer._n_elems_per_block; i++) {
          *(pointer++) = *(segement_pointer++);
        }
      }
      // last block
      pointer = (T*)&block_bytes[(this->_block_end_id - this->_block_start_id) *
                                 this->_auth_buffer._block_size_bytes];
      for (size_t i = 0; i <= this->_block_end_in_block_last_idx; i++) {
        *(pointer++) = *(segement_pointer++);
      }
    }
    void fillContiguous(const std::vector<uint8_t>& block_bytes) {
      // signle block
      if (this->_block_start_id == this->_block_end_id) {
        const T* pointer = (const T*)&block_bytes[0];
        for (size_t i = this->_block_start_in_block_first_idx;
             i <= this->_block_end_in_block_last_idx; ++i) {
          this->_segment_items[i - this->_block_start_in_block_first_idx] =
              pointer[i];
        }
        return;
      }
      // more than one block
      const T* pointer = (const T*)&block_bytes[0];
      T* segement_pointer = &this->_segment_items[0];
      // first block
      for (size_t i = this->_block_start_in_block_first_idx;
           i < this->_auth_buffer._n_elems_per_block; i++) {
        *(segement_pointer++) = *(pointer++);
      }
      // middle blocks
      for (size_t b = this->_block_start_id + 1; b < this->_block_end_id; b++) {
        const T* pointer =
            (const T*)&block_bytes[b * this->_auth_buffer._block_size_bytes];
        for (size_t i = 0; i < this->_auth_buffer._n_elems_per_block; i++) {
          *(segement_pointer++) = *(pointer++);
        }
      }
      // last block
      pointer =
          (const T*)&block_bytes[(this->_block_end_id - this->_block_start_id) *
                                 this->_auth_buffer._block_size_bytes];
      for (size_t i = 0; i <= this->_block_end_in_block_last_idx; i++) {
        *(segement_pointer++) = *(pointer++);
      }
    }

    bool isValidSegment(const PulledBlocks& pb, const size_t start_block_id,
                        const size_t end_block_id) {
      TShaContainer shas{};
      for (size_t i = 0; i < pb.neighbor_shas.size(); ++i) {
        shas[pb.neighbor_ids[i]] = pb.neighbor_shas[i];
      }
      for (size_t i = start_block_id; i <= end_block_id; i++) {
        bool is_success = false;
        std::tie(shas[this->_auth_buffer._n_blocks - 1 + i], is_success) =
            calculate_sha256(&pb.blocks[(i - start_block_id) *
                                        this->_auth_buffer._block_size_bytes],
                             this->_auth_buffer._block_size_bytes);
        assert(is_success);
      }
      for (size_t i = start_block_id; i <= end_block_id; i++) {
        if (!this->isValidBlock(i, shas)) {
          return false;
        }
      }
      return true;
    }

    bool isValidBlock(const size_t block_id, TShaContainer& shas) {
      size_t current_id = this->_auth_buffer._n_blocks - 1 + block_id;
      Sha256 current_sha = shas[current_id];
      std::vector<Sha256> sha_buffer(2);
      while (current_id > 0) {
        size_t neighbor_id;
        if ((current_id & 1) == 0) {
          neighbor_id = current_id - 1;
          sha_buffer[0] = shas[neighbor_id];
          sha_buffer[1] = current_sha;
        } else {
          neighbor_id = current_id + 1;
          sha_buffer[1] = shas[neighbor_id];
          sha_buffer[0] = current_sha;
        }
        bool is_success = false;
        std::tie(current_sha, is_success) = calculate_sha256(
            (const uint8_t*)&sha_buffer[0], 2 * sizeof(Sha256));
        assert(is_success);
        // parent
        current_id = (current_id - 1) / 2;
      }
      return std::memcmp(current_sha.sha, this->_auth_buffer._root_sha.sha,
                         SHA256_SIZE_BYTES) == 0;
    }

    void calculate_merkle_neighbors_and_parents() {
      const size_t start_block_id = this->_block_start_id;
      const size_t end_block_id = this->_block_end_id;
      assert(start_block_id <= end_block_id);
      const size_t mapped_start_block_id =
          start_block_id + this->_auth_buffer._n_blocks - 1;
      const size_t mapped_end_block_id =
          end_block_id + this->_auth_buffer._n_blocks - 1;
      assert(mapped_end_block_id < 2 * this->_auth_buffer._n_blocks - 1);

      for (size_t i = mapped_start_block_id; i <= mapped_end_block_id; ++i) {
        size_t current_node_id = i;
        while (current_node_id > 0) {
          size_t neighbor_id;
          if ((current_node_id & 1) == 0) {
            neighbor_id = current_node_id - 1;
          } else {
            neighbor_id = current_node_id + 1;
          }
          if (!(neighbor_id >= mapped_start_block_id &&
                neighbor_id <= mapped_end_block_id)) {
            this->_neighbor_node_ids.insert(neighbor_id);
          }
          current_node_id = (current_node_id - 1) / 2;
          this->_parent_node_ids.insert(current_node_id);
        }
      }
    }
  };

  Sha256 _root_sha{};
  size_t _n_elems{};
  size_t _id{};
  size_t _block_size_bytes{};
  size_t _n_blocks{};
  size_t _n_elems_per_block{};
  size_t _block_padding_size_bytes{};
  size_t _n_elems_last_block{};
  size_t _last_block_padding_size_bytes{};
  size_t _n_tree_nodes{};
  bool _last_fully_occupied{false};

  explicit SgxAuthBuffer(
      const size_t n_elems,
      const size_t block_size_bytes = DEFAULT_BLOCK_SIZE_BYTES,
      const T& default_val = T{})
      : SgxAuthBuffer<T>(calculate_meta(n_elems, elem_size, block_size_bytes)) {
    this->_n_elems = n_elems;
    this->_id = global_id++;
    this->_block_size_bytes = block_size_bytes;
    this->_n_tree_nodes = (2 * this->_n_blocks) - 1;
    initBufferOutside(default_val);
  }

  SgxAuthBuffer(const SgxAuthBuffer&) = delete;
  SgxAuthBuffer& operator=(const SgxAuthBuffer&) = delete;

  SgxAuthBuffer(SgxAuthBuffer&&) = delete;
  SgxAuthBuffer& operator=(SgxAuthBuffer&&) = delete;

  ~SgxAuthBuffer() = default;

  /**
   * end is inclusive
   */
  Segment getSegment(const size_t start, const size_t end) {
    return Segment{*this, start, end};
  }

  const Segment getSegment(const size_t start, const size_t end) const {
    return const_cast<SgxAuthBuffer<T>*>(this)->getSegment(start, end);
  }

  Segment getSegment(const size_t idx) { return Segment{*this, idx, idx}; }

  const Segment getSegment(const size_t idx) const {
    return const_cast<SgxAuthBuffer<T>*>(this)->getSegment(idx);
  }

  void saveSnapshot(const SnapshotMeta& meta) {
    CmacContent a{this->_root_sha, meta};
    auto [cmac, success] =
        calculate_cmac128((const uint8_t*)&a, sizeof(CmacContent));
    assert(success);
    persist_snapshot(this->_id, meta, (const uint8_t*)&cmac);
  }

 private:
  SgxAuthBuffer(const std::tuple<size_t, size_t, size_t, size_t, size_t, bool>&
                    computed_meta)
      : _n_blocks{std::get<0>(computed_meta)},
        _n_elems_per_block{std::get<1>(computed_meta)},
        _block_padding_size_bytes{std::get<2>(computed_meta)},
        _n_elems_last_block{std::get<3>(computed_meta)},
        _last_block_padding_size_bytes{std::get<4>(computed_meta)},
        _last_fully_occupied{std::get<5>(computed_meta)} {}

  void initBufferOutside(const T& default_val) {
    instantiate_new_buffer(this->_id, this->_n_elems, this->_n_blocks,
                           this->elem_size, this->_block_size_bytes);
    std::vector<Sha256> last_level_shas(this->_n_blocks);

    for (size_t i = 0; i < this->_n_blocks; ++i) {
      const std::vector<uint8_t> buff = make_inited_block(
          default_val, i, this->_block_size_bytes, this->_n_blocks,
          this->_n_elems_per_block, this->_block_padding_size_bytes,
          this->_n_elems_last_block, this->_last_block_padding_size_bytes);
      auto [sha, success] = calculate_sha256(&buff[0], buff.size());
      if (!success) {
        throw std::runtime_error("Calculating sha256 was unsuccesful");
      }
      last_level_shas[i] = sha;
      flushInitialBlock(i, &buff[0], buff.size());
    }
    // construct the merkle tree and store the root hash
    this->_root_sha =
        buildMerkleTreeAndFlushSha256s(std::move(last_level_shas));
  }

  Sha256 buildMerkleTreeAndFlushSha256s(std::vector<Sha256>&& leaf_shas) {
    std::vector<Sha256> merkle_tree(this->_n_tree_nodes);
    std::copy(leaf_shas.begin(), leaf_shas.end(),
              merkle_tree.begin() + this->_n_blocks - 1);
    auto temp_buff = std::vector<Sha256>(2);
    // Watch out: 0 minus 1 == max u64!!!! took me an hour to debug the
    // segfault for (size_t i = this->n_blocks - 2; i >= 0; --i) {
    for (int64_t i = this->_n_blocks - 2; i >= 0; --i) {
      temp_buff[0] = merkle_tree[2 * i + 1];
      temp_buff[1] = merkle_tree[2 * i + 2];
      auto [sha, success] =
          calculate_sha256((const uint8_t*)&temp_buff[0], 2 * sizeof(Sha256));
      if (!success) {
        throw std::runtime_error("Calculating sha256 was unsuccesful");
      }
      merkle_tree[i] = sha;
    }
    size_t current = 0;
    std::vector<size_t> id_seq(this->_n_tree_nodes);
    std::generate(id_seq.begin(), id_seq.end(),
                  [&current]() { return current++; });
    persist_shas_with_buff_id(this->_id, &id_seq[0], id_seq.size(),
                              &merkle_tree[0]);
    return merkle_tree[0];
  }

  void flushInitialBlock(const size_t block_id, const uint8_t* buff,
                         const size_t buff_len) {
    persist_blocks_with_buff_id(this->_id, block_id, block_id, buff, buff_len);
  }
};
