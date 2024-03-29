#include <BufferStore.h>
#include <bridge.h>
#include <gtest/gtest-death-test.h>
#include <gtest/gtest.h>

#include <SgxAuthBuffer.hpp>
#include <cstdint>
#include <cstring>
#include <tuple>

#include "common.h"

TEST(SgxAuthBufferFloatCalculationTest,
     full_blocks_no_padding_last_block_with_padding) {
  EXPECT_FALSE(AuthBufferStore::keyExists(0, AuthBufferStore::lookup_table));
  /**
   * 8*4 + 0 padding for two blocks
   * 5*4 + 12 padding bytes
   */
  const float default_val = 2.8;
  SgxAuthBuffer<float> a(21, 32, default_val);
  EXPECT_EQ(a._n_elems, 21);
  EXPECT_EQ(a._block_size_bytes, 32);
  EXPECT_EQ(a._n_blocks, 3);
  EXPECT_EQ(a._n_elems_per_block, 8);
  EXPECT_EQ(a._block_padding_size_bytes, 0);
  EXPECT_EQ(a._n_elems_last_block, 5);
  EXPECT_EQ(a._last_block_padding_size_bytes, 12);
  EXPECT_FALSE(a._last_fully_occupied);

  // check whether an empty corresponding buffer is created.
  EXPECT_TRUE(AuthBufferStore::keyExists(0, AuthBufferStore::lookup_table));
  EXPECT_EQ(AuthBufferStore::lookup_table.at(0)._content.size(), (3 * 32));
  EXPECT_EQ(AuthBufferStore::lookup_table.at(0)._mk_tree.size(), (5));
  EXPECT_EQ(AuthBufferStore::lookup_table.at(0)._n_elems, (21));

  // check whether a proper segement can be pulled in from buffer store and
  // verified.
  {
    auto first_sha = a._root_sha;
    {
      EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
      auto view = a.getSegment(3, 18);
      // we don't expect any change unless the view goes out of scope so the
      // write to bufferstore happens
      EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
    }
    // after going out of scope write happens
    EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
  }
  {
    auto first_sha = a._root_sha;
    {
      EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
      auto view = a.getSegment(3, 18);
      view[4] = 2.45;
      EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
    }
    EXPECT_NE(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
    {
      auto view = a.getSegment(3, 18);
      view[4] = default_val;
    }
    EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
  }
  // invalid indices requested
  {
    auto first_sha = a._root_sha;
    EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
    ASSERT_DEBUG_DEATH({ auto view = a.getSegment(3, 32); }, "");
  }

  // malicious changes, hence the verification root merkle hash will not match
  // the hash kept in enclave
  {
    auto& ref = AuthBufferStore::lookup_table.at(0)._content[32];
    auto before = ref;
    ref = 47;
    // should throw because will not match the root sha that is kept in enclave.
    EXPECT_ANY_THROW({ auto view = a.getSegment(8, 11); });
    ref = before;
    // should not throw
    { auto view = a.getSegment(8, 11); }
  }
  {
    auto first_sha = a._root_sha;
    // .ts = 1
    a.saveSnapshot(SnapshotMeta{1});
    EXPECT_EQ(AuthBufferStore::lookup_snapshot_table.count(0), 1);
    EXPECT_EQ(AuthBufferStore::lookup_snapshot_table[0].count({1}), 1);
    {
      auto view = a.getSegment(11, 20);
      view[13] = 4.0;
    }
    auto second_sha = a._root_sha;
    a.saveSnapshot(SnapshotMeta{2});
    EXPECT_EQ(AuthBufferStore::lookup_snapshot_table[0].count({2}), 1);
    EXPECT_NE(std::memcmp(&AuthBufferStore::lookup_snapshot_table[0]
                               .at({1})
                               ._inner._mk_tree[0],
                          &AuthBufferStore::lookup_snapshot_table[0]
                               .at({2})
                               ._inner._mk_tree[0],
                          sizeof(Sha256)),
              0);

    EXPECT_EQ(std::memcmp(first_sha.sha,
                          &AuthBufferStore::lookup_snapshot_table[0]
                               .at({1})
                               ._inner._mk_tree[0],
                          sizeof(Sha256)),
              0);
    EXPECT_EQ(std::memcmp(second_sha.sha,
                          &AuthBufferStore::lookup_snapshot_table[0]
                               .at({2})
                               ._inner._mk_tree[0],
                          sizeof(Sha256)),
              0);
    {
      auto view = a.getSegment(4, 12);
      view[8] = 4.5;
    }
    a.saveSnapshot(SnapshotMeta{3});
    // loading the snapshot 1
    a.loadSnapshot(SnapshotMeta{1});

    // malicious changes: messing with snapshot two and expecting failure
    {
      auto& ref =
          AuthBufferStore::lookup_snapshot_table[0].at({2})._inner._content[32];
      auto before = ref;
      // messing with the first byte of the second block
      ref = 3;
      a.loadSnapshot(SnapshotMeta{2});
      {
        // block 2 is included
        EXPECT_ANY_THROW({ auto view = a.getSegment(3, 11); });
        EXPECT_ANY_THROW({ auto view = a.getSegment(8, 11); });
        EXPECT_ANY_THROW({ auto view = a.getSegment(4, 19); });
        ref = before;
        a.loadSnapshot(SnapshotMeta{2});
        // we do not expect any throw since it mathes the initial content
        { auto view = a.getSegment(3, 11); };
        { auto view = a.getSegment(8, 11); };
        { auto view = a.getSegment(4, 19); };
      }
    }

    a.loadSnapshot(SnapshotMeta{3});
  }
}

TEST(SgxAuthBufferFloatCalculationTest, full_blocks_no_padding_no_last_block) {
  EXPECT_FALSE(AuthBufferStore::keyExists(0, AuthBufferStore::lookup_table));
  /**
   * 8*4 + 0 padding for two blocks
   */
  SgxAuthBuffer<float> a(16, 32);
  EXPECT_EQ(a._n_elems, 16);
  EXPECT_EQ(a._block_size_bytes, 32);
  EXPECT_EQ(a._n_blocks, 2);
  EXPECT_EQ(a._n_elems_per_block, 8);
  EXPECT_EQ(a._block_padding_size_bytes, 0);
  EXPECT_EQ(a._n_elems_last_block, 8);
  EXPECT_EQ(a._last_block_padding_size_bytes, 0);
  EXPECT_TRUE(a._last_fully_occupied);

  EXPECT_TRUE(AuthBufferStore::keyExists(0, AuthBufferStore::lookup_table));
  {
    auto first_sha = a._root_sha;
    {
      EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
      auto view = a.getSegment(2, 7);
      view[4] = 2.45;
      EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
    }
    EXPECT_NE(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
    {
      auto view = a.getSegment(2, 7);
      view[4] = 0;
    }
    EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
  }
}

TEST(SgxAuthBufferFloatCalculationTest, single_block_with_padding) {
  /**
   * 6*4 + 8 padding for one block
   */
  SgxAuthBuffer<float> a(6, 32);
  EXPECT_EQ(a._n_elems, 6);
  EXPECT_EQ(a._block_size_bytes, 32);
  EXPECT_EQ(a._n_blocks, 1);
  EXPECT_EQ(a._n_elems_per_block, 8);
  EXPECT_EQ(a._block_padding_size_bytes, 0);
  EXPECT_EQ(a._n_elems_last_block, 6);
  EXPECT_EQ(a._last_block_padding_size_bytes, 8);
  EXPECT_FALSE(a._last_fully_occupied);

  {
    auto first_sha = a._root_sha;
    {
      EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
      auto view = a.getSegment(1, 5);
      view[4] = 2.45;
      EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
    }
    EXPECT_NE(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
    {
      auto view = a.getSegment(1, 5);
      view[4] = 0;
    }
    EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
  }
}

TEST(SgxAuthBufferFloatCalculationTest, single_block_with_no_padding) {
  /**
   * 8*4 + 0 padding for one block
   */
  SgxAuthBuffer<float> a(8, 32);
  EXPECT_EQ(a._n_elems, 8);
  EXPECT_EQ(a._block_size_bytes, 32);
  EXPECT_EQ(a._n_blocks, 1);
  EXPECT_EQ(a._n_elems_per_block, 8);
  EXPECT_EQ(a._block_padding_size_bytes, 0);
  EXPECT_EQ(a._n_elems_last_block, 8);
  EXPECT_EQ(a._last_block_padding_size_bytes, 0);
  EXPECT_TRUE(a._last_fully_occupied);

  {
    auto first_sha = a._root_sha;
    {
      EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
      auto view = a.getSegment(0, 7);
      float* ptr = nullptr;
      size_t len = 0;
      std::tie(ptr, len) = view.ptr(4);
      EXPECT_EQ(len, 4);
      ptr[0] = 2.2;
      ptr[1] = 2.3;
      EXPECT_FLOAT_EQ(view[4], 2.2);
      EXPECT_FLOAT_EQ(view[5], 2.3);
      EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
    }
    EXPECT_NE(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
    {
      auto view = a.getSegment(0, 7);
      view[4] = 0;
      view[5] = 0;
    }
    EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
  }
}

typedef struct _cutstom {
  uint8_t f[5];
} custom;

TEST(SgxAuthBufferCustomCalculationTest,
     full_blocks_with_padding_last_block_with_padding) {
  /**
   * 6*5 + 2 padding for two blocks
   * 6*1 + 27 padding for one block
   */
  EXPECT_EQ(sizeof(custom), 5);
  SgxAuthBuffer<custom> a(13, 32);
  EXPECT_EQ(a._n_elems, 13);
  EXPECT_EQ(a._block_size_bytes, 32);
  EXPECT_EQ(a._n_blocks, 3);
  EXPECT_EQ(a._n_elems_per_block, 6);
  EXPECT_EQ(a._block_padding_size_bytes, 2);
  EXPECT_EQ(a._n_elems_last_block, 1);
  EXPECT_EQ(a._last_block_padding_size_bytes, 27);
  EXPECT_FALSE(a._last_fully_occupied);

  auto first_sha = a._root_sha;
  {
    auto view = a.getSegment(11, 12);
    uint8_t foo[10] = {1, 2, 3, 4, 5, 6, 8, 9, 10};
    custom* ptr = nullptr;
    size_t len = 0;
    std::tie(ptr, len) = view.ptr(11);
    EXPECT_EQ(len, 2);
    std::memmove(ptr, foo, 2 * sizeof(custom));
    EXPECT_EQ(std::memcmp(&view[12], &foo[5], sizeof(custom)), 0);
  }
  {
    EXPECT_NE(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
    auto view = a.getSegment(11, 12);
    custom* ptr = nullptr;
    size_t len = 0;
    std::tie(ptr, len) = view.ptr(11);
    std::memset(ptr, 0, len * sizeof(custom));
  }
  EXPECT_EQ(std::memcmp(first_sha.sha, a._root_sha.sha, sizeof(Sha256)), 0);
}

TEST(SgxAuthBufferCustomCalculationTest,
     full_blocks_with_padding_no_last_block) {
  /**
   * 6*5 + 2 padding for two blocks
   */
  SgxAuthBuffer<custom> a(12, 32);
  EXPECT_EQ(a._n_elems, 12);
  EXPECT_EQ(a._block_size_bytes, 32);
  EXPECT_EQ(a._n_blocks, 2);
  EXPECT_EQ(a._n_elems_per_block, 6);
  EXPECT_EQ(a._block_padding_size_bytes, 2);
  EXPECT_EQ(a._n_elems_last_block, 6);
  EXPECT_EQ(a._last_block_padding_size_bytes, 2);
  EXPECT_TRUE(a._last_fully_occupied);
  { const auto view = a.getSegment(8, 10); }
  { const auto view = a.getSegment(3, 5); }
  { const auto view = a.getSegment(5, 6); }
}

TEST(SgxAuthBufferCustomCalculationTest, single_block_with_padding) {
  /**
   * 5*5 + 2 padding for one block
   */
  SgxAuthBuffer<custom> a(5, 32);
  EXPECT_EQ(a._n_elems, 5);
  EXPECT_EQ(a._block_size_bytes, 32);
  EXPECT_EQ(a._n_blocks, 1);
  EXPECT_EQ(a._n_elems_per_block, 6);
  EXPECT_EQ(a._block_padding_size_bytes, 2);
  EXPECT_EQ(a._n_elems_last_block, 5);
  EXPECT_EQ(a._last_block_padding_size_bytes, 7);
  EXPECT_FALSE(a._last_fully_occupied);
  { const auto view = a.getSegment(2, 3); }
  { const auto view = a.getSegment(1, 4); }
  { const auto view = a.getSegment(0, 4); }
}

TEST(SgxAuthBufferCustomCalculationTest,
     single_block_with_padding_fully_occupied) {
  /**
   * 6*5 + 2 padding for one block
   */
  SgxAuthBuffer<custom> a(6, 32);
  EXPECT_EQ(a._n_elems, 6);
  EXPECT_EQ(a._block_size_bytes, 32);
  EXPECT_EQ(a._n_blocks, 1);
  EXPECT_EQ(a._n_elems_per_block, 6);
  EXPECT_EQ(a._block_padding_size_bytes, 2);
  EXPECT_EQ(a._n_elems_last_block, 6);
  EXPECT_EQ(a._last_block_padding_size_bytes, 2);
  EXPECT_TRUE(a._last_fully_occupied);
  {
    auto view = a.getSegment(2, 5);
    view[2] = custom{{1, 2, 3, 4, 5}};
  }
}
