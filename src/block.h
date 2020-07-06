
#pragma once
#include <iostream>

#include <cstring>
#include <iomanip>
#include <fstream>
#include <vector>

struct BlockHeader {
  uint32_t version;
  unsigned char hashPrevBlock[65];
  unsigned char hashMerkleRoot[65];
  uint32_t time;
  uint32_t bits;
  uint32_t nonce;
  uint64_t txn_count{0};
  unsigned char hash[65];
};

struct BlockOutPoint {
  unsigned char hash[65];
  uint32_t index{0};
};

struct BlockTxIn {
  BlockOutPoint prev_output;
  uint64_t script_len{0};
  unsigned char *script;
  uint32_t seq_no{0};
  BlockTxIn() : script(nullptr) {
  }
  ~BlockTxIn() {
    if (script != nullptr) {
      delete[] script;
      script = nullptr;
    }
  }
  std::string ToString() const;
};

struct BlockTxOut {
  int64_t value;
  uint64_t pk_script_len;
  unsigned char *pk_script;
  BlockTxOut() : pk_script(nullptr) {
  }
  ~BlockTxOut() {
    if (pk_script != nullptr) {
      delete[] pk_script;
      pk_script = nullptr;
    }
  }
  std::string ToString() const;
};

struct SegwitItem {
  uint64_t len{0};
  unsigned char *data{nullptr};
  ~SegwitItem() {
    if (data != nullptr) {
      delete[] data;
      data = nullptr;
    }
  }
};

struct BlockTxHash {
  unsigned char hash[65];
  unsigned char data[1024 * 1024 * 1];
  size_t len{0};
  unsigned char *m_mark{nullptr};

  inline __attribute__((always_inline)) void mark(unsigned char *ptr) {
    m_mark = ptr;
  }
  inline __attribute__((always_inline)) void glue(unsigned char *ptr) {
    size_t size = ptr - m_mark;
    std::memcpy(&data[len], m_mark, size);
    len += size;
  }
};

struct BlockTx {
  int32_t version;
  uint16_t flag;
  uint64_t in_cnt;
  uint64_t out_cnt;
  std::vector<BlockTxIn> vin;
  std::vector<BlockTxOut> vout;
  uint32_t lock_time;
  uint8_t segwit_flag{0};
  uint64_t segwit_count{0};
  std::vector<SegwitItem> witness;

  unsigned char txid[65];
  unsigned char wtxid[65];

  unsigned char hashBin[4096];
  size_t hashBinLen{0};

  unsigned char hash[65];
  BlockTx() {
  }
  ~BlockTx() {
  }
  std::string ToString() const;
};

struct BlockData : public BlockHeader {
  int32_t magic;
  uint32_t blockSize;
};

struct BlockFile : public BlockData {
  BlockFile(const std::string &path, uint32_t file);
  ~BlockFile();
  void Parse();
  std::string ToString() const;

private:
  std::ostringstream filename;
  std::ifstream ifs;
};
