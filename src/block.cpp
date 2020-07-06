#define DUMPHEX
#include "block.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <chrono>
//#include <openssl/sha.h>
#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <byteswap.h>

#include "util/misc.h"
#include "util/crypto.h"
#include "sha2.h"
#include "btc/base58.h"
#include "btc/script.h"
#include "script.h"
#include "ripemd160.h"

BlockFile::BlockFile(const std::string &path, uint32_t file) {
  if (path.empty()) {
    throw std::runtime_error("Path cannot be empty...");
  }
  filename << path << "/";
  filename << "blk" << std::setfill('0') << std::setw(5) << file << ".dat";

  ifs.open(filename.str(), std::ios::in | std::ios::binary);
  if (!ifs.is_open()) {
    std::string error = "Cannot open file " + filename.str();
    throw std::runtime_error(error);
  }
  std::cout << filename.str() << " opened successfully..." << std::endl;
}

BlockFile::~BlockFile() {
  if (ifs.is_open()) {
    ifs.close();
    std::cout << filename.str() << " closed successfully..." << std::endl;
  }
}

const ssize_t BUF_READ_SIZE = 1024 * 1024 * 10;

void BlockFile::Parse() {
  auto b = std::chrono::steady_clock::now();

  // scratch buffers
  unsigned char *tba = new unsigned char[4096];
  unsigned char *tbb = new unsigned char[4096];
  unsigned char *buf = new unsigned char[BUF_READ_SIZE];

  // ifs.seekg(8887649, std::ios::beg);

  uint64_t varint{0};
  std::streampos blockPos;
  while (ifs.good()) {
    std::cout << std::endl;
    std::cout << "===================================================="
              << std::endl;
    std::cout << std::endl;
    blockPos = ifs.tellg();

    BufReset();
    BufRead(ifs, buf, 4, &magic, CBRIGHTMAGENTA);  // magic
    if (magic != 0xD9B4BEF9) {
      std::cout << "File position: " << ifs.tellg() << std::endl;
      std::cout << "magic number invalid: " << std::hex << magic << std::endl;
      break;
    }

    PrintBufHex("Magic", magic);
    BufRead(ifs, buf, 4, &blockSize, CBRIGHTCYAN);  // blockSize
    PrintBufHex("Block size", blockSize);
    BufRead(ifs, buf, 4, &version, CBRIGHTCYAN);  // version
    PrintBufHex("Version", version);

    // hashPrevBlock
    BufRead(ifs, buf, 32, &hashPrevBlock, CBRIGHTGREEN);  // prev hash
    binhexle(&buf[12], 32, hashPrevBlock);
    PrintBufHex("HashPrevBlock", hashPrevBlock);

    // hashMerkleRoot
    BufRead(ifs, buf, 32, &hashMerkleRoot, CBRIGHTGREEN);  // merkle root hash
    binhexle(&buf[12 + 32], 32, hashMerkleRoot);
    PrintBufHex("HashMerkleRoot", hashMerkleRoot);

    BufRead(ifs, buf, 4, &time, CBRIGHTCYAN);  // time
    PrintBufHex("Time", time);
    BufRead(ifs, buf, 4, &bits, CBRIGHTCYAN);  // bits
    PrintBufHex("Bits", bits);
    BufRead(ifs, buf, 4, &nonce, CBRIGHTCYAN);  // nonce
    PrintBufHex("Nonce", nonce);

    // block hash
    dsha256(&buf[8], 80, tba);
    binhexle(tba, 32, hash);
    std::cout << CBRIGHTYELLOW << "Block Hash: " << hash << CRESET << std::endl;

    int flag = 0;

    BufReadVarInt(ifs, buf, txn_count);  // txn_count
    PrintBufHex("Transactions", txn_count);
    for (ssize_t i = 0; i < txn_count; i++) {
      std::cout << "Page: " << i / 5 << std::endl;
      BlockTx tx;
      BlockTxHash txid;
      BlockTxHash wtxid;

      txid.mark(GetBufCurPtr(buf));
      wtxid.mark(GetBufCurPtr(buf));

      BufRead(ifs, buf, 4, &tx.version, CBRIGHTYELLOW);  // tx version
      PrintBufHex("Version", tx.version);

      txid.glue(GetBufCurPtr(buf));
      txid.mark(GetBufCurPtr(buf));

      // input transactions
      BufReadVarInt(ifs, buf, varint);  // segwit marker / tx count

      if (varint == 0x00) {
        PrintBufHex("Segwit Marker", varint);
        BufRead(ifs, buf, 1, &tx.segwit_flag, CBRIGHTGREEN);  // segwit_flag
        PrintBufHex("Segwit Flag", (uint16_t)tx.segwit_flag);

        txid.mark(GetBufCurPtr(buf));
        BufReadVarInt(ifs, buf, varint);  // tx count
      }

      txid.glue(GetBufCurPtr(buf));
      txid.mark(GetBufCurPtr(buf));

      tx.in_cnt = varint;
      if (!tx.in_cnt) {
        getchar();
      }
      PrintBufHex("Inputs", tx.in_cnt);
      for (ssize_t ii = 0; ii < tx.in_cnt; ii++) {
        BlockTxIn txin;
        std::cout << std::setw(20) << "    Index: " << ii << std::endl;
        BufRead(ifs, buf, 32, tba, CBRIGHTGREEN);
        binhexle(tba, 32, txin.prev_output.hash);  // prev outout hash
        PrintBufHex("    PrevOutputHash", txin.prev_output.hash);
        BufRead(ifs, buf, 4, &txin.prev_output.index,
                CBRIGHTCYAN);  // prev output index
        PrintBufHex("    PrevOutputIndex", txin.prev_output.index);
        BufReadVarInt(ifs, buf, txin.script_len);  // script length
        PrintBufHex("    ScriptLen", txin.script_len);

        // script
        txin.script = new unsigned char[txin.script_len * 2 + 1];
        txin.script[txin.script_len * 2] = 0;
        BufRead(ifs, buf, txin.script_len, tba, CBRIGHTGREEN);  // script bin
        binhex(tba, txin.script_len, txin.script);              // script hex
        PrintBufHex("    Script", txin.script);
        BufRead(ifs, buf, 4, &txin.seq_no, CBRIGHTCYAN);  // sequence no
        PrintBufHex("    Seq No", txin.seq_no);
      }

      // output transactions
      BufReadVarInt(ifs, buf, tx.out_cnt);  // tx count
      PrintBufHex("Outputs", tx.out_cnt);
      for (ssize_t ii = 0; ii < tx.out_cnt; ii++) {
        BlockTxOut txout;
        std::cout << std::setw(20) << "    Index: " << ii << std::endl;
        BufRead(ifs, buf, 8, &txout.value, CBRIGHTRED);  // tx value
        PrintBufHex("    Value", txout.value);
        BufReadVarInt(ifs, buf, txout.pk_script_len,
                      CBRIGHTCYAN);  // pk script len
        PrintBufHex("    PK Length", txout.pk_script_len);

        // public key script
        txout.pk_script = new unsigned char[txout.pk_script_len * 2 + 1];
        txout.pk_script[txout.pk_script_len * 2] = 0;
        BufRead(ifs, buf, txout.pk_script_len, tba,
                CBRIGHTGREEN);                              // pk script bin
        binhex(tba, txout.pk_script_len, txout.pk_script);  // pk script hex
        PrintBufHex("    PK Script", txout.pk_script);

        Script script;
        script.Parse(tba, txout.pk_script_len);

        Address address;
        GetScriptAddress(&script, &address);

        std::cout << "    Address: " << address.value << std::endl;
      }
      // hash transaction (txid)
      txid.glue(GetBufCurPtr(buf));

      if (tx.segwit_flag) {
        for (size_t j = 0; j < tx.in_cnt; j++) {
          BufReadVarInt(ifs, buf, tx.segwit_count, CBRIGHTCYAN);
          PrintBufHex("    Witness Count", tx.segwit_count);
          for (size_t iii = 0; iii < tx.segwit_count; iii++) {
            SegwitItem witness;
            BufReadVarInt(ifs, buf, witness.len, CBRIGHTBLACK);
            // BufRead(ifs, buf, 1, &witness.len, CBRIGHTCYAN);

            PrintBufHex("        Witness Len", witness.len);
            witness.data = new unsigned char[witness.len + 1];
            BufRead(ifs, buf, witness.len, witness.data, CBRIGHTMAGENTA);
            witness.data[witness.len] = 0;
            binhex(witness.data, witness.len, tba);
            PrintBufHex("        Witness Data", tba);
          }
        }
      }

      txid.mark(GetBufCurPtr(buf));

      BufRead(ifs, buf, 4, &tx.lock_time);  // tx lock time
      PrintBufHex("Lock Time", tx.lock_time);

      // hash transaction data (wtxid)
      wtxid.glue(GetBufCurPtr(buf));
      txid.glue(GetBufCurPtr(buf));

      dsha256(txid.data, txid.len, tba);
      binhexle(tba, 32, txid.hash);
      dsha256(wtxid.data, wtxid.len, tba);
      binhexle(tba, 32, wtxid.hash);

      std::cout << "txid: " << txid.hash << std::endl;
      std::cout << "wtxid: " << wtxid.hash << std::endl;
      std::cout << CBRIGHTYELLOW << "Block Hash: " << hash << CRESET
                << std::endl;
      std::cout << "BlockPosition: " << blockPos << std::endl;
      getchar();

      // if (std::memcmp(txid.hash,
      //                 "35e2f1cc8026134fef7bd92b6f1575aab2c1505bcf50793731b63dda"
      //                 "fdd07a28",
      //                 65) == 0) {
      //   flag = 1;
      //   getchar();
      // }
    }
#ifdef DUMPHEX
    // getchar();
    // std::cout << GetBufHex() << std::endl;
#endif
  }

  delete[] buf;
  delete[] tba;
  auto e = std::chrono::steady_clock::now();
  std::cout
      << "Parse executed in "
      << std::chrono::duration_cast<std::chrono::nanoseconds>(e - b).count()
      << " ns..." << std::endl;
}

std::string BlockFile::ToString() const {
  std::stringstream s;
  std::string Hash(reinterpret_cast<const char *>(hash));
  std::string PrevBlock(reinterpret_cast<const char *>(hashPrevBlock));
  std::string MerkleRoot(reinterpret_cast<const char *>(hashMerkleRoot));
  // s << std::hex;
  s << "Hash: " << hash;
  s << " Ver: " << std::hex << version << std::dec;
  s << " HashPrevBlock: " << PrevBlock.substr(0, 14);
  s << " HashMerkleRoot: " << MerkleRoot.substr(0, 6);
  s << " Time: " << std::hex << time << std::dec << " (" << time << ")";
  s << " Bits: " << std::hex << bits << std::dec << " (" << bits << ")";
  s << " Nonce: " << std::hex << nonce << std::dec << " (" << nonce << ")";
  s << " Txs: " << std::dec << txn_count;

  return s.str();
}

std::string BlockTxOut::ToString() const {
  std::stringstream s;
  s << "Value: " << std::hex << value;
  s << " PK Script Len: " << pk_script_len;
  s << " PK Script: " << pk_script;
  return s.str();
}

std::string BlockTxIn::ToString() const {
  std::stringstream s;
  s << "PrevOutput Hash: " << std::hex << prev_output.hash;
  s << " PrevOutput Index: " << std::hex << prev_output.index;
  s << " PK Script Len: " << script_len;
  s << " PK Script: " << script;
  s << " Seq No: " << seq_no;
  return s.str();
}

std::string BlockTx::ToString() const {
  std::stringstream s;
  s << "Version: " << std::hex << version;
  s << " Hash: " << std::hex << hash;
  // for (const auto& tx : vtx) {
  //     s << "  " << tx->ToString() << "\n";
  // }
  return s.str();
}
