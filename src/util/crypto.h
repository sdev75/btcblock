
#pragma once
#include <iostream>
#include <cstdint>
#include <string>
#include <cstring>

#include "util/misc.h"
#include "sha2.h"
#include "btc/base58.h"
#include "btc/script.h"
#include "btc/segwit_addr.h"
#include "script.h"
#include "ripemd160.h"

inline __attribute__((always_inline)) void dsha256(
    const unsigned char *const data, size_t len, unsigned char *const digest) {
  unsigned char tmp[32];
  static SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(tmp, &ctx);
  sha256_init(&ctx);
  sha256_update(&ctx, tmp, 32);
  sha256_final(digest, &ctx);
}

inline __attribute__((always_inline)) void sha256(
    const unsigned char *const data, size_t len, unsigned char *const digest) {
  static SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(digest, &ctx);
}

// not thread safe function (using shared buffer)
// buf.000 = sha256
// buf.128 = ripe160
// buf.256 = dsha256
inline __attribute__((always_inline)) void get_p2pk_address(
    const unsigned char *const pk, size_t pk_len, unsigned char *const out,
    size_t *out_len) {
  static unsigned char buf[512];
  // static unsigned char hex[512];
  sha256(pk, pk_len, buf);

  // binhex(buf, 32, hex);
  // std::cout << "sha256: " << hex << std::endl;

  buf[128] = 0x00;                    // main net address
  btc_ripemd160(buf, 32, &buf[129]);  // extended ripe 160 hashing

  // binhex(&buf[128], 21, hex);
  // std::cout << "ExRipemd160: " << hex << std::endl;

  dsha256(&buf[128], 21, &buf[256]);  // double sha ExtRipe160

  // binhex(&buf[256], 32, hex);
  // std::cout << "dsha256: " << hex << std::endl;

  std::memcpy(&buf[128 + 21], &buf[256], 4);  // append checksum to ExtRipe160

  // binhex(&buf[128], 25, hex);
  // std::cout << "ExtRipe160 + checksum: " << hex << std::endl;

  btc_base58_encode(out, out_len, &buf[128], 25);
  out[*out_len] = 0;
}

// not thread safe function (using shared buffer)
// buf.000 = sha256
// buf.128 = ripe160
// buf.256 = dsha256
inline __attribute__((always_inline)) void get_p2pkh_address(
    const unsigned char *const pk, size_t pk_len, unsigned char *const out,
    size_t *out_len) {
  static unsigned char buf[512];
  // static unsigned char hex[512];

  // payload (prefix + pkscript) (0x00 == main net prefix)
  buf[128] = 0x00;
  std::memcpy(&buf[129], pk, pk_len);

  // binhex(&buf[128], pk_len + 1, hex);
  // std::cout << "Payload: " << hex << std::endl;

  // sha2 the payload
  dsha256(&buf[128], pk_len + 1, &buf[256]);
  // binhex(&buf[256], 32, hex);
  // std::cout << "Dsha256: " << hex << std::endl;

  // append checksum to payload
  std::memcpy(&buf[128 + 1 + pk_len], &buf[256], 4);
  // binhex(&buf[128], 1 + pk_len + 4, hex);
  // std::cout << "Payload with checksum: " << hex << std::endl;

  // base58 encode
  btc_base58_encode(out, out_len, &buf[128], 1 + pk_len + 4);
  out[*out_len] = 0;
}

// not thread safe function (using shared buffer)
inline __attribute__((always_inline)) void get_p2sh_address(
    const unsigned char *const pk, size_t pk_len, unsigned char *const out,
    size_t *out_len) {
  static unsigned char buf[512];
  // static unsigned char hex[512];

  // payload (prefix + pkscript)
  buf[128] = 0x05;
  std::memcpy(&buf[129], pk, pk_len);

  // binhex(&buf[128], pk_len + 1, hex);
  // std::cout << "Payload: " << hex << std::endl;

  // sha2 the payload
  dsha256(&buf[128], pk_len + 1, &buf[256]);
  // binhex(&buf[256], 32, hex);
  // std::cout << "Dsha256: " << hex << std::endl;

  // append checksum to payload
  std::memcpy(&buf[128 + 1 + pk_len], &buf[256], 4);
  // binhex(&buf[128], 1 + pk_len + 4, hex);
  // std::cout << "Payload with checksum: " << hex << std::endl;

  // base58 encode
  btc_base58_encode(out, out_len, &buf[128], 1 + pk_len + 4);
  out[*out_len] = 0;
}

inline __attribute__((always_inline)) void GetScriptAddress(
    const Script *const script, Address *address) {
  if (script->len == 35 || script->len == 67) {
    // p2pk (Pay-to-Public-Key-Hash)
    if (script->opcodes.size() == 2) {
      if (script->opcodes[1]->opcode == OP_CHECKSIG) {
        address->type = ADDR_P2PK;
        get_p2pk_address(script->opcodes[0]->data, script->opcodes[0]->len,
                         address->value, &address->len);
        // std::cout << "    Address (p2pk): " << address->value << std::endl;
        return;
      }
    }
  } else if (script->len == 25) {
    // p2pkh (Pay-to-Pubkey-Hash)
    if (script->opcodes.size() == 5) {
      if (script->opcodes[0]->opcode == OP_DUP &&
          script->opcodes[1]->opcode == OP_HASH160 &&
          script->opcodes[2]->opcode == 0x14 &&
          script->opcodes[3]->opcode == OP_EQUALVERIFY &&
          script->opcodes[4]->opcode == OP_CHECKSIG) {
        address->type = ADDR_P2PKH;
        get_p2pkh_address(script->opcodes[2]->data, script->opcodes[2]->len,
                          address->value, &address->len);
        // std::cout << "    Address (p2pkh): " << address->value << std::endl;
        return;
      }
    }

  } else if (script->len == 23) {
    // p2sh (Pay-To-Script-Hash)
    if (script->opcodes.size() == 3) {
      if (script->opcodes[0]->opcode == OP_HASH160 &&
          script->opcodes[1]->opcode == 0x14 &&
          script->opcodes[2]->opcode == OP_EQUAL) {
        address->type = ADDR_P2SH;
        get_p2sh_address(script->opcodes[1]->data, script->opcodes[1]->len,
                         address->value, &address->len);
        // std::cout << "    Address (p2sh): " << address->value << std::endl;
        return;
      }
    }
  } else if (script->len == 34) {
    // p2wpkh (Pay-To-Witness-Script-Hash)
    std::cout << "script len is 34";
    std::cout << script->opcodes.size();
    if (script->opcodes.size() == 2) {
      if (script->opcodes[0]->opcode == OP_0 &&
          script->opcodes[1]->opcode == 0x20) {
        address->type = ADDR_P2WPSH;
        // unsigned char tmp[500];

        // binhex(script->opcodes[1]->data, script->opcodes[1]->len, tmp);
        // std::cout << tmp << std::endl;
        segwit_addr_encode((char *)address->value, "bc", 0,
                           script->opcodes[1]->data, script->opcodes[1]->len);
        // std::cout << "    Address : " << address->value << std::endl;
        return;
      }
    }
  } else if (script->len == 22) {
    // P2WPKH (Pay-To-Witness-PubKey-Hash)
    if (script->opcodes.size() == 2) {
      if (script->opcodes[0]->opcode == OP_0 &&
          script->opcodes[1]->opcode == 0x14) {
        address->type = ADDR_P2WPKH;
        // unsigned char tmp[500];
        // binhex(script->opcodes[1]->data, script->opcodes[1]->len, tmp);
        // std::cout << tmp << std::endl;
        segwit_addr_encode((char *)address->value, "bc", 0,
                           script->opcodes[1]->data, script->opcodes[1]->len);
        // std::cout << "    Address : " << address->value << std::endl;
      }
    }
  }
  address->type = ADDR_UNKNOWN;
  std::cout << "Uknown address type..." << std::endl;
  return;
}
