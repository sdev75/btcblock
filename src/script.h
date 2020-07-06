#pragma once
#include <iostream>
#include <memory>
#include <vector>

#include "btc/script.h"

enum {
  ADDR_UNKNOWN = 0x0,
  ADDR_P2PK    = 0x1,
  ADDR_P2PKH   = 0x2,
  ADDR_P2SH    = 0x3,
  ADDR_P2WPKH  = 0x4,
  ADDR_P2WPSH  = 0x5,
};

struct Address {
  size_t len;
  unsigned char value[50];
  uint8_t type{ADDR_UNKNOWN};
};

struct ScriptOpcode {
  enum opcodetype opcode { OP_0 };
  unsigned char *data{nullptr};
  size_t len{0};
  ~ScriptOpcode();
};

struct Script {
  size_t len{0};
  std::vector<ScriptOpcode *> opcodes;
  void Parse(const unsigned char *const data, size_t len);
  ~Script();
};
