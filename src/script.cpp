
#include "script.h"
#include "util/crypto.h"
#include <cstring>

ScriptOpcode::~ScriptOpcode() {
  if (data != nullptr) {
    delete[] data;
  }
}

Script::~Script() {
  for (ScriptOpcode *obj : opcodes) {
    delete obj;
  }
  opcodes.clear();
}

void Script::Parse(const unsigned char *const data, size_t len) {
  const unsigned char *c = data;

  this->len = len;

  // unsigned char tmp[512];

  // if (*(uint8_t *)c == 0) {
  //   return;
  // }

  while (len > 0) {
    ScriptOpcode *op = new ScriptOpcode();
    op->opcode       = (enum opcodetype) * (uint8_t *)c;
    if (op->opcode < OP_PUSHDATA1) {
      // The next opcode bytes is data to be pushed onto the stack

      op->len = *(uint8_t *)c;
      if (op->len) {
        op->data          = new unsigned char[op->len + 1];
        op->data[op->len] = 0;
        std::memcpy(op->data, &c[1], op->len);
      }

      opcodes.push_back(op);
      len -= op->len + 1;
      c += op->len + 1;

      // binhex(op->data, op->len, tmp);
      // printf("PUSHDATA0: %x, len: %d, data: %s\n", op->opcode, op->len, tmp);
      continue;
    }

    if (op->opcode == OP_PUSHDATA1) {
      // The next byte contains the number of bytes to be pushed onto the stack

      op->len           = *(uint8_t *)&c[1];
      op->data          = new unsigned char[op->len + 1];
      op->data[op->len] = 0;
      std::memcpy(op->data, &c[2], op->len);
      opcodes.push_back(op);
      len -= op->len + 2;
      c += op->len + 2;

      // binhex(op->data, op->len, tmp);
      // printf("PUSHDATA1: %x, len: %d, data: %s\n", op->opcode, op->len, tmp);
      continue;
    }

    if (op->opcode == OP_PUSHDATA2) {
      // The next two bytes contain the number of bytes to be pushed onto the
      // stack in little endian order.printf("PUSHDATA2 %x\n", op->opcode);
      op->len           = *(uint16_t *)&c[1];
      op->data          = new unsigned char[op->len + 1];
      op->data[op->len] = 0;
      std::memcpy(op->data, &c[3], op->len);
      opcodes.push_back(op);
      len -= op->len + 3;
      c += op->len + 3;

      // binhex(op->data, op->len, tmp);
      // printf("PUSHDATA2: %x, len: %x, data: %s\n", op->opcode, op->len, tmp);
      continue;
    }

    if (op->opcode == OP_PUSHDATA4) {
      // The next two bytes contain the number of bytes to be pushed onto the
      // stack in little endian order.printf("PUSHDATA2 %x\n", op->opcode);
      op->len           = *(uint32_t *)&c[1];
      op->data          = new unsigned char[op->len + 1];
      op->data[op->len] = 0;
      std::memcpy(op->data, &c[5], op->len);
      opcodes.push_back(op);
      len -= op->len + 5;
      c += op->len + 5;

      // binhex(op->data, op->len, tmp);
      // printf("PUSHDATA2: %x, len: %x, data: %s\n", op->opcode, op->len, tmp);
      continue;
    }

    op->len  = 0;
    op->data = nullptr;
    opcodes.push_back(op);

    // printf("PUSHDATA: %x\n", op->opcode);
    len -= 1;
    c += 1;
  }
}
