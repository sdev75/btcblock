#pragma once
#include <iostream>
#include <fstream>
#include <cstdint>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>

#include <iomanip>

extern const char *CRESET;
extern const char *CRED;
extern const char *CGREEN;
extern const char *CYELLOW;
extern const char *CBLUE;
extern const char *CMAGENTA;
extern const char *CCYAN;
extern const char *CWHITE;
extern const char *CBRIGHTBLACK;
extern const char *CBRIGHTRED;
extern const char *CBRIGHTGREEN;
extern const char *CBRIGHTYELLOW;
extern const char *CBRIGHTBLUE;
extern const char *CBRIGHTMAGENTA;
extern const char *CBRIGHTCYAN;
extern const char *CBRIGHTWHITE;

extern ssize_t read_buf_cur;
extern ssize_t rb_cur;  // read buf cur
extern ssize_t hb_cnt;  // hex buf counter
extern std::stringstream hb_ss;

void DumpHex(const unsigned char *const buf, ssize_t size,
             const char *const color);

std::string GetDumpHex();

void ResetDumpHex();

inline ssize_t GetReadBufPos() {
  return read_buf_cur;
}

inline void ReadVar(std::ifstream &ifs, unsigned char *buf, ssize_t size,
                    void *out) {
  ifs.read(reinterpret_cast<char *>(&buf[read_buf_cur]), size);
  std::memcpy(out, &buf[read_buf_cur], size);
  read_buf_cur += size;
}

inline uint8_t ReadVarInt(std::ifstream &ifs, unsigned char *buf,
                          uint64_t &out) {
  out = 0;
  ifs.read(reinterpret_cast<char *>(&buf[read_buf_cur]), 1);
  if (out < 0xFD) {
    std::memcpy(&out, &buf[read_buf_cur], 1);
    read_buf_cur += 1;
    return 1;
  } else if (out < 0xFE) {
    ifs.read(reinterpret_cast<char *>(&buf[read_buf_cur]), 2);
    std::memcpy(&out, &buf[read_buf_cur], 2);
    read_buf_cur += 2;
    return 2;
  } else if (out < 0xFF) {
    ifs.read(reinterpret_cast<char *>(&buf[read_buf_cur]), 4);
    std::memcpy(&out, &buf[read_buf_cur], 4);
    read_buf_cur += 4;
    return 4;
  } else {
    ifs.read(reinterpret_cast<char *>(&buf[read_buf_cur]), 8);
    std::memcpy(&out, &buf[read_buf_cur], 8);
    read_buf_cur += 8;
    return 8;
  }
}

// In is non-null string, len is the actual length, no null terminating char at
// the end. Very simple and raw with and no memset, or any operation on the
// data...
static const char *hextable =
    "000102030405060708090a0b0c0d0e0f"  //  0 ...
    "101112131415161718191a1b1c1d1e1f"  // 16 ...
    "202122232425262728292a2b2c2d2e2f"  // 32 ...
    "303132333435363738393a3b3c3d3e3f"  // 48 ...
    "404142434445464748494a4b4c4d4e4f"  // 64 ...
    "505152535455565758595a5b5c5d5e5f"  // 80 ...
    "606162636465666768696a6b6c6d6e6f"  // 96 ...
    "707172737475767778797a7b7c7d7e7f"  // 112 ...
    "808182838485868788898a8b8c8d8e8f"  // 128 ...
    "909192939495969798999a9b9c9d9e9f"  // 144 ...
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"  // 160 ...
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"  // 176 ...
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"  // 192 ...
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"  // 208 ...
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"  // 224 ...
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"  // 240 ...
    ;
// out must be at least len*2 +1
inline __attribute__((always_inline)) void binhex(const unsigned char *const in,
                                                  uint64_t len,
                                                  unsigned char *const out) {
  for (ssize_t i = 0, j = 0; i < len; j += 2, i++) {
    out[j]     = *(hextable + ((uint32_t)in[i] * 2));
    out[j + 1] = *(hextable + ((uint32_t)in[i] * 2) + 1);
  }
  out[len * 2] = 0;
  // printf("in: %p '%s'\n", in, in);
  // printf("out: %p '%s'\n", out, out);
}

inline __attribute__((always_inline)) void binhexle(
    const unsigned char *const in, ssize_t len, unsigned char *const out) {
  for (ssize_t i = len - 1, j = 0; i >= 0; j += 2, i--) {
    out[j]     = *(hextable + (uint32_t)in[i] * 2);
    out[j + 1] = *(hextable + (uint32_t)in[i] * 2 + 1);
  }
  out[len * 2] = 0;
}

// Converts hex string input such as "f0fa12bc" to binary data
// the function does not check for data validity...
// a - f = x61/x66
// A - F = x41/x46
// 0 - 9 = x30/x39
// out must be at least len/2 +1
inline __attribute__((always_inline)) void hexbin(const unsigned char *const in,
                                                  ssize_t len,
                                                  unsigned char *const out) {
  uint16_t t;
  for (ssize_t i = 0; i < len; i += 2) {
    if (in[i] >= 0x61 && in[i] <= 0x66) {
      t = (10 + (in[i] - 0x61)) * 32;

    } else if (in[i] >= 0x30 && in[i] <= 0x39) {
      t = (in[i] - 0x30) * 32;

    } else if (in[i] >= 0x41 && in[i] <= 0x46) {
      t = (10 + (in[i] - 0x41)) * 32;
    }

    if (in[i + 1] >= 0x61 && in[i + 1] <= 0x66) {
      t = t + 1 + (10 + (in[i + 1] - 0x61)) * 2;

    } else if (in[i + 1] >= 0x30 && in[i + 1] <= 0x39) {
      t = t + 1 + (in[i + 1] - 0x30) * 2;

    } else if (in[i + 1] >= 0x41 && in[i + 1] <= 0x46) {
      t = t + 1 + (10 + (in[i + 1] - 0x41)) * 2;
    }

    out[(i + 2) - (((i + 2) / 2) + 1)] = (unsigned char)(t / 2);
  }
  out[len / 2] = 0;
}

// extern inline void BufRead(std::ifstream &, unsigned char *buf, ssize_t size,
//                            void *const out, const char *color = CRESET);

// extern inline uint8_t BufReadVarInt(std::ifstream &, unsigned char *buf,
// uint64_t &out,
//                              const char *color);

inline __attribute__((always_inline)) void BufReset() {
#ifdef DUMPHEX
  hb_ss.str("");
  hb_cnt = 0;
#endif
  rb_cur = 0;
}

constexpr static __attribute__((always_inline)) const char *resolveColor(
    const char *color = nullptr) {
  if (color == nullptr) {
    return CRESET;
  }

  return color;
}

constexpr static __attribute__((always_inline)) void BuildBufHex(
    ssize_t size, unsigned char *buf, char const *color = nullptr) {
  color = resolveColor(color);
  for (ssize_t i = 0; i < size; i++, hb_cnt += 2) {
    if (hb_cnt > 0 && hb_cnt % 2 == 0) {
      // if (i == 0) {
      //   hb_ss << "|";
      // }
    }
    hb_ss << color;

    if (hb_cnt > 0 && hb_cnt % 32 == 0) {
      // hb_ss << std::endl;
    }

    hb_ss << std::hex << std::setw(2) << std::setfill('0')
          << (uint16_t)(buf[rb_cur + i]);

    if (hb_cnt % 2 == 0 && i != size - 1) {
      hb_ss << " ";
    }
    hb_ss << CRESET;
  }
}

inline __attribute__((always_inline)) void FlushBufHex() {
  std::cout << hb_ss.str() << std::endl;
  hb_ss.str("");
}

template <class T>
inline __attribute__((always_inline)) void PrintBufHex(std::string label,
                                                       T value) {
#ifdef DUMPHEX
  std::cout << std::setw(20) << label << ": " << value << " (" << hb_ss.str()
            << ")" << std::endl;
  hb_ss.str("");
#else
  std::cout << std::setw(20) << label << ": " << value << std::endl;
#endif
}

inline __attribute__((always_inline)) std::string GetBufHex() {
  return hb_ss.str();
}

constexpr static __attribute__((always_inline)) bool isVarInt(
    const uint64_t size) {
  return size == 0;
}

inline __attribute__((always_inline)) void BufRead(std::ifstream &ifs,
                                                   unsigned char *buf,
                                                   ssize_t size,
                                                   void *const out,
                                                   const char *color = CRESET) {
  ifs.read(reinterpret_cast<char *>(&buf[rb_cur]), size);
  std::memcpy(out, &buf[rb_cur], size);
#ifdef DUMPHEX
  BuildBufHex(size, buf, color);
#endif
  rb_cur += size;
}

// ref: https://en.bitcoin.it/wiki/Protocol_documentation
inline __attribute__((always_inline)) uint8_t BufReadVarInt(
    std::ifstream &ifs, unsigned char *buf, uint64_t &out,
    const char *color = CBRIGHTCYAN) {
  ifs.read(reinterpret_cast<char *>(&buf[rb_cur]), 1);
#ifdef DUMPHEX
  BuildBufHex(1, buf, CBRIGHTBLACK);
#endif
  out = 0;
  std::memcpy(&out, &buf[rb_cur], 1);

  if (out == 0xFD) {
    out = 0;
    ifs.read(reinterpret_cast<char *>(&buf[rb_cur]), 2);
    std::memcpy(&out, &buf[rb_cur], 2);
#ifdef DUMPHEX
    BuildBufHex(2, buf, color);
#endif
    rb_cur += 2;
    return 2;

  } else if (out == 0xFE) {
    ifs.read(reinterpret_cast<char *>(&buf[rb_cur]), 4);
    out = 0;
    std::memcpy(&out, &buf[rb_cur], 4);
#ifdef DUMPHEX
    BuildBufHex(4, buf, color);
#endif
    rb_cur += 4;
    return 4;

  } else if (out == 0xFF) {
    ifs.read(reinterpret_cast<char *>(&buf[rb_cur]), 8);
    out = 0;
    std::memcpy(&out, &buf[rb_cur], 8);
#ifdef DUMPHEX
    BuildBufHex(8, buf, color);
#endif
    rb_cur += 8;
    return 8;
  } else {
    std::memcpy(&out, &buf[rb_cur], 1);
    rb_cur += 1;
    return 1;
  }
}

inline __attribute__((always_inline)) ssize_t GetBufCur() {
  return rb_cur;
}

inline __attribute__((always_inline)) unsigned char *GetBufCurPtr(
    unsigned char *buf) {
  return &buf[rb_cur];
}
