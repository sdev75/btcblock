#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <btc/script.h>
#include <script.h>
#include <util/misc.h>
#include <util/crypto.h>

typedef unsigned char u8;

static const unsigned char *vectors[5][1] = {
    (const u8 *)"4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    (const u8 *)"76a914ef24dd51f6ad50f01f7408ac0b5f2d1f309a1e0c88ac",
    (const u8 *)"4d0200abcd",
    (const u8 *)"4e02000000abcd",
    (const u8 *)"6a4c50000293580002799d82d9e8b9c2cde3538025af88ac9f32f8f4fcb4effedbe13d1101"
    "d7ffa7d32d7475e62b7e61ae4c071bed46ad5cedc46a070314739d4fab1a3c59b48a713bdb"
    "635187a1f9834ec15b"};

static const unsigned char *addresses[6][2] = {
    {(const u8 *)"a914c8ce6872bbfacdeb3b06c99dbaaff6f33d730ba387",
     (const u8 *)"3KznLPXMThVFa7WaAX265R13DXmv3b9y6n"},
    {(const u8 *)"76a91437505bea05f029b7cedf487c5410f007ef9a6f5e88ac",
     (const u8 *)"163URzgwqsnJnnzg2TA5VqCQQbUUJPiGWb"},
    {(const u8 *)"76a9149093f6f3e0e3e9ec486958f08d5407cd5665141388ac",
     (const u8 *)"1EBTZPXGNbNghBYGNGtf5adoVpP1Q9ew8e"},
    {(const u8 *)"0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d62"
                 "2ff8c58d",
     (const u8
          *)"bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"},
    {(const u8 *)"00148476980511f28c6ec81a3f9a90d6b3a21d10bdb7",
     (const u8 *)"bc1qs3mfspg372xxajq687dfp44n5gw3p0dhkymt4l"},

    {(const u8 *)"00149ff4604ab098c5ed7c125a752e3834d0d531f5e7",
     (const u8 *)"bc1qnl6xqj4snrz76lqjtf6juwp56r2nra08xdf8wm"}};

int main(void) {
  size_t itrs = 1;
  unsigned char buf[512];
  Script script;

  std::cout << "Testing script..." << std::endl;
  // for (ssize_t i = 0; i < 5; i++) {
  //   size_t len = strlen((const char *)vectors[i][0]) + 1;
  //   hexbin(vectors[i][0], len, buf);
  //   for (ssize_t j = 0; j < itrs; j++) {
  //     // std::cout << "Vector: " << vectors[i][0] << " len: " << len <<
  //     // std::endl;
  //     script.Parse(buf, len / 2);
  //   }
  //   std::cout << "Done with vector " << i << " with " << itrs
  //             << " iterations..." << std::endl;
  // }

  for (ssize_t i = 0; i < 6; i++) {
    for (ssize_t j = 0; j < itrs; j++) {
      // std::cout << "testing vector " << i << std::endl;
      size_t len = strlen((const char *)addresses[i][0]) + 1;
      hexbin(addresses[i][0], len, buf);

      Script script;
      script.Parse(buf, len / 2);

      Address address;
      GetScriptAddress(&script, &address);

      // std::cout << "Address type: " << (int)address.type << std::endl;
      // std::cout << "Address value: " << address.value << std::endl;
      // std::cout << "Address len: " << address.len << std::endl;

      if (std::memcmp(address.value, addresses[i][1], 34) != 0) {
        std::cout << "Expected: " << addresses[i][1]
                  << " Got: " << address.value << " @ " << j << std::endl;
        return EXIT_FAILURE;
      }
    }
    std::cout << "Done with addresses " << i << " with " << itrs
              << " iterations..." << std::endl;
  }

  return EXIT_SUCCESS;
}
