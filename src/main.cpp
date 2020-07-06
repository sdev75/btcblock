#include <iostream>
#include <cstdint>
#include <cstring>

#include "block.h"

// clear; make -s && valgrind -s --gen-suppressions=yes --track-origins=yes
// --leak-check=full --show-leak-kinds=all ./src/btcblock -d
// ~/.bitcoin/blocks;

using namespace std;

struct Config {
  std::string blocksDir;
  uint8_t blockNum{0};
  uint64_t blockPos{0};
};

int main(int argc, char **argv) {
  Config cfg;
  for (uint8_t i = 1; i < argc; i++) {
    if (strncmp(argv[i], "-d", 2) == 0 && i + 1 < argc) {
      cfg.blocksDir.assign(argv[++i]);
    } else if (strncmp(argv[i], "-b", 2) == 0 && i + 1 < argc) {
      cfg.blockNum = (uint8_t)atoi(argv[++i]);
    } else if (strncmp(argv[i], "-p", 2) == 0 && i + 1 < argc) {
      cfg.blockPos = strtoull(argv[++i], NULL, 10);
    } else {
      cerr << "Unknown option: [" << argv[i] << "]" << endl;
      exit(EXIT_FAILURE);
    }
  }

  try {
    BlockFile block(cfg.blocksDir, cfg.blockNum);
    block.Parse();
  } catch (const std::exception &e) {
    cerr << "Exception: " << e.what() << endl;
  }

  return EXIT_SUCCESS;
}
