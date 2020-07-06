#include "misc.h"

#include <iostream>
#include <fstream>
#include <cstdint>
#include <iomanip>

const char *CRESET         = "\x1B[0m";
const char *CRED           = "\x1B[31m";
const char *CGREEN         = "\x1B[32m";
const char *CYELLOW        = "\x1B[33m";
const char *CBLUE          = "\x1B[34m";
const char *CMAGENTA       = "\x1B[35m";
const char *CCYAN          = "\x1B[36m";
const char *CWHITE         = "\x1B[37m";
const char *CBRIGHTBLACK   = "\x1B[90m";
const char *CBRIGHTRED     = "\x1B[91m";
const char *CBRIGHTGREEN   = "\x1B[92m";
const char *CBRIGHTYELLOW  = "\x1B[93m";
const char *CBRIGHTBLUE    = "\x1B[94m";
const char *CBRIGHTMAGENTA = "\x1B[95m";
const char *CBRIGHTCYAN    = "\x1B[96m";
const char *CBRIGHTWHITE   = "\x1B[97m";

ssize_t rb_cur;  // read buf cur
ssize_t hb_cnt;  // hex buf counter
std::stringstream hb_ss;
