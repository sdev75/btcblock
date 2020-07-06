AM_LDFLAGS = $(LIBTOOL_LDFLAGS)
AM_CXXFLAGS = $(DEBUG_CXXFLAGS) $(ERROR_CXXFLAGS) 
AM_CPPFLAGS = $(DEBUG_CPPFLAGS)

ARFLAGS = crs
noinst_LIBRARIES = libbtc.a
libbtc_a_SOURCES = \
segwit_addr.c \
base58.c \
../ripemd160.c \
../sha2.c

libbtc_a_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/utils/btc -I$(top_srcdir)/utils/crypto
libbtc_a_CXXFLAGS = $(AM_CXXFLAGS)

