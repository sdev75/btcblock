
AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS)
AM_CXXFLAGS = $(DEBUG_CXXFLAGS) $(ERROR_CXXFLAGS) 
AM_CPPFLAGS = $(DEBUG_CPPFLAGS) 

bin_PROGRAMS = btcblock

btcblock_SOURCES = \
	util/misc.cpp \
	script.cpp \
	block.cpp \
	main.cpp 

btcblock_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/utils/crypto -I$(builddir)/src 
btcblock_CXXFLAGS = $(AM_CXXFLAGS)
btcblock_LDFLAGS = $(AM_LDFLAGS)
btcblock_LDADD = \
$(top_builddir)/utils/crypto/btc/libbtc.a
