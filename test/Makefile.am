AM_LDFLAGS = $(LIBTOOL_LDFLAGS)
AM_CXXFLAGS = $(DEBUG_CXXFLAGS) $(ERROR_CXXFLAGS) 
AM_CPPFLAGS = $(DEBUG_CPPFLAGS) 

noinst_PROGRAMS = tests
tests_SOURCES = test_script.cpp $(top_srcdir)/src/script.cpp
tests_CPPFLAGS = -I$(top_srcdir)/utils/crypto -I$(top_srcdir)/src
tests_LDFLAGS = $(AM_LDFLAGS)
tests_LDADD = $(top_builddir)/utils/crypto/btc/libbtc.a
tests_DEPENDENCIES = $(top_builddir)/utils/crypto/btc/libbtc.a
TESTS = tests
