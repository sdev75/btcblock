
AM_LDFLAGS = $(LIBTOOL_LDFLAGS)
AM_CXXFLAGS = $(DEBUG_CXXFLAGS) $(ERROR_CXXFLAGS) 
AM_CPPFLAGS = $(DEBUG_CPPFLAGS)

ARFLAGS = crs
noinst_LIBRARIES = libsha2.a libripemd160.a
libsha2_a_SOURCES = sha2.c
libsha2_a_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/utils
libsha2_a_CXXFLAGS = $(AM_CXXFLAGS)

libripemd160_a_SOURCES = ripemd160.c
libripemd160_a_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/utils
libripemd160_a_CXXFLAGS = $(AM_CXXFLAGS)
