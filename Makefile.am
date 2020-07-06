
# Pattern rule to print variables, e.g. make print-top_srcdir
print-%:
	@echo $* = $($*)

ACLOCAL_AMFLAGS = -I .build-m4
SUBDIRS = src

BTCBLOCK_BIN=$(top_builddir)/src/$(PACKAGE_NAME)$(EXEEXT)

$(BTCBLOCK_BIN): FORCE
	$(MAKE) -C src $(@F)

.PHONY: FORCE
