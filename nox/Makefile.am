AUTOMAKE_OPTIONS = foreign 1.10
ACLOCAL_AMFLAGS = -I config

SUBDIRS = src $(subdirs) doc
EXTRA_DIST = \
	man

dist-local:
	cd doc/manual && make clean

nox_installsubdir = $(DESTDIR)$(subst src,$(bindir),$(subdir))
install-exec-hook:
	(cd $(DESTDIR)$(bindir) && $(PYTHON) -c "import compileall; compileall.compile_dir('.', force=True)") 
