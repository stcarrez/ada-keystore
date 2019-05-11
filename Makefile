NAME=keystoreada

-include Makefile.conf

STATIC_MAKE_ARGS = $(MAKE_ARGS) -XKEYSTORE_LIBRARY_TYPE=static
SHARED_MAKE_ARGS = $(MAKE_ARGS) -XKEYSTORE_LIBRARY_TYPE=relocatable
SHARED_MAKE_ARGS += -XUTILADA_BASE_BUILD=relocatable -XUTIL_LIBRARY_TYPE=relocatable
SHARED_MAKE_ARGS += -XXMLADA_BUILD=relocatable
SHARED_MAKE_ARGS += -XLIBRARY_TYPE=relocatable

include Makefile.defaults

# Build executables for all mains defined by the project.
build-test::	setup
	$(GNATMAKE) $(GPRFLAGS) -p -P$(NAME)_tests $(MAKE_ARGS)

build:: tools

tools:  tools/akt-configs.ads
	$(GNATMAKE) $(GPRFLAGS) -p -P$(NAME)_tools $(MAKE_ARGS)

tools/akt-configs.ads:   Makefile.conf tools/akt-configs.gpb
	gnatprep -DCONFIG_DIR='"$(config_dir)/base"' -DVERSION='"$(VERSION)"' \
		  tools/akt-configs.gpb tools/akt-configs.ads

install::
	mkdir -p $(DESTDIR)$(prefix)
	$(INSTALL) bin/akt $(DESTDIR)$(prefix)/bin/akt
	$(INSTALL) docs/akt.1 $(DESTDIR)$(prefix)/share/man/man1/akt.1

ifeq ($(HAVE_GTK),yes)
build:: gtk

gtk:
	$(GNATMAKE) $(GPRFLAGS) -p -P$(NAME)_gtk $(MAKE_ARGS)

install::
	$(INSTALL) bin/gakt $(DESTDIR)$(prefix)/bin/gakt
	$(INSTALL) docs/akt.1 $(DESTDIR)$(prefix)/share/man/man1/gatk.1
	mkdir -p $(DESTDIR)$(prefix)/share/gatk
	$(INSTALL) gatk.glade $(DESTDIR)$(prefix)/share/gatk/gatk.glade

endif

# Build and run the unit tests
test:	build
	# Apply access constraints to the test key and directory.
	chmod 600 regtests/files/file.key
	chmod 700 regtests/files
	bin/keystore_harness -xml keystore-aunit.xml -config tests.properties

install-samples:
	$(MKDIR) -p $(samplesdir)/samples
	cp -rp $(srcdir)/samples/*.ad[sb] $(samplesdir)/samples/
	cp -p $(srcdir)/samples.gpr $(samplesdir)
	cp -p $(srcdir)/config.gpr $(samplesdir)

$(eval $(call ada_library,$(NAME)))

.PHONY: tools gtk

