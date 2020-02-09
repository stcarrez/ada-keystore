NAME=keystoreada

-include Makefile.conf

STATIC_MAKE_ARGS = $(MAKE_ARGS) -XKEYSTORE_LIBRARY_TYPE=static
SHARED_MAKE_ARGS = $(MAKE_ARGS) -XKEYSTORE_LIBRARY_TYPE=relocatable
SHARED_MAKE_ARGS += -XUTILADA_BASE_BUILD=relocatable -XUTIL_LIBRARY_TYPE=relocatable
SHARED_MAKE_ARGS += -XXMLADA_BUILD=relocatable
SHARED_MAKE_ARGS += -XLIBRARY_TYPE=relocatable

ifeq ($(HAVE_FUSE),yes)
FUSE_LIBS := $(shell pkg-config --libs fuse)

export FUSE_LIBS
endif

include Makefile.defaults

# Build executables for all mains defined by the project.
build-test::	setup
	$(GNATMAKE) $(GPRFLAGS) -p -P$(NAME)_tests $(MAKE_ARGS)

build:: tools

tools:  tools/akt-configs.ads
	$(GNATMAKE) $(GPRFLAGS) -p -P$(NAME)_tools $(MAKE_ARGS)

tools/akt-configs.ads:   Makefile.conf tools/akt-configs.gpb
	gnatprep -DPREFIX='"${prefix}"' -DVERSION='"$(VERSION)"' \
		  tools/akt-configs.gpb tools/akt-configs.ads

install::
	mkdir -p $(DESTDIR)$(prefix)/bin
	$(INSTALL) bin/akt $(DESTDIR)$(prefix)/bin/akt
	mkdir -p $(DESTDIR)$(prefix)/share/man/man1
	$(INSTALL) docs/akt.1 $(DESTDIR)$(prefix)/share/man/man1/akt.1
	(cd share && tar --exclude='*~' -cf - .) \
       | (cd $(DESTDIR)$(prefix)/share/ && tar xf -)
	mkdir -p $(DESTDIR)$(prefix)/share/locale/fr/LC_MESSAGES
	$(INSTALL) po/fr.mo $(DESTDIR)$(prefix)/share/locale/fr/LC_MESSAGES/akt.mo

ifeq ($(HAVE_GTK),yes)
build:: gtk

gtk:
	$(GNATMAKE) $(GPRFLAGS) -p -P$(NAME)_gtk $(MAKE_ARGS)

install::
	$(INSTALL) bin/gakt $(DESTDIR)$(prefix)/bin/gakt
	$(INSTALL) docs/akt.1 $(DESTDIR)$(prefix)/share/man/man1/gakt.1
	mkdir -p $(DESTDIR)$(prefix)/share/gakt
	$(INSTALL) gakt.glade $(DESTDIR)$(prefix)/share/gakt/gakt.glade

endif

# Build and run the unit tests
test:	build stamp-test-setup
	bin/keystore_harness -t 120 -xml keystore-aunit.xml -config tests.properties

stamp-test-setup:
	# Apply access constraints to the test key and directory.
	chmod 600 regtests/files/file.key
	chmod 700 regtests/files
	sh regtests/files/setup-tests.sh
	touch stamp-test-setup

clean::
	rm -f stamp-test-setup tests.log

install-samples:
	$(MKDIR) -p $(samplesdir)/samples
	cp -rp $(srcdir)/samples/*.ad[sb] $(samplesdir)/samples/
	cp -p $(srcdir)/samples.gpr $(samplesdir)
	cp -p $(srcdir)/config.gpr $(samplesdir)

ifeq ($(HAVE_PANDOC),yes)
ifeq ($(HAVE_DYNAMO),yes)
doc::  docs/keystore-book.pdf docs/keystore-book.html
	$(DYNAMO) build-doc -markdown wiki

KEYSTORE_DOC= \
  title.md \
  pagebreak.tex \
  index.md \
  pagebreak.tex \
  Installation.md \
  pagebreak.tex \
  Using.md \
  pagebreak.tex \
  Keystore_Programming.md \
  pagebreak.tex \
  Keystore_Tool.md \
  pagebreak.tex \
  Keystore_Design.md

DOC_OPTIONS=-f markdown -o keystore-book.pdf --listings --number-sections --toc
HTML_OPTIONS=-f markdown -o keystore-book.html --listings --number-sections --toc --css pandoc.css

docs/keystore-book.pdf: $(KEYSTORE_DOC_DEP) force
	$(DYNAMO) build-doc -pandoc docs
	cat docs/Programming.md docs/Keystore.md > docs/Keystore_Programming.md
	cat docs/Tool.md docs/akt.md > docs/Keystore_Tool.md
	cat docs/Design.md \
	    docs/Keystore_IO_Headers.md \
	    docs/Keystore_Repository_Entries.md \
		docs/Keystore_Repository_Data.md \
        docs/Design_Implementation.md > docs/Keystore_Design.md
	cd docs && pandoc $(DOC_OPTIONS) --template=./eisvogel.tex $(KEYSTORE_DOC)

docs/keystore-book.html: docs/keystore-book.pdf force
	cd docs && pandoc $(HTML_OPTIONS) $(KEYSTORE_DOC)

endif
endif

$(eval $(call ada_library,$(NAME)))

DIST_DIRS=ada-util
dist::
	rm -f $(DIST_FILE)
	git archive -o $(DIST_DIR).tar --prefix=$(DIST_DIR)/ HEAD
	for i in $(DIST_DIRS); do \
	   cd $$i && git archive -o ../$$i.tar --prefix=$(DIST_DIR)/$$i/ HEAD ; \
           cd .. && tar --concatenate --file=$(DIST_DIR).tar $$i.tar ; \
           rm -f $$i.tar; \
        done
	gzip $(DIST_DIR).tar

.PHONY: tools gtk

