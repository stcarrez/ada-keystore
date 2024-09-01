NAME=keystoreada
VERSION=1.4.1

DIST_DIR=ada-keystore-$(VERSION)
DIST_FILE=ada-keystore-$(VERSION).tar.gz

MAKE_ARGS += -XKEYSTORE_BUILD=$(BUILD)

-include Makefile.conf

STATIC_MAKE_ARGS = $(MAKE_ARGS) -XKEYSTORE_LIBRARY_TYPE=static
SHARED_MAKE_ARGS = $(MAKE_ARGS) -XKEYSTORE_LIBRARY_TYPE=relocatable
SHARED_MAKE_ARGS += -XUTILADA_BASE_BUILD=relocatable -XUTIL_LIBRARY_TYPE=relocatable
SHARED_MAKE_ARGS += -XXMLADA_BUILD=relocatable
SHARED_MAKE_ARGS += -XLIBRARY_TYPE=relocatable

include Makefile.defaults

# Build executables for all mains defined by the project.
build-test::	lib-setup
	cd regtests && $(BUILD_COMMAND) $(GPRFLAGS) $(MAKE_ARGS) 

build:: tools

tools:  akt/src/akt-configs.ads
	cd akt && $(BUILD_COMMAND) $(GPRFLAGS) $(MAKE_ARGS) 

akt/src/akt-configs.ads:   akt/src/akt-configs.gpb
	gnatprep -DPREFIX='"${prefix}"' -DVERSION='"$(VERSION)"' \
		  akt/src/akt-configs.gpb akt/src/akt-configs.ads

install::
	mkdir -p $(DESTDIR)$(prefix)/bin
	$(INSTALL) bin/akt $(DESTDIR)$(prefix)/bin/akt
	mkdir -p $(DESTDIR)$(prefix)/share/man/man1
	$(INSTALL) man/man1/akt.1 $(DESTDIR)$(prefix)/share/man/man1/akt.1
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
	$(INSTALL) man/man1/akt.1 $(DESTDIR)$(prefix)/share/man/man1/gakt.1
	mkdir -p $(DESTDIR)$(prefix)/share/gakt
	$(INSTALL) gakt.glade $(DESTDIR)$(prefix)/share/gakt/gakt.glade

endif

# Build and run the unit tests
test:	build stamp-test-setup
	bin/keystore_harness -v -l $(NAME): -t 120 -xml keystore-aunit.xml -config tests.properties

stamp-test-setup:
	# Apply access constraints to the test key and directory.
	chmod 600 regtests/files/file.key
	chmod 700 regtests/files
	sh regtests/files/setup-tests.sh > test-setup.log 2>&1
	touch stamp-test-setup

clean::
	rm -f stamp-test-setup tests.log

install-samples:
	$(MKDIR) -p $(samplesdir)/samples
	cp -rp $(srcdir)/samples/*.ad[sb] $(samplesdir)/samples/
	cp -p $(srcdir)/samples.gpr $(samplesdir)
	cp -p $(srcdir)/config.gpr $(samplesdir)

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

DOC_OPTIONS=-f markdown -o keystoreada-book.pdf --listings --number-sections --toc
HTML_OPTIONS=-f markdown -o keystoreada-book.html --listings --number-sections --toc --css pandoc.css

$(eval $(call pandoc_build,keystoreada-book,$(KEYSTORE_DOC),\
	cat docs/Programming.md docs/Keystore.md > docs/Keystore_Programming.md; \
	cat docs/Tool.md docs/akt.md > docs/Keystore_Tool.md; \
	cat docs/Design.md \
	    docs/Keystore_IO_Headers.md \
	    docs/Keystore_Passwords_GPG.md \
	    docs/Keystore_Keys.md \
	    docs/Keystore_Repository_Entries.md \
		docs/Keystore_Repository_Data.md \
        docs/Design_Implementation.md > docs/Keystore_Design.md))

$(eval $(call ada_library,$(NAME),.))
$(eval $(call alire_publish,.,ke/keystoreada,keystoreada-$(VERSION).toml))
$(eval $(call alire_publish,akt,ak/akt,akt-$(VERSION).toml))

.PHONY: tools gtk

