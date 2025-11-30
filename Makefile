NAME=keystoreada
VERSION=1.4.2

DIST_DIR=ada-keystore-$(VERSION)
DIST_FILE=ada-keystore-$(VERSION).tar.gz

MAKE_ARGS += -XKEYSTORE_BUILD=$(BUILD)

-include Makefile.conf

HAVE_FUSE?=yes
HAVE_AKT?=yes

STATIC_MAKE_ARGS = $(MAKE_ARGS) -XKEYSTORE_LIBRARY_TYPE=static
SHARED_MAKE_ARGS = $(MAKE_ARGS) -XKEYSTORE_LIBRARY_TYPE=relocatable
SHARED_MAKE_ARGS += -XUTILADA_BASE_BUILD=relocatable -XUTIL_LIBRARY_TYPE=relocatable
SHARED_MAKE_ARGS += -XXMLADA_BUILD=relocatable
SHARED_MAKE_ARGS += -XLIBRARY_TYPE=relocatable

ifeq ($(HAVE_FUSE),yes)
AKT_GPRNAME=akt_fuse.gpr
else
AKT_GPRNAME=akt_nofuse.gpr
endif

include Makefile.defaults

setup::
	echo "HAVE_FUSE=$(HAVE_FUSE)" >> Makefile.conf
	echo "HAVE_AKT=$(HAVE_AKT)" >> Makefile.conf

# Build executables for all mains defined by the project.
build-test::	lib-setup
	cd regtests && $(BUILD_COMMAND) $(GPRFLAGS) $(MAKE_ARGS)

build:: tools

ifeq ($(HAVE_AKT),yes)
tools:  akt/src/akt-configs.ads
ifeq ($(HAVE_ALIRE),yes)
	cd akt && $(BUILD_COMMAND) $(GPRFLAGS) $(MAKE_ARGS) 
else
	cd akt && $(BUILD_COMMAND) $(GPRFLAGS) $(MAKE_ARGS) -P$(AKT_GPRNAME)
endif
else
tools:
endif

akt/src/akt-configs.ads:   akt/src/akt-configs.gpb
	$(GNATPREP) -DPREFIX='"${prefix}"' -DVERSION='"$(VERSION)"' \
		  akt/src/akt-configs.gpb akt/src/akt-configs.ads

ifeq ($(HAVE_AKT),yes)
install:: install-akt

install-akt:: uninstall-akt
ifeq ($(HAVE_ALIRE),yes)
	cd akt && $(ALR) exec -- $(GPRINSTALL) -p -f --prefix=$(DESTDIR)${prefix} $(AKT_GPRNAME)
else
	cd akt && $(GPRINSTALL) -p -f --prefix=$(DESTDIR)${prefix} $(AKT_GPRNAME)
endif

uninstall-akt::
ifeq ($(HAVE_ALIRE),yes)
	-cd akt && $(ALR) exec -- $(GPRINSTALL) --uninstall -q -f --prefix=$(DESTDIR)${prefix} $(AKT_GPRNAME)
else
	-cd akt && $(GPRINSTALL) --uninstall -q -f --prefix=$(DESTDIR)${prefix} $(AKT_GPRNAME)
endif
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

