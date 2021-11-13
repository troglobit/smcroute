## SMCRoute - A static multicast routing tool             -*-Makefile-*-
ACLOCAL_AMFLAGS         = -I m4
TAG                     = $(top_srcdir)/.git/refs/tags/$(PACKAGE_VERSION)
DISTCLEANFILES		= *~ DEADJOE semantic.cache *.gdb *.elf core core.* *.d
dist_sbin_SCRIPTS       = smcroute
doc_DATA		= README.md COPYING smcroute.conf
EXTRA_DIST		= README.md ChangeLog.md autogen.sh smcroute.conf smcroute.default smcroute.init
SUBDIRS                 = man src

if ENABLE_TEST
SUBDIRS                += test
endif

if HAVE_SYSTEMD
systemd_DATA            = smcroute.service
endif

## Check if tagged in git
$(TAG):
	@printf "\e[1m\e[41mPlease create the \"$(PACKAGE_VERSION)\" tag first\e[0m\n"
	@exit 1

## Target to run when building a release
release: $(TAG) distcheck
	@for file in $(DIST_ARCHIVES); do		\
		md5sum    $$file > ../$$file.md5;	\
		sha256sum $$file > ../$$file.sha256;	\
	done
	@mv $(DIST_ARCHIVES) ../
	@echo
	@echo "Resulting release files ======================================================================="
	@for file in $(DIST_ARCHIVES); do						\
		printf "%-30s Distribution tarball\n" $$file;				\
		printf "%-30s " $$file.md5;    cat ../$$file.md5    | cut -f1 -d' ';	\
		printf "%-30s " $$file.sha256; cat ../$$file.sha256 | cut -f1 -d' ';	\
	done

# Workaround for systemd unit file duing distcheck
DISTCHECK_CONFIGURE_FLAGS = --with-systemd=$$dc_install_base/$(systemd) --enable-mrdisc --enable-test
