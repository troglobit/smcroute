## SMCRoute - A static multicast routing tool             -*-Makefile-*-
ACLOCAL_AMFLAGS           = -I m4
DISTCHECK_CONFIGURE_FLAGS = --with-systemd=$$dc_install_base/$(systemd)

DISTCLEANFILES		= *~ DEADJOE semantic.cache *.gdb *.elf core core.* *.d
dist_man8_MANS		= smcroute.8
doc_DATA		= README.md ChangeLog.md COPYING smcroute.conf
EXTRA_DIST		= README.md AUTHORS ChangeLog.md autogen.sh smcroute.conf smcroute.init
sbin_PROGRAMS		= smcrouted
smcrouted_SOURCES	= smcrouted.c mroute-api.c ifvc.c mcgroup.c script.c util.h log.c \
			  pidfile.c common.c common.h utimensat.c mclab.h queue.h
smcrouted_CFLAGS        = -W -Wall -Wextra
smcrouted_CPPFLAGS	= -Wno-deprecated-declarations
if USE_LIBCAP
smcrouted_LDADD		= -lcap
endif

if HAVE_SYSTEMD
systemd_DATA            = smcroute.service
endif

if HAVE_CLIENT
sbin_PROGRAMS	       += smcroutectl
smcrouted_SOURCES      += msg.c msg.h ipc.c ipc.h
smcroutectl_SOURCES	= smcroutectl.c ipc.c ipc.h common.c common.h msg.h
smcroutectl_CFLAGS      = -W -Wall -Wextra
endif

if USE_DOTCONF
smcrouted_SOURCES      += conf.c conf.h
endif

## Generate detached signature file (ascii-armored), like OpenVPN does
GPG = gpg
gpg-dist:
	for file in $(DIST_ARCHIVES); do 	\
		$(GPG) -ba $$file; 		\
	done

## Generate MD5 checksum file
MD5 = md5sum
md5-dist:
	@for file in $(DIST_ARCHIVES); do	\
		$(MD5) $$file > $$file.md5;	\
	done

## Check if tagged in git
release-hook:
	if [ ! `git tag | grep $(PACKAGE_VERSION)` ]; then				\
		echo;									\
		printf "\e[1m\e[41mCannot find release tag $(PACKAGE_VERSION)\e[0m\n";	\
		printf "\e[1m\e[5mDo release anyway?\e[0m "; read yorn;			\
		if [ "$$yorn" != "y" -a "$$yorn" != "Y" ]; then				\
			printf "OK, aborting release.\n";				\
			exit 1;								\
		fi;									\
		echo;									\
	else										\
		echo;									\
		printf "\e[1m\e[42mFound GIT release tag $(PACKAGE_VERSION)\e[0m\n";	\
		printf "\e[1m\e[44m>>Remember to push tags!\e[0m\n";			\
		echo;									\
	fi

## Target to run when building a release
release: distcheck release-hook md5-dist gpg-dist
	@echo
	@echo "Resulting release files:"
	@echo "================================================================="
	@for file in $(DIST_ARCHIVES); do						\
		printf "$$file    \tDistribution tarball\n";				\
		printf "$$file.md5\t"; cat $$file.md5 | cut -f1 -d' ';			\
		printf "$$file.asc\tGPG signature "; gpg --verify $$file.asc 2>&1	\
			| grep 'key ID' | sed 's/.*using \(.*\)/\1/'; echo;		\
	done
