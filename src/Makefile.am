AUTOMAKE_OPTIONS        = subdir-objects

sbin_PROGRAMS		= smcrouted
smcrouted_SOURCES	= smcrouted.c mroute.c mroute.h ifvc.c ifvc.h mcgroup.c mcgroup.h  \
			  script.c script.h util.h log.c log.h pidfile.c socket.c socket.h \
			  timer.c timer.h queue.h
smcrouted_CFLAGS        = -W -Wall -Wextra -Wno-deprecated-declarations
smcrouted_CPPFLAGS	= -D_ATFILE_SOURCE -D_INCOMPLETE_XOPEN_C063
smcrouted_CPPFLAGS     += -DSYSCONFDIR=\"@sysconfdir@\" -DLOCALSTATEDIR=\"@localstatedir@\"
smcrouted_LDADD		= $(LIBS) $(LIBOBJS) @LIB_RT@ @LIB_PTHREAD@

if USE_LIBCAP
smcrouted_SOURCES      += cap.c cap.h
smcrouted_LDADD	       += -lcap
endif

if USE_MRDISC
smcrouted_SOURCES      += mrdisc.c mrdisc.h inet.c inet.h
endif

if HAVE_CLIENT
sbin_PROGRAMS	       += smcroutectl
smcrouted_SOURCES      += msg.c msg.h ipc.c ipc.h
smcroutectl_SOURCES	= smcroutectl.c msg.h util.h
smcroutectl_CFLAGS      = -W -Wall -Wextra
smcroutectl_CPPFLAGS    = -DLOCALSTATEDIR=\"@localstatedir@\"
endif

if USE_DOTCONF
smcrouted_SOURCES      += conf.c conf.h
endif

