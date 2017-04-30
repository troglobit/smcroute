sbin_PROGRAMS		= smcrouted
smcrouted_SOURCES	= smcrouted.c mroute.c mroute.h ifvc.c ifvc.g mcgroup.c mcgroup.h \
			  script.c script.h util.h log.c pidfile.c socket.c socket.h      \
			  timer.c timer.h utimensat.c queue.h
smcrouted_CFLAGS        = -W -Wall -Wextra
smcrouted_CPPFLAGS	= -Wno-deprecated-declarations
smcrouted_LDADD		= -lrt

if USE_LIBCAP
smcrouted_LDADD	       += -lcap
endif

if HAVE_CLIENT
sbin_PROGRAMS	       += smcroutectl
smcrouted_SOURCES      += msg.c msg.h ipc.c ipc.h
smcroutectl_SOURCES	= smcroutectl.c msg.h util.h
smcroutectl_CFLAGS      = -W -Wall -Wextra
endif

if USE_DOTCONF
smcrouted_SOURCES      += conf.c conf.h
endif

