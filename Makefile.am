## SMCRoute - A static multicast routing tool             -*-Makefile-*-

dist_man8_MANS		= smcroute.8 mcsender.8

doc_DATA		= smcroute.conf README AUTHORS TODO ChangeLog COPYING 
EXTRA_DIST		= autogen.sh smcroute.conf

bin_PROGRAMS		= smcroute mcsender

mcsender_SOURCES	= mcsender.c syslog.c

smcroute_SOURCES	= smcroute.c mroute-api.c ifvc.c cmdpkt.c ipc.c	\
			  mcgroup.c  parse-conf.c syslog.c pidfile.c mclab.h 

DISTCLEANFILES		= *~ DEADJOE semantic.cache *.gdb *.elf core core.* *.d

