
BINDIR=../bin

# CFLAGS=-g
CFLAGS=-O

default : build.h smcroute

all	: smcroute mcsender

clean	:
	rm -f *.o *.asm build.h smcroute mcsender  

install : 
	mkdir -p ${BINDIR}
	cp smcroute mcsender ${BINDIR}

mcsender:  mcsender.o udpsock.c syslog.c ifvc.o lib.o

smcroute:  smcroute.o mroute-api.o ifvc.o cmdpkt.o ipc.o syslog.o udpsock.o mcgroup.o lib.o 
smcroute.c : build.h version.h 

build.h	:  
	echo '#define BUILD "' `date +%y%m%d` '"' >build.h


