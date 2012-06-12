# Generated automatically from Makefile.in by configure.
# $Id: Makefile.in,v 1.1 2010/05/04 11:20:38 paolo Exp $

prefix=/usr
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
libexecdir=${exec_prefix}/libexec
datadir=${prefix}/share
mandir=${prefix}/share/man
sysconfdir=${prefix}/etc
srcdir=.
top_srcdir=../..
CC=gcc
DEFS= -DPACKAGE=\"pmacctd\" -DVERSION=\"0.12.4-cvs\" -DPROGNAME=1 -DIM_LITTLE_ENDIAN=1 -DHAVE_L2=1 -DHAVE_INET_PTON=1 -DHAVE_INET_NTOP=1 -DENABLE_IPV6=1 -DV4_MAPPED=1 -DHAVE_PCAP_H=1 -DHAVE_LIBPCAP=1 -DPCAP_7=1 -DPCAP_TYPE_linux=1 -DHAVE_DLOPEN=1 -DSTDC_HEADERS=1 -DHAVE_SYS_WAIT_H=1 -DHAVE_GETOPT_H=1 -DHAVE_SYS_SELECT_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_U_INT64_T=1 -DHAVE_U_INT32_T=1 -DHAVE_U_INT16_T=1 -DHAVE_U_INT8_T=1 -DENABLE_THREADS=1 -D_XOPEN_SOURCE=600 -D_GNU_SOURCE=1 -DRETSIGTYPE=void -DHAVE_VSNPRINTF=1 
LDFLAGS=-Wl,--export-dynamic 
CFLAGS=$(DEFS) -I$(srcdir) -I.. -O2 -DENABLE_ULOG 
CPPFLAGS=
LIBS=-lpcap  -ldl -lpthread -lnfprobe_plugin -Lnfprobe_plugin/ -lsfprobe_plugin -Lsfprobe_plugin/ -lbgp -Lbgp/ -ltee_plugin -Ltee_plugin/
INSTALL=/usr/bin/install -c
RANLIB=ranlib 

TARGETS=libtee_plugin.a

all: $(TARGETS)

libtee_plugin.a: tee_plugin.o
	ar rc $@ tee_plugin.o
	$(RANLIB) $@

clean:
	rm -f $(TARGETS) *.o core *.core

realclean: clean
	rm -rf autom4te.cache Makefile config.log config.status

distclean: realclean
	rm -f config.h* configure

strip:
	strip $(TARGETS)

install: all

