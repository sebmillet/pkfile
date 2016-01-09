# src/Makefile.am

SUFFIXES = .c .h

AM_CFLAGS = @CFLAGS@ -Wshadow -Wall -I$(srcdir)
AM_LDFLAGS = @LDFLAGS@

bin_PROGRAMS = pkfile

pkfile_SOURCES = common.h main.c pkfile.h pkfile.c
pkfile_LDFLAGS = 

if WITH_OPENSSL
pkfile_LDFLAGS += -lssl -lcrypto
pkfile_SOURCES += ppem.h ppem.c
endif

