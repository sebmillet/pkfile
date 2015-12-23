# src/Makefile

# pkfile Makefile for Linux

# Sébastien Millet, December 2015

# FORTIFYFLAGS = -Wunreachable-code -Wformat=2 \
#     -D_FORTIFY_SOURCE=2 -fstack-protector --param ssp-buffer-size=4 \
#     -fPIE -pie -Wl,-z,relro,-z,now
CPP = gcc
CPPFLAGS = -g -O2 -Wall -Wextra -Wuninitialized $(FORTIFYFLAGS)
LINKERFLAGS = -g -O2 -Wall -Wextra -Wuninitialized $(FORTIFYFLAGS)
OFLAG = -o

.SUFFIXES : .o .c .h
.c.o :
	$(CPP) $(FORTIFYFLAGS) $(CPPFLAGS) -c $<

all : pkfile

pkfile : pkfile.o main.o
	$(CPP) $(LINKERFLAGS) $(OFLAG)$@ pkfile.o main.o

.PHONY: all clean mrproper

mrproper : clean

clean :
	rm -f *.o
	rm -f pkfile

