CC           = gcc
LD           = gcc
CFLAGS       = -Wall -Os -c
LDFLAGS      = -Wall -Os
LIBDIR		 = ../lib

default: all

test_AES128.o : test_AES128.c $(LIBDIR)/aes.h
	echo [CC] $@
	$(CC) $(CFLAGS) -o  $@ $<

test_AES128 : test_AES128.o $(LIBDIR)/aes.o
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^
	mv test_AES128 ..

test2_AES128.o : test2_AES128.c $(LIBDIR)/crypto.h $(LIBDIR)/aes.h $(LIBDIR)/utilities.h
	echo [CC] $@
	$(CC) $(CFLAGS) -o  $@ $<

test2_AES128 : test2_AES128.o $(LIBDIR)/crypto.o $(LIBDIR)/aes.o $(LIBDIR)/utilities.o
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^
	mv test2_AES128 ..

test_sha256.o : test_sha256.c $(LIBDIR)/sha256.h
	echo [CC] $@
	$(CC) $(CFLAGS) -o $@ $<

test_SHA256 : test_sha256.o $(LIBDIR)/sha256.o
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^
	mv test_SHA256 ..

test_hmac_sha256.o : test_hmac_sha256.c $(LIBDIR)/hmac_sha256.h
	echo [CC] $@
	$(CC) $(CFLAGS) -o $@ $<

test_HMAC_SHA256 : test_hmac_sha256.o $(LIBDIR)/hmac_sha256.o $(LIBDIR)/sha256.c
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^
	mv test_HMAC_SHA256 ..

test_dllist.o : test_dllist.c $(LIBDIR)/dllist.h $(LIBDIR)/dllist.c
	echo [CC] $@
	$(CC) $(CFLAGS) -o $@ $<

test_dllist : test_dllist.o $(LIBDIR)/dllist.o
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^
	mv test_dllist ..

all : test_AES128 test2_AES128 test_SHA256 test_HMAC_SHA256 test_dllist

clean :
	rm -f *.o

