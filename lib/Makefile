CC           = gcc
LD           = gcc
CFLAGS       = -Wall -Os -c
LDFLAGS      = -Wall -Os

default : all

utilities.o : utilities.c utilities.h
	echo [CC] $@
	$(CC) $(CFLAGS) -o  $@ $<

crypto.o : crypto.c crypto.h
	echo [CC] $@
	$(CC) $(CFLAGS) -o  $@ $<

aes.o : aes.c aes.h
	echo [CC] $@
	$(CC) $(CFLAGS) -o $@ $<

sha256.o : sha256.c sha256.h
	echo [CC] $@
	$(CC) $(CFLAGS) -o $@ $<	

hmac_sha256.o : hmac_sha256.c hmac_sha256.h
	echo [CC] $@
	$(CC) $(CFLAGS) -o $@ $<

all : utilities.o crypto.o aes.o sha256.o hmac_sha256.o

clean :
	rm -f *.o
