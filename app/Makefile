CC           = gcc
LD           = gcc
CFLAGS       = -Wall -Os -c
LDFLAGS      = -Wall -Os -lncurses
LIBDIR		 = ../lib

default : all

yatpama_shared.o : yatpama_shared.c yatpama_shared.h
	@(echo [CC] $@)
	$(CC) $(CFLAGS) -o $@ $<

yatpama_core.o : yatpama_core.c yatpama_core.h yatpama_shared.h $(LIBDIR)/aes.h $(LIBDIR)/crypto.h $(LIBDIR)/hmac_sha256.h $(LIBDIR)/sha256.h $(LIBDIR)/utilities.h $(LIBDIR)/dllist.h
	@(echo [CC] $@)
	$(CC) $(CFLAGS) -o $@ $<

yatpama_hmi.o : yatpama_hmi.c yatpama_hmi.h yatpama_shared.h
	@(echo [CC] $@)
	$(CC) $(CFLAGS) -o $@ $<

yatpama_main.o : yatpama_main.c yatpama_hmi.h yatpama_core.h yatpama_shared.h $(LIBDIR)/aes.h $(LIBDIR)/dllist.h 
	@(echo [CC] $@)
	$(CC) $(CFLAGS) -o $@ $<

yatpama : yatpama_shared.o yatpama_core.o yatpama_hmi.o yatpama_main.o $(LIBDIR)/aes.o $(LIBDIR)/crypto.o $(LIBDIR)/hmac_sha256.o $(LIBDIR)/sha256.o $(LIBDIR)/utilities.o $(LIBDIR)/dllist.o
	@(echo [LD] $@)
	$(LD) $(LDFLAGS) -o $@ $^
	mv yatpama ..

all : yatpama

clean :
	rm -f *.o
