CC           = gcc
LD           = gcc
CFLAGS       = -Wall -Os -c
LDFLAGS      = -Wall -Os
SUBDIRS      = lib test
LIBDIR       = lib
TESTDIR      = test

default: all

yatpama.o : yatpama.c $(LIBDIR)/aes.h $(LIBDIR)/crypto.h $(LIBDIR)/hmac_sha256.h $(LIBDIR)/sha256.h $(LIBDIR)/utilities.h
	echo [CC] $@
	$(CC) $(CFLAGS) -o $@ $<

yatpama : yatpama.o $(LIBDIR)/aes.o $(LIBDIR)/crypto.o $(LIBDIR)/hmac_sha256.o $(LIBDIR)/sha256.o $(LIBDIR)/utilities.o
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^

test_HMAC_SHA256 : $(TESTDIR)/test_hmac_sha256.o
	@( cd test; $(MAKE) test_HMAC_SHA256 )

test_SHA256 : $(TESTDIR)/test_sha256.o
	@( cd test; $(MAKE) test_SHA256 )

test2_AES128 : $(TESTDIR)/test_AES128.o
	@( cd test; $(MAKE) test2_AES128 )

test_AES128 : $(TESTDIR)/test2_AES128.o
	@( cd test; $(MAKE) test_AES128 )

test : test_AES128 test2_AES128 test_SHA256 test_HMAC_SHA256

all : yatpama test

clean :
	@echo "Make clean"
	-rm -f *.o
	@for i in $(SUBDIRS) ; do ( cd $$i ; echo "Make clean in $$i" ; $(MAKE) clean ; ) done

delete :
	@echo "Make delete"
	rm -f yatpama test_AES128 test2_AES128 test_SHA256 test_HMAC_SHA256
