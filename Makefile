CC           = gcc
LD           = gcc
CFLAGS       = -Wall -Os -c
LDFLAGS      = -Wall -Os
SUBDIRS      = lib test app
LIBDIR       = lib
TESTDIR      = test
APPDIR		 = app

default: all

yatpama : $(APPDIR)/yatpama_core.o $(APPDIR)/yatpama_hmi.o $(APPDIR)/yatpama_main.o
	@( cd app ; $(MAKE) yatpama )

test_HMAC_SHA256 : $(TESTDIR)/test_hmac_sha256.o
	@( cd test; $(MAKE) test_HMAC_SHA256 )

test_SHA256 : $(TESTDIR)/test_sha256.o
	@( cd test; $(MAKE) test_SHA256 )

test2_AES128 : $(TESTDIR)/test_AES128.o
	@( cd test; $(MAKE) test2_AES128 )

test_AES128 : $(TESTDIR)/test2_AES128.o
	@( cd test; $(MAKE) test_AES128 )

test_dllist : $(TESTDIR)/test_dllist.o
	@( cd test; $(MAKE) test_dllist )

test : test_AES128 test2_AES128 test_SHA256 test_HMAC_SHA256 test_dllist

all : yatpama test

clean :
	@echo "Make clean"
	@for i in $(SUBDIRS) ; do ( cd $$i ; echo "Make clean in $$i" ; $(MAKE) clean ; ) done

delete :
	@echo "Make delete"
	rm -f yatpama test_AES128 test2_AES128 test_SHA256 test_HMAC_SHA256 test_dllist
