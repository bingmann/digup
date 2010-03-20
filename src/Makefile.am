# $Id$

AM_CFLAGS = -W -Wall -pedantic -Wno-long-long

bin_PROGRAMS = digup

digup_SOURCES = digup.c \
	rbtree.c rbtree.h \
	digest.c digest.h \
	md5.c md5.h sha1.c sha1.h \
	sha256.c sha256.h sha512.c sha512.h \
	crc32.c crc32.h

dist_man1_MANS = digup.1

if BUILDTESTS

noinst_PROGRAMS = test_rbtree test_digest test_digup

TESTS = test_rbtree test_digest test_digup

test_rbtree_SOURCES = test_rbtree.c \
	rbtree.c rbtree.h

test_rbtree_CFLAGS = -DRBTREE_VERIFY

test_digest_SOURCES = test_digest.c \
	digest.c digest.h \
	md5.c md5.h sha1.c sha1.h \
	sha256.c sha256.h sha512.c sha512.h \
	crc32.c crc32.h

test_digup_SOURCES = test_digup.c \
	rbtree.c rbtree.h \
	digest.c digest.h \
	md5.c md5.h sha1.c sha1.h \
	sha256.c sha256.h sha512.c sha512.h \
	crc32.c crc32.h

test_digup_CFLAGS = -DRBTREE_VERIFY

endif