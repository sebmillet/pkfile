# Makefile.am

SUBDIRS = src
ACLOCAL_AMFLAGS = -I admin

dist_doc_DATA=README

EXTRA_DIST=bootstrap

dist-hook:
	rm -rf `find $(distdir) -name .git`

appsdir = $(datadir)/applications

