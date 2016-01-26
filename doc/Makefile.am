# doc/Makefile.am

MANPAGEEN=${srcdir}/pkfile.1
HTMLPAGEEN=${srcdir}/pkfile.html
TEXTPAGEEN=${srcdir}/pkfile.txt

dist_doc_DATA=${HTMLPAGEEN} ${TEXTPAGEEN}

EXTRA_DIST=${HTMLPAGEEN}

dist_man_MANS=${MANPAGEEN}

if BUILD_DOCS

${HTMLPAGEEN}: ${MANPAGEEN}
	man2html ${MANPAGEEN} > $@
${TEXTPAGEEN}: ${MANPAGEEN}
	nroff -man ${MANPAGEEN} | col -b > $@

endif

