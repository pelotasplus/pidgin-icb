LOCALBASE?=	/usr/local
PREFIX?=	${LOCALBASE}
CTAGSCMD?=	ectags

CFLAGS+=`pkg-config pidgin --cflags` \
	-I${LOCALBASE}/include \
	-fPIC \
	-Wall
DATE=	`grep ICB_VERSION icb.h | awk '{print $$3}' | sed -e 's/"//g'`

.c.o:
	$(CC) -c $< $(CFLAGS)

OBJS=	icb.o

all: ${OBJS}
	$(CC) -shared -fPIC -o libicb.so ${OBJS}

tags:
	${CTAGSCMD} -R .
	${CTAGSCMD} -R ${LOCALBASE}/include/libpurple

clean:
	rm -f ${OBJS} libicb.so pidgin-icb-*

install:
	install -d -o root -g wheel ${PREFIX}/lib/purple-2/
	install -o root -g wheel libicb.so ${PREFIX}/lib/purple-2/
	for i in 16 22 48; do \
		install -d -o root -g wheel ${DESTDIR}${LOCALBASE}/share/pixmaps/pidgin/protocols/$$i/; \
		install -o root -g wheel icb_$$i.png \
			${DESTDIR}${LOCALBASE}/share/pixmaps/pidgin/protocols/$$i/icb.png; \
	done

dist: clean
	rm -f pidgin-icb-${DATE}.tar.gz
	rm -rf pidgin-icb-${DATE}
	mkdir pidgin-icb-${DATE}
	cp README* icb.[ch] icb_*.png Makefile* pidgin-icb-${DATE}
	tar zcvf pidgin-icb-${DATE}.tar.gz pidgin-icb-${DATE}
	rm -rf pidgin-icb-${DATE}
