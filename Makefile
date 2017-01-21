CC= gcc

CFLAGS= -O3 -ggdb -Wall -Wno-overflow
CPPFLAGS=
LDFLAGS= -lpq -lssl -lmagic

BINARY= tcpaste
SOURCES= tcpaste.c logging.c pastebin.c
INCLUDES= array.h config.h logging.h pastebin.h extensions.h

tcpaste: $(SOURCES) $(INCLUDES)
	$(CC) -o $(BINARY) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(SOURCES)

stop:
	killall tcpaste

start:
	bash -c './$(BINARY) &disown'
