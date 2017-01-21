CC= gcc

CFLAGS= -O3 -ggdb -Wall
CPPFLAGS=
LDFLAGS= -lpq -lssl

BINARY= tcpaste
SOURCES= tcpaste.c logging.c pastebin.c
INCLUDES= array.h config.h logging.h pastebin.h

tcpaste: $(SOURCES) $(INCLUDES)
	$(CC) -o $(BINARY) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(SOURCES)

stop:
	killall tcpaste

start:
	bash -c './$(BINARY) &disown'
