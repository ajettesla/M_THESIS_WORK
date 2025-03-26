CC = gcc
CFLAGS = -Wall -O3 $(shell pkg-config --cflags libnetfilter_conntrack)
LDFLAGS = $(shell pkg-config --libs libnetfilter_conntrack) -lncurses -lssl -lcrypto

all: conntrack_watch

conntrack_watch: conntrack_watch.o
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o conntrack_watch

.PHONY: all clean

