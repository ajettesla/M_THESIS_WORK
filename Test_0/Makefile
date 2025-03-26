CC = gcc
CFLAGS = -Wall -Wextra -pedantic -O2 $(shell pkg-config --cflags libnetfilter_conntrack)
LDFLAGS = $(shell pkg-config --libs libnetfilter_conntrack) -lmnl

all: conntrack_view

conntrack_view: conntrack_view.o
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o conntrack_view

.PHONY: all clean

