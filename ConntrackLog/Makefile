CC = gcc
CFLAGS = -g -Wall -O2
LDFLAGS = -lnetfilter_conntrack -lnfnetlink -lmnl -lcrypto

TARGET = conntrack

all: $(TARGET)

$(TARGET): conntrack.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

conntrack.o: conntrack.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
