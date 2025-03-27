CC = gcc
CFLAGS = -g -Wall -O2
LDFLAGS = -lnetfilter_conntrack -lnfnetlink -lmnl -lcrypto

TARGET = conntrack_logger

all: $(TARGET)

$(TARGET): conntrack_logger.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

conntrack_logger.o: conntrack_logger.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
