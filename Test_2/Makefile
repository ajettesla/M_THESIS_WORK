CC := gcc
CFLAGS := -Wall -Wextra -pedantic -fstack-protector
LDFLAGS := -lnetfilter_conntrack -lmnl -lnfnetlink

TARGET := conntrack_dump
SRC := conntrack_dump.c
OBJ := $(SRC:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)

