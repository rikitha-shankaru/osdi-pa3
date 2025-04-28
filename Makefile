# FAT12 Utility Makefile for MINIX 3.1
CC = cc
CFLAGS = -D_MINIX -D_POSIX_SOURCE -w
LDFLAGS = 

SRCS = fat12.c main.c
OBJS = $(SRCS:.c=.o)

all: fat12

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

fat12: fat12.o main.o
	$(CC) $(LDFLAGS) -o $@ $^

fat12.o: fat12.c fat12.h
	$(CC) $(CFLAGS) -c $<

main.o: main.c fat12.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS)
	rm -f *.o fat12 *.txt

.PHONY: all clean