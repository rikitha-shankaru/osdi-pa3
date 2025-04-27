# FAT12 Utility Makefile for MINIX 3.1
CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = 

SRCS = fat12.c main.c
OBJS = $(SRCS:.c=.o)

TEST_SRCS = test_fat12_core.c
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_BINS = $(TEST_SRCS:.c=)

all: fat12 test_fat12_core

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

fat12: fat12.o main.o
	$(CC) $(LDFLAGS) -o $@ $^

test_fat12_core: test_fat12_core.o fat12.o
	$(CC) $(LDFLAGS) -o $@ $^

test_fat12_core.o: test_fat12_core.c fat12.h
	$(CC) $(CFLAGS) -c $<

fat12.o: fat12.c fat12.h
	$(CC) $(CFLAGS) -c $<

main.o: main.c fat12.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TEST_OBJS) $(TEST_BINS)
	rm -f test.img test_*.txt
	rm -f *.o *.out test_fat12_core fat12

.PHONY: all clean