# FAT12 Utility Makefile for MINIX 3.1
CC = cc
CFLAGS = -w -D_MINIX -D_KERNEL
TARGET = fat12util
OBJS = main.o fat12.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

main.o: main.c fat12.h
	$(CC) $(CFLAGS) -c main.c

fat12.o: fat12.c fat12.h
	$(CC) $(CFLAGS) -c fat12.c

clean:
	rm -f $(TARGET) $(OBJS)

test: $(TARGET)
	./$(TARGET) disk.fat list

.PHONY: all clean test