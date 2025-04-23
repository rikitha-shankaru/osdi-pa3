# FAT12 Utility Makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99
TARGET = fat12util

# Default target
all: $(TARGET)

# Build main executable
$(TARGET): main.c fat12.c fat12.h
	$(CC) $(CFLAGS) -o $@ main.c fat12.c

# Clean build artifacts
clean:
	rm -f $(TARGET)

# Test with sample disk
test: $(TARGET)
	./$(TARGET) disk.fat list

.PHONY: all clean test