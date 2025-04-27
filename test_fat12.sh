#!/bin/bash

# Check for required commands
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo "Error: $1 is required but not installed."
        echo "Please install it using your package manager:"
        echo "  - For Ubuntu/Debian: sudo apt-get install dosfstools"
        echo "  - For Fedora: sudo dnf install dosfstools"
        echo "  - For Arch Linux: sudo pacman -S dosfstools"
        exit 1
    fi
}

# Check for required commands
check_command mkfs.fat
check_command dd

# Rebuild the project
echo "Rebuilding project..."
make clean
make

# Create a fresh FAT12 disk image
echo "Creating FAT12 disk image..."
dd if=/dev/zero bs=512 count=2880 of=test.fat
mkfs.msdos -F 12 test.fat

# Test 1: List empty disk (tests disk access and boot sector parsing)
echo -e "\nTest 1: List empty disk (tests disk access and boot sector parsing)"
./fat12 test.fat list

# Test 2: Create and list multiple files (tests file copy in and directory listing)
echo -e "\nTest 2: Create and list multiple files"
echo "Hello FAT12!" > test1.txt
echo "Another test file" > test2.txt
./fat12 test.fat copyin test1.txt TEST1.TXT
./fat12 test.fat copyin test2.txt TEST2.TXT
./fat12 test.fat list

# Test 3: Copy files out (tests file copy out)
echo -e "\nTest 3: Copy files out"
./fat12 test.fat copyout TEST1.TXT output1.txt
./fat12 test.fat copyout TEST2.TXT output2.txt
echo "Contents of TEST1.TXT:"
cat output1.txt
echo -e "\nContents of TEST2.TXT:"
cat output2.txt

# Test 4: Verify file contents
echo -e "\nTest 4: Verify file contents"
if diff test1.txt output1.txt > /dev/null; then
    echo "TEST1.TXT: Files match ✓"
else
    echo "TEST1.TXT: Files differ ✗"
    exit 1
fi

if diff test2.txt output2.txt > /dev/null; then
    echo "TEST2.TXT: Files match ✓"
else
    echo "TEST2.TXT: Files differ ✗"
    exit 1
fi

# Cleanup
rm -f test1.txt test2.txt output1.txt output2.txt

echo -e "\nAll core functionality tests completed successfully!" 