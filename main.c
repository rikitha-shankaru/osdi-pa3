#include "fat12.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* Print usage */
static void print_usage(prog_name)
char *prog_name;
{
    printf("FAT12 Disk Utility for MINIX 3.1\n");
    printf("Usage: %s <disk_image> <command> [args...]\n", prog_name);
    printf("Commands:\n");
    printf("  list [path]          - List directory contents\n");
    printf("  copyout <src> <dest> - Extract file from disk\n");
    printf("  copyin <src> <dest>  - Add file to disk\n");
    printf("  mkdir <path>         - Create directory (extra)\n");
    printf("  rm <path>            - Delete file/dir (extra)\n");
    printf("  edit <path> <offset> <size> - Edit file in place (extra)\n");
}

/* Main function */
int main(argc, argv)
int argc;
char *argv[];
{
    int fd;
    struct BootSector bs;
    
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    fd = open(argv[1], O_RDWR);
    if (fd == -1) {
        perror("Error opening disk image");
        return 1;
    }
    
    if (read_boot_sector(fd, &bs) != 0) {
        close(fd);
        return 1;
    }
    
    if (strcmp(argv[2], "list") == 0) {
        if (list_root_directory(fd, &bs) != 0) {
            close(fd);
            return 1;
        }
    }
    else if (strcmp(argv[2], "copyin") == 0) {
        if (argc != 5) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        if (copyin(fd, &bs, argv[3], argv[4]) != 0) {
            close(fd);
            return 1;
        }
    }
    else if (strcmp(argv[2], "copyout") == 0) {
        if (argc != 5) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        if (copyout(fd, &bs, argv[3], argv[4]) != 0) {
            close(fd);
            return 1;
        }
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", argv[2]);
        print_usage(argv[0]);
        close(fd);
        return 1;
    }
    
    close(fd);
    return 0;
}