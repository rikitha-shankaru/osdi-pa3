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
    printf("Usage: %s <disk_image> [command] [args]\n", prog_name);
    printf("Commands:\n");
    printf("  list                 - List root directory\n");
    printf("  copyout <src> <dest> - Extract file from disk\n");
    printf("  copyin <src> <dest>  - Add file to disk\n");
    printf("  mkdir <path>         - Create directory (extra)\n");
    printf("  rm <path>            - Delete file/dir (extra)\n");
}

/* Main function */
int main(argc, argv)
int argc;
char *argv[];
{
    int fd;
    struct BootSector bs;
    
    /* Check minimum arguments */
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    /* Open disk image in read-write mode for full functionality */
    fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        perror("Failed to open disk image");
        return 1;
    }
    
    /* Read and verify boot sector */
    if (read_boot_sector(fd, &bs) != 0) {
        fprintf(stderr, "Error: Not a valid FAT12 disk image\n");
        close(fd);
        return 1;
    }
    
    /* Handle commands */
    if (argc == 2 || strcmp(argv[2], "list") == 0) {
        if (argc > 3) {
            fprintf(stderr, "Error: Too many arguments for 'list'\n");
            close(fd);
            return 1;
        }
        list_root_directory(fd, &bs);
    }
    else if (strcmp(argv[2], "copyout") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Error: Usage: %s <image> copyout <src> <dest>\n", argv[0]);
            close(fd);
            return 1;
        }
        if (copyout(fd, &bs, argv[3], argv[4]) != 0) {
            fprintf(stderr, "Error: Failed to copy file out\n");
            close(fd);
            return 1;
        }
    }
    else if (strcmp(argv[2], "copyin") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Error: Usage: %s <image> copyin <src> <dest>\n", argv[0]);
            close(fd);
            return 1;
        }
        if (copyin(fd, &bs, argv[3], argv[4]) != 0) {
            fprintf(stderr, "Error: Failed to copy file in\n");
            close(fd);
            return 1;
        }
    }
    else if (strcmp(argv[2], "mkdir") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: Usage: %s <image> mkdir <path>\n", argv[0]);
            close(fd);
            return 1;
        }
        if (create_file(fd, &bs, argv[3], 1) != 0) {
            fprintf(stderr, "Error: Failed to create directory\n");
            close(fd);
            return 1;
        }
    }
    else if (strcmp(argv[2], "rm") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: Usage: %s <image> rm <path>\n", argv[0]);
            close(fd);
            return 1;
        }
        if (delete_file(fd, &bs, argv[3]) != 0) {
            fprintf(stderr, "Error: Failed to delete file\n");
            close(fd);
            return 1;
        }
    }
    else {
        fprintf(stderr, "Error: Invalid command\n");
        print_usage(argv[0]);
        close(fd);
        return 1;
    }
    
    close(fd);
    return 0;
}