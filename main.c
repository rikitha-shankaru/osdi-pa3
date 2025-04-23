#include "fat12.h"
#include <stdio.h>
#include <string.h>

/*
 * Prints usage instructions
 */
static void print_usage(const char *prog_name) {
    printf("FAT12 Disk Utility\n");
    printf("Usage: %s <disk_image> [command]\n", prog_name);
    printf("Commands:\n");
    printf("  list                 - List root directory contents\n");
    printf("  copyout <src> <dest> - Extract file from disk\n");
    printf("  copyin <src> <dest>  - Insert file into disk\n");
}

int main(int argc, char *argv[]) {
    /* Check minimum arguments */
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    /* Open disk image in read-write mode */
    int fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        perror("Failed to open disk image");
        return 1;
    }

    /* Read and parse boot sector */
    BootSector bs;
    if (read_boot_sector(fd, &bs) != 0) {
        close(fd);
        return 1;
    }

    /* Handle commands */
    if (argc == 2 || strcmp(argv[2], "list") == 0) {
        list_root_directory(fd, &bs);
    }
    else if (strcmp(argv[2], "copyout") == 0 && argc == 5) {
        copyout(fd, &bs, argv[3], argv[4]);
    }
    else if (strcmp(argv[2], "copyin") == 0 && argc == 5) {
        copyin(fd, &bs, argv[3], argv[4]);
    }
    else if (strcmp(argv[2], "mkdir") == 0 && argc == 4) {
        create_file(fd, &bs, argv[3], true);
    }
    else if (strcmp(argv[2], "create") == 0 && argc == 4) {
        create_file(fd, &bs, argv[3], false);
    }
    else if (strcmp(argv[2], "delete") == 0 && argc == 4) {
        delete_file(fd, &bs, argv[3]);
    }
    else if (strcmp(argv[2], "edit") == 0 && argc == 6) {
        uint32_t offset = atoi(argv[4]);
        uint8_t data[256];
        memcpy(data, argv[5], strlen(argv[5]));
        edit_file(fd, &bs, argv[3], offset, data, strlen(argv[5]));
    }
    else if (strcmp(argv[2], "ls") == 0 && argc >= 3) {
        list_path(fd, &bs, argc == 4 ? argv[3] : "/");
    }
    else {
        printf("Invalid command or arguments\n");
        print_usage(argv[0]);
    }

    close(fd);
    return 0;
}