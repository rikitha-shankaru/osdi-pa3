#ifndef FAT12_H
#define FAT12_H

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>

/* File attribute masks */
#define ATTR_READ_ONLY  0x01
#define ATTR_HIDDEN     0x02
#define ATTR_SYSTEM     0x04
#define ATTR_VOLUME_ID  0x08
#define ATTR_DIRECTORY  0x10
#define ATTR_ARCHIVE    0x20

/* Special cluster values */
#define CLUSTER_FREE    0x000
#define CLUSTER_BAD     0xFF7
#define CLUSTER_END     0xFF8

/* 
 * Boot Sector Structure (512 bytes)
 * - Contains critical disk parameters
 * - #pragma pack ensures no compiler padding between fields
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t  jump[3];          /* x86 jump instruction (usually 0xEB, 0x3C, 0x90) */
    char     oem[8];           /* OEM identifier (e.g., "MSDOS5.0") */
    uint16_t bytes_per_sector; /* Typically 512 (little-endian) */
    uint8_t  sectors_per_cluster; /* Usually 1 for floppies */
    uint16_t reserved_sectors; /* Sectors before first FAT (usually 1) */
    uint8_t  fat_count;        /* Number of FAT copies (usually 2) */
    uint16_t root_entries;     /* Max root directory entries (usually 224) */
    uint16_t total_sectors;    /* Total sectors if < 65535 (little-endian) */
    uint8_t  media_descriptor; /* 0xF0 for removable media */
    uint16_t sectors_per_fat;  /* Sectors occupied by one FAT */
    uint16_t sectors_per_track; /* For physical disk geometry */
    uint16_t head_count;       /* Number of heads */
    uint32_t hidden_sectors;   /* Sectors before partition (usually 0) */
    uint32_t total_sectors_large; /* Used if total_sectors == 0 */
    uint8_t  drive_number;     /* BIOS drive number (0x00 for floppies) */
    uint8_t  reserved;         /* Unused */
    uint8_t  boot_signature;   /* Should be 0x29 for extended boot record */
    uint32_t volume_id;        /* Serial number */
    char     volume_label[11]; /* Disk label (space-padded) */
    char     filesystem_type[8]; /* "FAT12   " (space-padded) */
} BootSector;
#pragma pack(pop)

/*
 * Directory Entry Structure (32 bytes)
 * - Represents one file/subdirectory in root directory
 */
#pragma pack(push, 1)
typedef struct {
    char     filename[8];      /* File name (space-padded) */
    char     extension[3];     /* File extension (space-padded) */
    uint8_t  attributes;       /* File attributes (see below) */
    uint8_t  reserved[10];     /* Unused in FAT12 */
    uint16_t time;             /* Last write time (HH:MM:SS packed) */
    uint16_t date;             /* Last write date (YYYY-MM-DD packed) */
    uint16_t first_cluster;    /* Starting cluster number (little-endian) */
    uint32_t file_size;        /* File size in bytes (little-endian) */
} DirEntry;
#pragma pack(pop)

/* Function prototypes */
int read_boot_sector(int fd, BootSector *bs);
void list_root_directory(int fd, BootSector *bs);
int copyout(int fd, BootSector *bs, const char *fat_filename, const char *host_filename);
int copyin(int fd, BootSector *bs, const char *host_filename, const char *fat_filename);

int create_file(int fd, BootSector *bs, const char *path, bool is_dir);
int delete_file(int fd, BootSector *bs, const char *path);
int edit_file(int fd, BootSector *bs, const char *path, uint32_t offset, uint8_t *data, uint32_t size);
int list_path(int fd, BootSector *bs, const char *path);

/* Helper functions */
uint16_t find_free_cluster(int fd, BootSector *bs);
int update_fat(int fd, BootSector *bs, uint16_t cluster, uint16_t value);
char* to_83_filename(const char *name, char *out);

#endif // FAT12_H

