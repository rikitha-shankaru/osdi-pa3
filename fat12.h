#ifndef FAT12_H
#define FAT12_H

/* Standard includes for MINIX 3.1 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* Sector constants */
#define SECTOR_SIZE 512        /* Standard FAT12 sector size */
#define DIR_ENTRY_SIZE 32      /* Size of directory entry */
#define FAT12_ENTRY_SIZE 12    /* Bits per FAT entry */

/* FAT locations */
#define FAT1_SECTOR 1          /* First FAT starts at sector 1 */
#define FAT2_SECTOR 10         /* Second FAT starts at sector 10 */
#define ROOT_DIR_SECTOR 19     /* Root directory starts at sector 19 */

/* Cluster status values (12-bit) */
#define CLUSTER_FREE 0x000
#define CLUSTER_RESERVED_MIN 0xFF0
#define CLUSTER_RESERVED_MAX 0xFF6
#define CLUSTER_BAD 0xFF7
#define CLUSTER_END_MIN 0xFF8
#define CLUSTER_END_MAX 0xFFF
#define CLUSTER_END CLUSTER_END_MAX

/* Filesystem limits */
#define MAX_FILENAME_LEN 8     /* 8.3 filename format */
#define MAX_EXT_LEN 3
#define MAX_PATH_LEN 256
#define MAX_DIR_ENTRIES 224    /* Maximum root directory entries */
#define MAX_COMPONENTS 16      /* Maximum path components */

/* File attributes */
#define ATTR_READ_ONLY 0x01
#define ATTR_HIDDEN 0x02
#define ATTR_SYSTEM 0x04
#define ATTR_VOLUME_ID 0x08
#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE 0x20
#define ATTR_LONG_NAME 0x0F

/* Boot Sector structure (all multi-byte fields are little-endian) */
struct BootSector {
    unsigned char jump[3];      /* Boot jump instruction */
    unsigned char oem[8];       /* OEM name/version */
    unsigned short bytes_per_sector;  /* LE */
    unsigned char sectors_per_cluster;
    unsigned short reserved_sectors;  /* LE */
    unsigned char fat_count;
    unsigned short root_entries;      /* LE */
    unsigned short total_sectors_16;  /* LE */
    unsigned char media_type;
    unsigned short sectors_per_fat;   /* LE */
    unsigned short sectors_per_track; /* LE */
    unsigned short head_count;        /* LE */
    unsigned long hidden_sectors;     /* LE */
    unsigned long total_sectors_32;   /* LE */
    unsigned char drive_number;
    unsigned char reserved;
    unsigned char boot_signature;
    unsigned long volume_id;          /* LE */
    unsigned char volume_label[11];
    unsigned char fs_type[8];
    unsigned char boot_code[448];
    unsigned short signature;         /* 0xAA55 LE */
};

/* Directory Entry structure */
struct DirEntry {
    unsigned char filename[8];
    unsigned char extension[3];
    unsigned char attributes;
    unsigned char reserved[10];
    unsigned short time;        /* LE */
    unsigned short date;        /* LE */
    unsigned short first_cluster;  /* LE */
    unsigned long file_size;    /* LE */
};

/* Function declarations */
extern int read_boot_sector();
extern int list_root_directory();
extern int copyout();
extern int copyin();
extern unsigned short read_fat_entry();
extern unsigned long get_cluster_location();
extern int update_fat();
extern unsigned short find_free_cluster();
extern int to_83_filename();
extern int from_83_filename();
extern void set_dos_time_date();
extern int create_file();
extern int delete_file();
extern int edit_file();
extern int list_path();
extern int is_directory_empty();
extern int find_file();
extern int resolve_path();
extern int initialize_directory_cluster();
extern int find_free_entry();

#endif /* FAT12_H */