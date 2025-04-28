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

/* FAT12 Constants */
#define SECTOR_SIZE 512
#define DIR_ENTRY_SIZE 32
#define FAT12_ENTRY_SIZE 12
#define ROOT_DIR_SECTOR 19
#define FAT1_SECTOR 1
#define FAT2_SECTOR 10

/* Cluster markers */
#define CLUSTER_FREE 0x000
#define CLUSTER_RESERVED_MIN 0xFF0
#define CLUSTER_RESERVED_MAX 0xFF6
#define CLUSTER_BAD 0xFF7
#define CLUSTER_END_MIN 0xFF8
#define CLUSTER_END_MAX 0xFFF
#define CLUSTER_END CLUSTER_END_MAX

/* Filesystem limits */
#define MAX_FILENAME_LEN 8
#define MAX_EXT_LEN 3
#define MAX_PATH_LEN 256
#define MAX_DIR_ENTRIES 224
#define MAX_COMPONENTS 16

/* File attributes */
#define ATTR_READ_ONLY 0x01
#define ATTR_HIDDEN 0x02
#define ATTR_SYSTEM 0x04
#define ATTR_VOLUME_ID 0x08
#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE 0x20
#define ATTR_LONG_NAME 0x0F

/* Boot Sector structure */
struct BootSector {
    unsigned char jump[3];
    unsigned char oem[8];
    unsigned short bytes_per_sector;
    unsigned char sectors_per_cluster;
    unsigned short reserved_sectors;
    unsigned char fat_count;
    unsigned short root_entries;
    unsigned short total_sectors_16;
    unsigned char media_type;
    unsigned short sectors_per_fat;
    unsigned short sectors_per_track;
    unsigned short head_count;
    unsigned long hidden_sectors;
    unsigned long total_sectors_32;
    unsigned char drive_number;
    unsigned char reserved;
    unsigned char boot_signature;
    unsigned long volume_id;
    unsigned char volume_label[11];
    unsigned char fs_type[8];
    unsigned char boot_code[448];
    unsigned short signature;
};

/* Directory Entry structure */
struct DirEntry {
    unsigned char filename[8];
    unsigned char extension[3];
    unsigned char attributes;
    unsigned char reserved[10];
    unsigned short time;
    unsigned short date;
    unsigned short first_cluster;
    unsigned long file_size;
};

/* Core function declarations in K&R style */
int read_boot_sector();
int list_root_directory();
int copyout();
int copyin();
unsigned short read_fat_entry();
unsigned long get_cluster_location();
int update_fat();
unsigned short find_free_cluster();
int to_83_filename();
int from_83_filename();
void set_dos_time_date();
int create_file();
int delete_file();
int edit_file();
int list_path();
int is_directory_empty();
int find_file();
int resolve_path();
int initialize_directory_cluster();
int find_free_entry();

#endif