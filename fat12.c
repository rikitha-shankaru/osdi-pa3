#include "fat12.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* Debug flag */
#define DEBUG 1

/* K&R compatible debug print */
#ifdef DEBUG
#define DEBUG_PRINT(msg) fprintf(stderr, "DEBUG: %s\n", msg)
#define DEBUG_PRINT2(msg, arg) fprintf(stderr, "DEBUG: %s %d\n", msg, arg)
#define DEBUG_PRINT3(msg, arg1, arg2) fprintf(stderr, "DEBUG: %s %d %d\n", msg, arg1, arg2)
#else
#define DEBUG_PRINT(msg)
#define DEBUG_PRINT2(msg, arg)
#define DEBUG_PRINT3(msg, arg1, arg2)
#endif

/* Forward declarations in K&R style */
static unsigned short le16_to_cpu();
static unsigned long le32_to_cpu();
static unsigned short cpu_to_le16();
static unsigned long cpu_to_le32();
static int fat_strcasecmp();
static int compare_dir_entry();
unsigned short read_fat_entry();
unsigned long get_cluster_location();
int update_fat();
unsigned short find_free_cluster();
void set_dos_time_date();

/* Helper: Convert little-endian 16-bit value to host byte order */
static unsigned short le16_to_cpu(val)
unsigned short val;
{
    unsigned char *p;
    p = (unsigned char *)&val;
    return p[0] | (p[1] << 8);
}

/* Helper: Convert little-endian 32-bit value to host byte order */
static unsigned long le32_to_cpu(val)
unsigned long val;
{
    unsigned char *p;
    p = (unsigned char *)&val;
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

/* Helper: Convert host byte order to little-endian 16-bit value */
static unsigned short cpu_to_le16(val)
unsigned short val;
{
    unsigned char *p;
    p = (unsigned char *)&val;
    return (p[1] << 8) | p[0];
}

/* Helper: Convert host byte order to little-endian 32-bit value */
static unsigned long cpu_to_le32(val)
unsigned long val;
{
    unsigned char *p;
    p = (unsigned char *)&val;
    return (p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0];
}

/* Case-insensitive string comparison for 8.3 filenames */
static int fat_strcasecmp(s1, s2)
char *s1, *s2;
{
    int i;
    char c1, c2;
    
    /* Compare base name (8 chars) */
    for (i = 0; i < 8; i++) {
        c1 = toupper(s1[i]);
        c2 = toupper(s2[i]);
        if (c1 != c2)
            return c1 - c2;
    }
    
    /* Compare extension (3 chars) */
    for (i = 0; i < 3; i++) {
        c1 = toupper(s1[8 + i]);
        c2 = toupper(s2[8 + i]);
        if (c1 != c2)
            return c1 - c2;
    }
    
    return 0;
}

/* Compare directory entry with 8.3 filename */
static int compare_dir_entry(entry, name)
struct DirEntry *entry;
char *name;
{
    char entry_name[11];
    
    /* Construct entry name */
    memcpy(entry_name, entry->filename, 8);
    memcpy(entry_name + 8, entry->extension, 3);
    
    return fat_strcasecmp(entry_name, name);
}

/* Convert filename to 8.3 format */
int to_83_filename(name, out)
char *name;
char *out;
{
    char *dot;
    int i;
    int base_len;
    int ext_len;
    static int counter = 1;
    
    /* Initialize with spaces */
    for (i = 0; i < 11; i++)
        out[i] = ' ';
    
    /* Find last dot */
    dot = strrchr(name, '.');
    
    /* Process base name */
    base_len = 0;
    for (i = 0; name[i] && name[i] != '.' && base_len < 8; i++) {
        if (isalnum(name[i])) {
            out[base_len++] = toupper(name[i]);
        }
    }
    
    /* Handle truncation */
    if (base_len == 0) {
        memcpy(out, "FILE", 4);
        base_len = 4;
    } 
    else if (dot && (dot - name) > 8) {
        if (base_len > 6) base_len = 6;
        out[base_len] = '~';
        out[base_len+1] = '0' + (counter++ % 10);
        base_len += 2;
    }
    
    /* Process extension */
    if (dot && dot[1]) {
        ext_len = 0;
        for (i = 1; ext_len < 3 && dot[i]; i++) {
            if (isalnum(dot[i])) {
                out[8 + ext_len++] = toupper(dot[i]);
            }
        }
    }
    
    DEBUG_PRINT3("Converted filename", out[0], out[8]);
    return 0;
}

/* Read boot sector from disk image */
int read_boot_sector(fd, bs)
int fd;
struct BootSector *bs;
{
    unsigned char buffer[512];
    DEBUG_PRINT("Reading boot sector...");
    
    if (lseek(fd, 0, SEEK_SET) != 0) {
        perror("Error seeking to start of file");
        return -1;
    }

    if (read(fd, buffer, 512) != 512) {
        perror("Error reading boot sector");
        return -1;
    }
    
    /* Copy fields with proper byte order */
    bs->bytes_per_sector = (buffer[11] | (buffer[12] << 8));
    bs->sectors_per_cluster = buffer[13];
    bs->reserved_sectors = (buffer[14] | (buffer[15] << 8));
    bs->fat_count = buffer[16];
    bs->root_entries = (buffer[17] | (buffer[18] << 8));
    bs->total_sectors_16 = (buffer[19] | (buffer[20] << 8));
    bs->sectors_per_fat = (buffer[22] | (buffer[23] << 8));
    bs->sectors_per_track = (buffer[24] | (buffer[25] << 8));
    bs->head_count = (buffer[26] | (buffer[27] << 8));
    bs->hidden_sectors = (buffer[28] | (buffer[29] << 8) | 
                        (buffer[30] << 16) | (buffer[31] << 24));
    bs->total_sectors_32 = (buffer[32] | (buffer[33] << 8) | 
                         (buffer[34] << 16) | (buffer[35] << 24));
    bs->signature = (buffer[510] | (buffer[511] << 8));

    /* Validate boot sector */
    if (bs->bytes_per_sector != 512) {
        fprintf(stderr, "Invalid sector size: %d\n", bs->bytes_per_sector);
        return -1;
    }
    
    if (bs->signature != 0xAA55) {
        fprintf(stderr, "Invalid boot signature\n");
        return -1;
    }
    
    return 0;
}

/* Read FAT12 cluster entry */
unsigned short read_fat_entry(fd, bs, cluster)
int fd;
struct BootSector *bs;
unsigned short cluster;
{
    unsigned long fat_offset;
    unsigned long fat_sector;
    unsigned int entry_offset;
    unsigned char sector[512];
    unsigned short entry;

    fat_offset = cluster * 3 / 2;
    fat_sector = bs->reserved_sectors + (fat_offset / bs->bytes_per_sector);
    entry_offset = fat_offset % bs->bytes_per_sector;
    
    if (lseek(fd, fat_sector * bs->bytes_per_sector, SEEK_SET) != 
        fat_sector * bs->bytes_per_sector) {
        perror("Error seeking to FAT sector");
        return CLUSTER_BAD;
    }
    
    if (read(fd, sector, bs->bytes_per_sector) != bs->bytes_per_sector) {
        perror("Error reading FAT sector");
        return CLUSTER_BAD;
    }
    
    entry = sector[entry_offset] | (sector[entry_offset + 1] << 8);
    if (cluster & 1) 
        entry >>= 4;
    else 
        entry &= 0x0FFF;
    
    return entry;
}

/* Get physical sector for cluster */
unsigned long get_cluster_location(bs, cluster)
struct BootSector *bs;
unsigned short cluster;
{
    unsigned long root_dir_sectors;
    unsigned long data_start;

    root_dir_sectors = ((bs->root_entries * 32) + (bs->bytes_per_sector - 1)) / bs->bytes_per_sector;
    data_start = bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat) + root_dir_sectors;
    return data_start + (cluster - 2) * bs->sectors_per_cluster;
}

/* Update FAT entry */
int update_fat(fd, bs, cluster, value)
int fd;
struct BootSector *bs;
unsigned short cluster;
unsigned short value;
{
    unsigned long fat_offset;
    unsigned long fat_sector;
    unsigned int entry_offset;
    unsigned char sector[512];
    int i;

    fat_offset = cluster * 3 / 2;
    fat_sector = bs->reserved_sectors + (fat_offset / bs->bytes_per_sector);
    entry_offset = fat_offset % bs->bytes_per_sector;
    
    /* Read FAT sector */
    if (lseek(fd, fat_sector * bs->bytes_per_sector, SEEK_SET) != 
        fat_sector * bs->bytes_per_sector) {
        perror("Error seeking to FAT sector");
        return -1;
    }
    
    if (read(fd, sector, bs->bytes_per_sector) != bs->bytes_per_sector) {
        perror("Error reading FAT sector");
        return -1;
    }
    
    /* Update entry */
    if (cluster & 1) {
        sector[entry_offset] = (sector[entry_offset] & 0x0F) | ((value << 4) & 0xF0);
        sector[entry_offset+1] = (value >> 4) & 0xFF;
    } else {
        sector[entry_offset] = value & 0xFF;
        sector[entry_offset+1] = (sector[entry_offset+1] & 0xF0) | ((value >> 8) & 0x0F);
    }
    
    /* Write back to all FAT copies */
    for (i = 0; i < bs->fat_count; i++) {
        if (lseek(fd, (bs->reserved_sectors + (i * bs->sectors_per_fat)) * bs->bytes_per_sector + entry_offset, 
            SEEK_SET) != (bs->reserved_sectors + (i * bs->sectors_per_fat)) * bs->bytes_per_sector + entry_offset) {
            perror("Error seeking to FAT copy");
            return -1;
        }
        
        if (write(fd, &sector[entry_offset], 2) != 2) {
            perror("Error writing FAT sector");
            return -1;
        }
    }
    
    return 0;
}

/* Find first free cluster */
unsigned short find_free_cluster(fd, bs)
int fd;
struct BootSector *bs;
{
    unsigned short cluster;
    unsigned short max_cluster;
    unsigned short entry;

    max_cluster = bs->sectors_per_fat * bs->bytes_per_sector * 2 / 3;
    
    for (cluster = 2; cluster < max_cluster; cluster++) {
        entry = read_fat_entry(fd, bs, cluster);
        if (entry == CLUSTER_FREE) {
            return cluster;
        }
    }
    return CLUSTER_FREE;
}

/* Set DOS time/date in directory entry */
void set_dos_time_date(entry)
struct DirEntry *entry;
{
    entry->time = 0x0000;  /* 00:00:00 */
    entry->date = 0x21C1;  /* 01-01-2020 */
}

/* List root directory contents */
int list_root_directory(fd, bs)
int fd;
struct BootSector *bs;
{
    int i, j;
    unsigned long root_dir_start;
    struct DirEntry entry;
    unsigned char buffer[32];

    memset(&entry, 0, sizeof(entry));

    root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
    
    if (lseek(fd, root_dir_start, SEEK_SET) != root_dir_start) {
        perror("Error seeking to root directory");
        return -1;
    }
    
    printf("Type\tSize\tCluster\tName\n");
    printf("----\t----\t-------\t----\n");

    for (i = 0; i < bs->root_entries; i++) {
        if (read(fd, buffer, 32) != 32) {
            perror("Error reading directory entry");
            return -1;
        }

        /* Parse directory entry */
        memcpy(entry.filename, buffer, 8);
        memcpy(entry.extension, buffer + 8, 3);
        entry.attributes = buffer[11];
        entry.first_cluster = (buffer[27] << 8) | buffer[26];
        entry.file_size = (buffer[31] << 24) | (buffer[30] << 16) | 
                         (buffer[29] << 8) | buffer[28];

        if (entry.filename[0] == 0x00)
            break;
        if (entry.filename[0] == 0xE5)
            continue;

        /* Print file info */
        printf("0x%02X\t%lu\t%u\t", entry.attributes, entry.file_size, entry.first_cluster);

        /* Print filename */
        for (j = 0; j < 8 && entry.filename[j] != ' '; j++)
            putchar(entry.filename[j]);

        /* Print extension */
        if (entry.extension[0] != ' ') {
            putchar('.');
            for (j = 0; j < 3 && entry.extension[j] != ' '; j++)
                putchar(entry.extension[j]);
        }
        putchar('\n');
    }

    return 0;
}

/* Extract file from FAT12 disk to host */
int copyout(fd, bs, fat_filename, host_filename)
int fd;
struct BootSector *bs;
char *fat_filename;
char *host_filename;
{
    struct DirEntry entry;
    unsigned long root_dir_start;
    unsigned long file_size;
    unsigned long cluster_size;
    unsigned long sector;
    unsigned long write_size;
    unsigned short cluster;
    FILE *out_file;
    unsigned char *buffer;
    int i;
    int found;
    char search_name[11];
    unsigned char dir_buffer[32];

    memset(&entry, 0, sizeof(entry));

    root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
    cluster_size = bs->bytes_per_sector * bs->sectors_per_cluster;
    found = 0;

    /* Convert search name */
    to_83_filename(fat_filename, search_name);

    if (lseek(fd, root_dir_start, SEEK_SET) != root_dir_start) {
        perror("Error seeking to root directory");
        return -1;
    }

    /* Search for file */
    for (i = 0; i < bs->root_entries; i++) {
        if (read(fd, dir_buffer, 32) != 32) {
            perror("Error reading directory entry");
            return -1;
        }

        memcpy(entry.filename, dir_buffer, 8);
        memcpy(entry.extension, dir_buffer + 8, 3);
        entry.first_cluster = (dir_buffer[27] << 8) | dir_buffer[26];
        entry.file_size = (dir_buffer[31] << 24) | (dir_buffer[30] << 16) | 
                        (dir_buffer[29] << 8) | dir_buffer[28];

        if (entry.filename[0] == 0x00)
            break;
        if (entry.filename[0] == 0xE5)
            continue;

        if (compare_dir_entry(&entry, search_name) == 0) {
            found = 1;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "File not found: %s\n", fat_filename);
        return -1;
    }

    /* Open output file */
    out_file = fopen(host_filename, "wb");
    if (!out_file) {
        perror("Failed to open output file");
        return -1;
    }

    buffer = malloc(cluster_size);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(out_file);
        return -1;
    }

    cluster = entry.first_cluster;
    file_size = entry.file_size;

    /* Read file data */
    while (cluster < CLUSTER_END && cluster != CLUSTER_FREE && file_size > 0) {
        sector = get_cluster_location(bs, cluster);
        if (lseek(fd, sector * bs->bytes_per_sector, SEEK_SET) != sector * bs->bytes_per_sector) {
            perror("Error seeking to cluster");
            free(buffer);
            fclose(out_file);
            return -1;
        }

        write_size = (file_size < cluster_size) ? file_size : cluster_size;
        if (read(fd, buffer, write_size) != write_size) {
            perror("Error reading cluster data");
            free(buffer);
            fclose(out_file);
            return -1;
        }

        if (fwrite(buffer, 1, write_size, out_file) != write_size) {
            perror("Error writing to output file");
            free(buffer);
            fclose(out_file);
            return -1;
        }

        file_size -= write_size;
        cluster = read_fat_entry(fd, bs, cluster);
    }

    free(buffer);
    fclose(out_file);
    return 0;
}

/* Add file from host to FAT12 disk */
int copyin(fd, bs, host_filename, fat_filename)
int fd;
struct BootSector *bs;
char *host_filename;
char *fat_filename;
{
    struct DirEntry new_entry;
    unsigned long root_dir_start;
    unsigned long file_size;
    unsigned long cluster_size;
    unsigned long original_file_size;
    unsigned long sector;
    unsigned long read_size;
    FILE *in_file;
    unsigned char *buffer;
    unsigned short first_cluster;
    unsigned short prev_cluster;
    unsigned short new_cluster;
    int i;
    int free_entry;
    char search_name[11];
    unsigned char dir_buffer[32];

    memset(&new_entry, 0, sizeof(new_entry));

    in_file = fopen(host_filename, "rb");
    if (!in_file) {
        perror("Failed to open input file");
        return -1;
    }

    /* Get file size */
    fseek(in_file, 0, SEEK_END);
    original_file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);
    file_size = original_file_size;

    cluster_size = bs->bytes_per_sector * bs->sectors_per_cluster;
    free_entry = -1;

    /* Allocate buffer */
    buffer = malloc(cluster_size);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(in_file);
        return -1;
    }

    /* Find free directory entry */
    root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
    if (lseek(fd, root_dir_start, SEEK_SET) != root_dir_start) {
        perror("Error seeking to root directory");
        free(buffer);
        fclose(in_file);
        return -1;
    }

    for (i = 0; i < bs->root_entries; i++) {
        if (read(fd, dir_buffer, 32) != 32) {
            perror("Error reading directory entry");
            free(buffer);
            fclose(in_file);
            return -1;
        }

        if (dir_buffer[0] == 0x00 && free_entry == -1) {
            free_entry = i;
            break;
        }
        if (dir_buffer[0] == 0xE5 && free_entry == -1) {
            free_entry = i;
        }
    }

    if (free_entry == -1) {
        fprintf(stderr, "Root directory is full\n");
        free(buffer);
        fclose(in_file);
        return -1;
    }

    /* Write file data */
    first_cluster = find_free_cluster(fd, bs);
    if (first_cluster == 0) {
        fprintf(stderr, "No free clusters\n");
        free(buffer);
        fclose(in_file);
        return -1;
    }

    prev_cluster = first_cluster;
    while (file_size > 0) {
        read_size = fread(buffer, 1, cluster_size, in_file);
        if (read_size <= 0) break;

        sector = get_cluster_location(bs, prev_cluster);
        if (lseek(fd, sector * bs->bytes_per_sector, SEEK_SET) != sector * bs->bytes_per_sector) {
            perror("Error seeking to cluster");
            free(buffer);
            fclose(in_file);
            return -1;
        }

        if (write(fd, buffer, read_size) != read_size) {
            perror("Error writing cluster data");
            free(buffer);
            fclose(in_file);
            return -1;
        }

        file_size -= read_size;

        if (file_size > 0) {
            new_cluster = find_free_cluster(fd, bs);
            if (new_cluster == 0) {
                fprintf(stderr, "No free clusters\n");
                free(buffer);
                fclose(in_file);
                return -1;
            }
            update_fat(fd, bs, prev_cluster, new_cluster);
            prev_cluster = new_cluster;
        }
    }

    update_fat(fd, bs, prev_cluster, CLUSTER_END);

    /* Create directory entry */
    to_83_filename(fat_filename, search_name);
    memcpy(new_entry.filename, search_name, 8);
    memcpy(new_entry.extension, search_name + 8, 3);
    new_entry.attributes = ATTR_ARCHIVE;
    new_entry.first_cluster = first_cluster;
    new_entry.file_size = original_file_size;
    set_dos_time_date(&new_entry);

    /* Write directory entry */
    if (lseek(fd, root_dir_start + (free_entry * 32), SEEK_SET) != root_dir_start + (free_entry * 32)) {
        perror("Error seeking to directory entry");
        free(buffer);
        fclose(in_file);
        return -1;
    }

    memset(dir_buffer, 0, 32);
    memcpy(dir_buffer, new_entry.filename, 8);
    memcpy(dir_buffer + 8, new_entry.extension, 3);
    dir_buffer[11] = new_entry.attributes;
    dir_buffer[26] = new_entry.first_cluster & 0xFF;
    dir_buffer[27] = (new_entry.first_cluster >> 8) & 0xFF;
    dir_buffer[28] = new_entry.file_size & 0xFF;
    dir_buffer[29] = (new_entry.file_size >> 8) & 0xFF;
    dir_buffer[30] = (new_entry.file_size >> 16) & 0xFF;
    dir_buffer[31] = (new_entry.file_size >> 24) & 0xFF;

    if (write(fd, dir_buffer, 32) != 32) {
        perror("Error writing directory entry");
        free(buffer);
        fclose(in_file);
        return -1;
    }

    free(buffer);
    fclose(in_file);
    return 0;
}