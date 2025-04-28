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

/* Debug print macro */
#define DEBUG_PRINT(fmt, ...) \
    do { if (DEBUG) fprintf(stderr, "DEBUG: " fmt "\n", ##__VA_ARGS__); } while (0)

/* Helper: Convert little-endian 16-bit value to host byte order */
static unsigned short le16_to_cpu(val)
unsigned short val;
{
    return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
}

/* Helper: Convert little-endian 32-bit value to host byte order */
static unsigned long le32_to_cpu(val)
unsigned long val;
{
    return ((val & 0xFF) << 24) |
           ((val & 0xFF00) << 8) |
           ((val & 0xFF0000) >> 8) |
           ((val & 0xFF000000) >> 24);
}

/* Helper: Convert host byte order to little-endian 16-bit value */
static unsigned short cpu_to_le16(val)
unsigned short val;
{
    return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
}

/* Helper: Convert host byte order to little-endian 32-bit value */
static unsigned long cpu_to_le32(val) 
unsigned long val;
{
    return ((val & 0xFF) << 24) |
           ((val & 0xFF00) << 8) |
           ((val & 0xFF0000) >> 8) |
           ((val & 0xFF000000) >> 24);
}

/* Case-insensitive string comparison */
static int fat_strcasecmp(s1, s2)
char *s1, *s2;
{
    while (*s1 && *s2) {
        char c1 = toupper((unsigned char)*s1);
        char c2 = toupper((unsigned char)*s2);
        if (c1 != c2)
            return c1 - c2;
        s1++;
        s2++;
    }
    return toupper((unsigned char)*s1) - toupper((unsigned char)*s2);
}

/* Read boot sector from disk image */
int read_boot_sector(fd, bs)
int fd;
struct BootSector *bs;
{
    unsigned char buffer[512];
    DEBUG_PRINT("Reading boot sector...");
    
    /* Seek to start of file */
    if (lseek(fd, 0, SEEK_SET) != 0) {
        perror("Error seeking to start of file");
        return -1;
    }

    /* Read entire sector into buffer */
    if (read(fd, buffer, 512) != 512) {
        perror("Error reading boot sector");
        return -1;
    }
    
    /* Copy non-byte-order dependent fields */
    memcpy(bs->jump, buffer, 3);
    memcpy(bs->oem, buffer + 3, 8);
    bs->sectors_per_cluster = buffer[13];
    bs->fat_count = buffer[16];
    bs->media_type = buffer[21];
    bs->drive_number = buffer[36];
    bs->reserved = buffer[37];
    bs->boot_signature = buffer[38];
    memcpy(bs->volume_label, buffer + 43, 11);
    memcpy(bs->fs_type, buffer + 54, 8);
    memcpy(bs->boot_code, buffer + 62, 448);
    
    /* Read and convert byte-order dependent fields */
    bs->bytes_per_sector = (buffer[12] << 8) | buffer[11];
    bs->reserved_sectors = (buffer[15] << 8) | buffer[14];
    bs->root_entries = (buffer[18] << 8) | buffer[17];
    bs->total_sectors_16 = (buffer[20] << 8) | buffer[19];
    bs->sectors_per_fat = (buffer[23] << 8) | buffer[22];
    bs->sectors_per_track = (buffer[25] << 8) | buffer[24];
    bs->head_count = (buffer[27] << 8) | buffer[26];
    bs->hidden_sectors = ((unsigned long)buffer[31] << 24) |
                        ((unsigned long)buffer[30] << 16) |
                        ((unsigned long)buffer[29] << 8) |
                        buffer[28];
    bs->total_sectors_32 = ((unsigned long)buffer[35] << 24) |
                          ((unsigned long)buffer[34] << 16) |
                          ((unsigned long)buffer[33] << 8) |
                          buffer[32];
    bs->volume_id = ((unsigned long)buffer[42] << 24) |
                   ((unsigned long)buffer[41] << 16) |
                   ((unsigned long)buffer[40] << 8) |
                   buffer[39];
    bs->signature = (buffer[511] << 8) | buffer[510];
    
    /* Print raw values before conversion */
    DEBUG_PRINT("Raw boot sector values before conversion:");
    DEBUG_PRINT("  Bytes per sector: 0x%04X", bs->bytes_per_sector);
    DEBUG_PRINT("  Reserved sectors: 0x%04X", bs->reserved_sectors);
    DEBUG_PRINT("  Root entries: 0x%04X", bs->root_entries);
    DEBUG_PRINT("  Sectors per FAT: 0x%04X", bs->sectors_per_fat);
    DEBUG_PRINT("  Signature: 0x%04X", bs->signature);
    
    /* Print converted values */
    DEBUG_PRINT("Converted boot sector values:");
    DEBUG_PRINT("  Bytes per sector: %d (0x%04X)", bs->bytes_per_sector, bs->bytes_per_sector);
    DEBUG_PRINT("  Reserved sectors: %d (0x%04X)", bs->reserved_sectors, bs->reserved_sectors);
    DEBUG_PRINT("  Root entries: %d (0x%04X)", bs->root_entries, bs->root_entries);
    DEBUG_PRINT("  Sectors per FAT: %d (0x%04X)", bs->sectors_per_fat, bs->sectors_per_fat);
    DEBUG_PRINT("  Signature: 0x%04X", bs->signature);
    
    /* Validate boot sector */
    if (bs->bytes_per_sector != 512) {
        fprintf(stderr, "Invalid sector size: %d (expected 512)\n", bs->bytes_per_sector);
        return -1;
    }
    
    if (bs->signature != 0xAA55) {
        fprintf(stderr, "Invalid boot sector signature: 0x%04X (expected 0xAA55)\n", bs->signature);
        return -1;
    }
    
    DEBUG_PRINT("Boot sector validation passed");
    return 0;
}

/* List root directory contents */
int list_root_directory(fd, bs)
int fd;
struct BootSector *bs;
{
    int i, j;
    unsigned long root_dir_start;
    struct DirEntry entry;

    memset(&entry, 0, sizeof(entry));

    root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
    
    if (lseek(fd, root_dir_start, SEEK_SET) != root_dir_start) {
        perror("Error seeking to root directory");
        return -1;
    }
    
    printf("Type\tSize\tCluster\tName\n");
    printf("----\t----\t-------\t----\n");

    for (i = 0; i < bs->root_entries; i++) {
        if (read(fd, &entry, sizeof(struct DirEntry)) != sizeof(struct DirEntry)) {
            perror("Error reading directory entry");
            return -1;
        }

        if (entry.filename[0] == 0x00)
            break;
        if (entry.filename[0] == 0xE5)
            continue;

        /* Skip volume label */
        if (entry.attributes & ATTR_VOLUME_ID)
            continue;

        /* Print file info */
        printf("0x%02X\t%lu\t%u\t",
               entry.attributes,
               le32_to_cpu(entry.file_size),
               le16_to_cpu(entry.first_cluster));

        /* Print base name (trim trailing spaces) */
        for (j = 0; j < 8 && entry.filename[j] != ' '; j++) {
            putchar(entry.filename[j]);
        }

        /* Print extension if not empty */
        if (entry.extension[0] != ' ') {
            putchar('.');
            for (j = 0; j < 3 && entry.extension[j] != ' '; j++) {
                putchar(entry.extension[j]);
            }
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
    unsigned long root_dir_start, file_size, cluster_size, sector, write_size;
    unsigned short cluster;
    FILE *out_file;
    unsigned char *buffer;
    int i, found;
    char search_name[11];

    memset(&entry, 0, sizeof(entry));

    root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
    cluster_size = bs->bytes_per_sector * bs->sectors_per_cluster;
    found = 0;

    /* Convert search name to 8.3 format */
    to_83_filename(fat_filename, search_name);

    if (lseek(fd, root_dir_start, SEEK_SET) != root_dir_start) {
        perror("Error seeking to root directory");
        return -1;
    }

    for (i = 0; i < bs->root_entries; i++) {
        if (read(fd, &entry, sizeof(struct DirEntry)) != sizeof(struct DirEntry)) {
            perror("Error reading directory entry");
            return -1;
        }

        if (entry.filename[0] == 0x00)
            break;
        if (entry.filename[0] == 0xE5)
            continue;

        /* Compare raw 8.3 names (no dot) */
        if (memcmp(entry.filename, search_name, 8) == 0 && 
            memcmp(entry.extension, search_name + 8, 3) == 0) {
            found = 1;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "File not found: %s\n", fat_filename);
        return -1;
    }

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

    cluster = le16_to_cpu(entry.first_cluster);
    file_size = le32_to_cpu(entry.file_size);

    while (cluster < CLUSTER_END && cluster != CLUSTER_FREE && file_size > 0) {
        sector = get_cluster_location(bs, cluster);
        if (lseek(fd, sector * bs->bytes_per_sector, SEEK_SET) != sector * bs->bytes_per_sector) {
            perror("Error seeking to cluster");
            free(buffer);
            fclose(out_file);
            return -1;
        }
        
        /* Read only what we need */
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
    unsigned long root_dir_start, file_size, cluster_size, original_file_size, sector, read_size;
    unsigned long total_clusters, available_clusters;
    FILE *in_file;
    unsigned char *buffer;
    unsigned short first_cluster, prev_cluster, new_cluster;
    int i, free_entry;
    char search_name[11];

    memset(&new_entry, 0, sizeof(new_entry));

    in_file = fopen(host_filename, "rb");
    if (!in_file) {
        perror("Failed to open input file");
        return -1;
    }

    fseek(in_file, 0, SEEK_END);
    file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    /* Calculate cluster size */
    cluster_size = bs->bytes_per_sector * bs->sectors_per_cluster;

    /* Check if we have enough space */
    total_clusters = (bs->sectors_per_fat * bs->bytes_per_sector * 2 / 3) - 2;
    available_clusters = 0;
    for (i = 2; i < total_clusters; i++) {
        if (read_fat_entry(fd, bs, i) == CLUSTER_FREE) {
            available_clusters++;
        }
    }

    if ((file_size + cluster_size - 1) / cluster_size > available_clusters) {
        fprintf(stderr, "Not enough free clusters\n");
        fclose(in_file);
        return -1;
    }

    buffer = malloc(cluster_size);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(in_file);
        return -1;
    }

    first_cluster = find_free_cluster(fd, bs);
    if (first_cluster == 0) {
        fprintf(stderr, "No free clusters\n");
        free(buffer);
        fclose(in_file);
        return -1;
    }

    prev_cluster = first_cluster;
    original_file_size = file_size;

    while (file_size > 0) {
        read_size = (file_size < cluster_size) ? file_size : cluster_size;
        if (fread(buffer, 1, read_size, in_file) != read_size) {
            perror("Error reading from input file");
            free(buffer);
            fclose(in_file);
            return -1;
        }

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

    /* Set up directory entry */
    to_83_filename(fat_filename, search_name);
    memcpy(new_entry.filename, search_name, 8);
    memcpy(new_entry.extension, search_name + 8, 3);
    new_entry.attributes = ATTR_ARCHIVE;
    new_entry.first_cluster = cpu_to_le16(first_cluster);
    new_entry.file_size = cpu_to_le32(original_file_size);
    set_dos_time_date(&new_entry);

    /* Find free entry in root directory */
    root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
    if (lseek(fd, root_dir_start, SEEK_SET) != root_dir_start) {
        perror("Error seeking to root directory");
        free(buffer);
        fclose(in_file);
        return -1;
    }

    for (i = 0; i < bs->root_entries; i++) {
        struct DirEntry entry;
        if (read(fd, &entry, sizeof(struct DirEntry)) != sizeof(struct DirEntry)) {
            perror("Error reading directory entry");
            free(buffer);
            fclose(in_file);
            return -1;
        }
        if (entry.filename[0] == 0x00 || entry.filename[0] == 0xE5) {
            free_entry = i;
            break;
        }
    }

    if (free_entry == -1) {
        fprintf(stderr, "No free directory entries\n");
        free(buffer);
        fclose(in_file);
        return -1;
    }

    if (lseek(fd, root_dir_start + (free_entry * sizeof(struct DirEntry)), SEEK_SET) != 
        root_dir_start + (free_entry * sizeof(struct DirEntry))) {
        perror("Error seeking to directory entry");
        free(buffer);
        fclose(in_file);
        return -1;
    }

    if (write(fd, &new_entry, sizeof(struct DirEntry)) != sizeof(struct DirEntry)) {
        perror("Error writing directory entry");
        free(buffer);
        fclose(in_file);
        return -1;
    }

    free(buffer);
    fclose(in_file);
    return 0;
}

/* Read FAT12 cluster entry */
unsigned short read_fat_entry(fd, bs, cluster)
int fd;
struct BootSector *bs;
unsigned short cluster;
{
    unsigned long fat_offset, fat_sector, fat_entry_offset;
    unsigned short fat_entry;
    unsigned char fat_data[3];
    
    /* Validate cluster number */
    if (cluster < 2 || cluster >= (bs->sectors_per_fat * bs->bytes_per_sector * 2 / 3)) {
        return CLUSTER_BAD;
    }
    
    fat_offset = cluster + (cluster / 2);
    fat_sector = bs->reserved_sectors + (fat_offset / bs->bytes_per_sector);
    fat_entry_offset = fat_offset % bs->bytes_per_sector;
    
    if (lseek(fd, fat_sector * bs->bytes_per_sector + fat_entry_offset, SEEK_SET) != 
        fat_sector * bs->bytes_per_sector + fat_entry_offset) {
        perror("Error seeking to FAT entry");
        return CLUSTER_BAD;
    }

    if (read(fd, fat_data, 3) != 3) {
        perror("Error reading FAT entry");
        return CLUSTER_BAD;
    }
    
    if (cluster & 1)
        fat_entry = ((fat_data[1] & 0x0F) << 8) | fat_data[0];
    else
        fat_entry = (fat_data[2] << 4) | (fat_data[1] >> 4);
    
    return le16_to_cpu(fat_entry);
}

/* Get physical sector for cluster */
unsigned long get_cluster_location(bs, cluster)
struct BootSector *bs;
unsigned short cluster;
{
    unsigned long root_dir_sectors, data_start;

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
    unsigned long fat_offset, fat_sector, fat_entry_offset;
    unsigned char fat_data[3];
    int i;
    
    /* Validate cluster number */
    if (cluster < 2 || cluster >= (bs->sectors_per_fat * bs->bytes_per_sector * 2 / 3)) {
        return -1;
    }
    
    value = cpu_to_le16(value);
    fat_offset = cluster + (cluster / 2);
    fat_sector = bs->reserved_sectors + (fat_offset / bs->bytes_per_sector);
    fat_entry_offset = fat_offset % bs->bytes_per_sector;
    
    if (lseek(fd, fat_sector * bs->bytes_per_sector + fat_entry_offset, SEEK_SET) != 
        fat_sector * bs->bytes_per_sector + fat_entry_offset) {
        perror("Error seeking to FAT entry");
        return -1;
    }

    if (read(fd, fat_data, 3) != 3) {
        perror("Error reading FAT entry");
        return -1;
    }
    
    if (cluster & 1) {
        fat_data[0] = value & 0xFF;
        fat_data[1] = (fat_data[1] & 0xF0) | ((value >> 8) & 0x0F);
    } else {
        fat_data[1] = (fat_data[1] & 0x0F) | ((value << 4) & 0xF0);
        fat_data[2] = (value >> 4) & 0xFF;
    }
    
    /* Update both FAT copies */
    for (i = 0; i < bs->fat_count; i++) {
        if (lseek(fd, (bs->reserved_sectors + (i * bs->sectors_per_fat)) * bs->bytes_per_sector + fat_entry_offset, SEEK_SET) != 
            (bs->reserved_sectors + (i * bs->sectors_per_fat)) * bs->bytes_per_sector + fat_entry_offset) {
            perror("Error seeking to FAT copy");
            return -1;
        }

        if (write(fd, fat_data, 3) != 3) {
            perror("Error writing FAT entry");
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
    unsigned short cluster, max_cluster, entry;

    max_cluster = bs->sectors_per_fat * bs->bytes_per_sector * 2 / 3;
    
    for (cluster = 2; cluster < max_cluster; cluster++) {
        entry = read_fat_entry(fd, bs, cluster);
        if (entry == CLUSTER_FREE) {
            return cluster;
        }
    }
    return CLUSTER_FREE;
}

/* Convert filename to 8.3 format */
int to_83_filename(name, out)
char *name;
char *out;
{
    char *dot;
    int i, base_len, ext_len;
    static int counter = 1;
    
    /* Initialize with spaces */
    for (i = 0; i < 11; i++)
        out[i] = ' ';
    
    /* Find last dot */
    dot = strrchr(name, '.');
    
    /* -- Process base name -- */
    /* Calculate base length without special chars */
    base_len = 0;
    for (i = 0; name[i] && name[i] != '.' && base_len < 8; i++) {
        /* Convert to uppercase and handle special chars */
        if (isalnum(name[i])) {
            out[base_len++] = toupper(name[i]);
        } else if (name[i] == '_' || name[i] == '-') {
            out[base_len++] = '_';
        }
    }
    
    /* Handle truncation */
    if (base_len == 0) {  /* No valid chars */
        memcpy(out, "FILE", 4);
        base_len = 4;
    } 
    else if ((dot - name) > 8) {  /* Original name was long */
        if (base_len > 6) base_len = 6;
        out[base_len] = '~';
        out[base_len+1] = '0' + (counter++ % 10);
        base_len += 2;
    }
    
    /* -- Process extension -- */
    if (dot && dot[1]) {
        ext_len = 0;
        for (i = 1; ext_len < 3 && dot[i]; i++) {
            /* Convert to uppercase and handle special chars */
            if (isalnum(dot[i])) {
                out[8 + ext_len++] = toupper(dot[i]);
            } else if (dot[i] == '_' || dot[i] == '-') {
                out[8 + ext_len++] = '_';
            }
        }
        if (ext_len == 0) {
            out[8] = '_';  /* Empty extension case */
        }
    }
    
    return 0;
}

/* Set DOS time/date in directory entry */
void set_dos_time_date(entry)
struct DirEntry *entry;
{
    entry->time = 0x0000;  /* 00:00:00 */
    entry->date = 0x21C1;  /* 01-01-2020 */
}