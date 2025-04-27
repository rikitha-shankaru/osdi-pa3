#include "fat12.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/* Helper: Convert little-endian 16-bit value to host byte order */
static unsigned short le16_to_cpu(val)
unsigned short val;
{
    return (val >> 8) | (val << 8);
}

/* Helper: Convert little-endian 32-bit value to host byte order */
static unsigned long le32_to_cpu(val)
unsigned long val;
{
    return ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) |
           ((val >> 8) & 0xff00) | ((val << 24) & 0xff000000);
}

static unsigned short cpu_to_le16(val)
unsigned short val;
{
    return (val << 8) | (val >> 8);
}

static unsigned long cpu_to_le32(val) 
unsigned long val;
{
    return ((val << 24) & 0xff000000) |
           ((val << 8)  & 0x00ff0000) |
           ((val >> 8)  & 0x0000ff00) |
           ((val >> 24) & 0x000000ff);
}

/* Case-insensitive string comparison */
static int fat_strcasecmp(s1, s2)
char *s1, *s2;
{
    while (*s1 && *s2) {
        if (toupper(*s1) != toupper(*s2))
            return *s1 - *s2;
        s1++;
        s2++;
    }
    return *s1 - *s2;
}

/* Read boot sector from disk image */
int read_boot_sector(fd, bs)
int fd;
struct BootSector *bs;
{
    if (read(fd, bs, sizeof(struct BootSector)) != sizeof(struct BootSector)) {
        perror("Error reading boot sector");
        return -1;
    }
    
    bs->bytes_per_sector = le16_to_cpu(bs->bytes_per_sector);
    bs->sectors_per_cluster = bs->sectors_per_cluster;
    bs->reserved_sectors = le16_to_cpu(bs->reserved_sectors);
    bs->fat_count = bs->fat_count;
    bs->root_entries = le16_to_cpu(bs->root_entries);
    bs->total_sectors_16 = le16_to_cpu(bs->total_sectors_16);
    bs->media_type = bs->media_type;
    bs->sectors_per_fat = le16_to_cpu(bs->sectors_per_fat);
    bs->sectors_per_track = le16_to_cpu(bs->sectors_per_track);
    bs->head_count = le16_to_cpu(bs->head_count);
    bs->hidden_sectors = le32_to_cpu(bs->hidden_sectors);
    bs->total_sectors_32 = le32_to_cpu(bs->total_sectors_32);
    bs->signature = le16_to_cpu(bs->signature);
    
    return 0;
}

/* List root directory contents */
int list_root_directory(fd, bs)
int fd;
struct BootSector *bs;
{
    unsigned long root_dir_start, root_dir_sectors;
    struct DirEntry entry;
    memset(&entry, 0, sizeof(entry));
    int i, j;

    root_dir_sectors = ((bs->root_entries * 32) + (bs->bytes_per_sector - 1)) / bs->bytes_per_sector;
    root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
    
    lseek(fd, root_dir_start, SEEK_SET);
    printf("Type\tSize\tCluster\tName\n");
    printf("----\t----\t-------\t----\n");

    for (i = 0; i < bs->root_entries; i++)
    {
        if (read(fd, &entry, sizeof(struct DirEntry)) != sizeof(struct DirEntry))
        {
            perror("Error reading directory entry");
            break;
        }

        if (entry.filename[0] == 0x00)
            break;
        if (entry.filename[0] == 0xE5)
            continue;

        /* Print file info */
        printf("0x%02X\t%lu\t%u\t",
               entry.attributes,
               le32_to_cpu(entry.file_size),
               le16_to_cpu(entry.first_cluster));

        /* Print base name (trim trailing spaces) */
        for (j = 0; j < 8 && entry.filename[j] != ' '; j++)
        {
            putchar(entry.filename[j]);
        }

        /* Print extension if not empty */
        if (entry.extension[0] != ' ')
        {
            putchar('.');
            for (j = 0; j < 3 && entry.extension[j] != ' '; j++)
            {
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
    memset(&entry, 0, sizeof(entry));
    unsigned long root_dir_start, root_dir_sectors, file_size, cluster_size, sector, write_size;
    unsigned short cluster;
    FILE *out_file;
    unsigned char *buffer;
    int i, found;
    char search_name[11];

    root_dir_sectors = ((bs->root_entries * 32) + (bs->bytes_per_sector - 1)) / bs->bytes_per_sector;
    root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
    cluster_size = bs->bytes_per_sector * bs->sectors_per_cluster;
    found = 0;

    /* Convert search name to 8.3 format */
    to_83_filename(fat_filename, search_name);

    lseek(fd, root_dir_start, SEEK_SET);
    for (i = 0; i < bs->root_entries; i++) {
        if (read(fd, &entry, sizeof(struct DirEntry)) != sizeof(struct DirEntry)) {
            perror("Error reading directory entry");
            break;
        }

        if (entry.filename[0] == 0x00) break;
        if (entry.filename[0] == 0xE5) continue;

        /* Compare raw 8.3 names (no dot) */
        if (memcmp(entry.filename, search_name, 11) == 0) {
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
        lseek(fd, sector * bs->bytes_per_sector, SEEK_SET);
        if (read(fd, buffer, cluster_size) != cluster_size) {
            perror("Error reading cluster data");
            break;
        }

        write_size = (file_size < cluster_size) ? file_size : cluster_size;
        if (fwrite(buffer, 1, write_size, out_file) != write_size) {
            perror("Error writing to output file");
            break;
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
    struct DirEntry new_entry, entry;
    memset(&entry, 0, sizeof(entry));
    memset(&new_entry, 0, sizeof(new_entry));
    unsigned long root_dir_start, root_dir_sectors, file_size, cluster_size, original_file_size, sector, read_size;
    FILE *in_file;
    unsigned char *buffer;
    unsigned short first_cluster, prev_cluster, new_cluster;
    int i, free_entry;

    root_dir_sectors = ((bs->root_entries * 32) + (bs->bytes_per_sector - 1)) / bs->bytes_per_sector;
    root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
    cluster_size = bs->bytes_per_sector * bs->sectors_per_cluster;
    free_entry = -1;

    lseek(fd, root_dir_start, SEEK_SET);
    for (i = 0; i < bs->root_entries; i++) {
        entry;
        if (read(fd, &entry, sizeof(struct DirEntry)) != sizeof(struct DirEntry)) {
            perror("Error reading directory entry");
            return -1;
        }

        if (entry.filename[0] == 0x00 && free_entry == -1) {
            free_entry = i;
            break;
        }
        if (entry.filename[0] == 0xE5 && free_entry == -1) {
            free_entry = i;
        }
    }

    if (free_entry == -1) {
        fprintf(stderr, "Root directory is full\n");
        return -1;
    }

    in_file = fopen(host_filename, "rb");
    if (!in_file) {
        perror("Failed to open input file");
        return -1;
    }

    fseek(in_file, 0, SEEK_END);
    original_file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);
    file_size = original_file_size;

    buffer = malloc(cluster_size);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(in_file);
        return -1;
    }

    first_cluster = 0;
    prev_cluster = 0;

    while (file_size > 0) {
        new_cluster = find_free_cluster(fd, bs);
        if (new_cluster == CLUSTER_FREE) {
            fprintf(stderr, "No free clusters available\n");
            break;
        }

        if (prev_cluster != 0) {
            update_fat(fd, bs, prev_cluster, new_cluster);
        } else {
            first_cluster = new_cluster;
        }

        read_size = fread(buffer, 1, cluster_size, in_file);
        if (read_size <= 0) break;

        sector = get_cluster_location(bs, new_cluster);
        lseek(fd, sector * bs->bytes_per_sector, SEEK_SET);
        write(fd, buffer, cluster_size);

        update_fat(fd, bs, new_cluster, CLUSTER_END);
        prev_cluster = new_cluster;
        file_size -= read_size;
    }

    memset(&new_entry, 0, sizeof(struct DirEntry));
    to_83_filename(fat_filename, new_entry.filename);
    new_entry.attributes = ATTR_ARCHIVE;
    new_entry.first_cluster = cpu_to_le16(first_cluster);
    new_entry.file_size = cpu_to_le32(original_file_size);
    set_dos_time_date(&new_entry);

    lseek(fd, root_dir_start + (free_entry * sizeof(struct DirEntry)), SEEK_SET);
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
    unsigned long fat_offset, fat_sector, entry_offset;
    unsigned char sector[512];
    unsigned short entry;

    fat_offset = cluster * 3 / 2;
    fat_sector = bs->reserved_sectors + (fat_offset / bs->bytes_per_sector);
    entry_offset = fat_offset % bs->bytes_per_sector;
    
    lseek(fd, fat_sector * bs->bytes_per_sector, SEEK_SET);
    if (read(fd, sector, bs->bytes_per_sector) != bs->bytes_per_sector) {
        perror("Error reading FAT sector");
        return CLUSTER_BAD;
    }
    
    entry = sector[entry_offset] | (sector[entry_offset + 1] << 8);
    if (cluster & 1) entry >>= 4;
    else entry &= 0x0FFF;
    
    return entry;
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
    unsigned long fat_offset, fat_sector, entry_offset;
    unsigned char sector[512];

    fat_offset = cluster * 3 / 2;
    fat_sector = bs->reserved_sectors + (fat_offset / bs->bytes_per_sector);
    entry_offset = fat_offset % bs->bytes_per_sector;
    
    lseek(fd, fat_sector * bs->bytes_per_sector, SEEK_SET);
    if (read(fd, sector, bs->bytes_per_sector) != bs->bytes_per_sector) {
        perror("Error reading FAT sector");
        return -1;
    }
    
    if (cluster & 1) {
        sector[entry_offset] = (sector[entry_offset] & 0x0F) | ((value << 4) & 0xF0);
        sector[entry_offset+1] = (value >> 4) & 0xFF;
    } else {
        sector[entry_offset] = value & 0xFF;
        sector[entry_offset+1] = (sector[entry_offset+1] & 0xF0) | ((value >> 8) & 0x0F);
    }
    
    lseek(fd, fat_sector * bs->bytes_per_sector, SEEK_SET);
    if (write(fd, sector, bs->bytes_per_sector) != bs->bytes_per_sector) {
        perror("Error writing FAT sector");
        return -1;
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
    int i, j, base_len, ext_len;
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
        if (isalnum(name[i])) {
            out[base_len++] = toupper(name[i]);
        }
    }
    
    /* Handle truncation */
    if (base_len == 0) {  /* No valid chars */
        strncpy(out, "FILE", 4);
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
            if (isalnum(dot[i])) {
                out[8 + ext_len++] = toupper(dot[i]);
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

/* Create new file or directory */
int create_file(fd, bs, path, is_dir)
int fd;
struct BootSector *bs;
char *path;
int is_dir;
{
    char *last_slash, *filename, dir_path[MAX_PATH_LEN];
    unsigned short parent_cluster;
    struct DirEntry new_entry;
    memset(&new_entry, 0, sizeof(new_entry));
    unsigned long entry_offset;

    last_slash = strrchr(path, '/');
    filename = last_slash ? last_slash + 1 : path;
    
    if (last_slash) {
        strncpy(dir_path, path, last_slash - path);
        dir_path[last_slash - path] = '\0';
    } else {
        strcpy(dir_path, "/");
    }
    
    parent_cluster = resolve_path(fd, bs, dir_path);
    if (parent_cluster == (unsigned short)-1) {
        fprintf(stderr, "Parent directory not found\n");
        return -1;
    }

    entry_offset = find_free_entry(fd, bs, parent_cluster);
    if (entry_offset == 0) {
        fprintf(stderr, "No free directory entries\n");
        return -1;
    }

    memset(&new_entry, 0, sizeof(struct DirEntry));
    to_83_filename(filename, new_entry.filename);
    
    new_entry.attributes = is_dir ? ATTR_DIRECTORY : ATTR_ARCHIVE;
    new_entry.first_cluster = find_free_cluster(fd, bs);
    set_dos_time_date(&new_entry);
    
    lseek(fd, entry_offset, SEEK_SET);
    if (write(fd, &new_entry, sizeof(struct DirEntry)) != sizeof(struct DirEntry)) {
        perror("Error writing directory entry");
        return -1;
    }
    
    if (is_dir) {
        initialize_directory_cluster(fd, bs, new_entry.first_cluster, parent_cluster);
    }
    
    return 0;
}

/* Delete file or empty directory */
int delete_file(fd, bs, path)
int fd;
struct BootSector *bs;
char *path;
{
    struct DirEntry entry;
    memset(&entry, 0, sizeof(entry));
    unsigned long entry_offset;
    unsigned short parent_cluster, cluster, next;
    unsigned char marker;

    parent_cluster = find_file(fd, bs, path, &entry, &entry_offset);
    if (parent_cluster == (unsigned short)-1) {
        fprintf(stderr, "File not found\n");
        return -1;
    }

    if ((entry.attributes & ATTR_DIRECTORY) && 
        !is_directory_empty(fd, bs, le16_to_cpu(entry.first_cluster))) {
        fprintf(stderr, "Directory not empty\n");
        return -1;
    }

    cluster = le16_to_cpu(entry.first_cluster);
    while (cluster < CLUSTER_END && cluster != CLUSTER_FREE) {
        next = read_fat_entry(fd, bs, cluster);
        update_fat(fd, bs, cluster, CLUSTER_FREE);
        cluster = next;
    }

    lseek(fd, entry_offset, SEEK_SET);
    marker = 0xE5;
    write(fd, &marker, 1);

    return 0;
}

/* Edit file content */
int edit_file(fd, bs, path, offset, data, size)
int fd;
struct BootSector *bs;
char *path;
unsigned long offset;
unsigned char *data;
unsigned long size;
{
    struct DirEntry entry;
    memset(&entry, 0, sizeof(entry));
    unsigned short cluster;
    unsigned long file_size, sector, sector_offset, bytes_remaining, cluster_size;

    if (!find_file(fd, bs, path, &entry, NULL)) {
        fprintf(stderr, "File not found\n");
        return -1;
    }

    file_size = le32_to_cpu(entry.file_size);
    if (offset + size > file_size) {
        fprintf(stderr, "Edit exceeds file size\n");
        return -1;
    }

    cluster = le16_to_cpu(entry.first_cluster);
    cluster_size = bs->bytes_per_sector * bs->sectors_per_cluster;
    bytes_remaining = offset;

    while (bytes_remaining >= cluster_size) {
        cluster = read_fat_entry(fd, bs, cluster);
        if (cluster >= CLUSTER_END) break;
        bytes_remaining -= cluster_size;
    }

    sector = get_cluster_location(bs, cluster) + (bytes_remaining / bs->bytes_per_sector);
    sector_offset = bytes_remaining % bs->bytes_per_sector;
    
    lseek(fd, sector * bs->bytes_per_sector + sector_offset, SEEK_SET);
    write(fd, data, size);

    return 0;
}

/* List directory contents */
int list_path(fd, bs, path)
int fd;
struct BootSector *bs;
char *path;
{
    unsigned short cluster;
    unsigned long sector;
    struct DirEntry entry;
    memset(&entry, 0, sizeof(entry));
    char name[13];

    cluster = resolve_path(fd, bs, path);
    if (cluster == (unsigned short)-1) {
        fprintf(stderr, "Path not found\n");
        return -1;
    }

    sector = get_cluster_location(bs, cluster);
    lseek(fd, sector * bs->bytes_per_sector, SEEK_SET);

    printf("Name\t\tSize\tCluster\tAttr\n");
    printf("----\t\t----\t-------\t----\n");

    while (1) {
        if (read(fd, &entry, sizeof(struct DirEntry)) != sizeof(struct DirEntry)) break;
        if (entry.filename[0] == 0x00) break;
        if (entry.filename[0] == 0xE5) continue;

        sprintf(name, "%.8s.%.3s", entry.filename, entry.extension);
        printf("%-12s\t%lu\t%u\t0x%02X\n", 
               name,
               le32_to_cpu(entry.file_size),
               le16_to_cpu(entry.first_cluster),
               entry.attributes);
    }
    return 0;
}

/* Check if directory is empty */
int is_directory_empty(fd, bs, cluster)
int fd;
struct BootSector *bs;
unsigned short cluster;
{
    unsigned long sector;
    struct DirEntry entry;
    memset(&entry, 0, sizeof(entry));

    sector = get_cluster_location(bs, cluster);
    lseek(fd, sector * bs->bytes_per_sector, SEEK_SET);
    
    while (read(fd, &entry, sizeof(struct DirEntry)) == sizeof(struct DirEntry)) {
        if (entry.filename[0] == 0x00) break;
        if (entry.filename[0] == 0xE5) continue;
        if (strncmp(entry.filename, ".       ", 8) == 0) continue;
        if (strncmp(entry.filename, "..      ", 8) == 0) continue;
        return 0;
    }
    return 1;
}

/* Find file entry by path */
int find_file(fd, bs, path, entry, entry_offset)
int fd;
struct BootSector *bs;
char *path;
struct DirEntry *entry;
unsigned long *entry_offset;
{
    char *last_slash, *filename, dir_path[MAX_PATH_LEN], name[13];
    unsigned short parent_cluster;
    unsigned long dir_start, offset;

    last_slash = strrchr(path, '/');
    filename = last_slash ? last_slash + 1 : path;
    
    if (last_slash) {
        strncpy(dir_path, path, last_slash - path);
    } else {
        strcpy(dir_path, "/");
    }

    parent_cluster = resolve_path(fd, bs, dir_path);
    if (parent_cluster == (unsigned short)-1) {
        return -1;
    }

    dir_start = get_cluster_location(bs, parent_cluster);
    lseek(fd, dir_start, SEEK_SET);

    offset = 0;
    while (read(fd, entry, sizeof(struct DirEntry)) == sizeof(struct DirEntry)) {
        if (entry->filename[0] == 0x00) break;
        if (entry->filename[0] == 0xE5) {
            offset += sizeof(struct DirEntry);
            continue;
        }

        sprintf(name, "%.8s.%.3s", entry->filename, entry->extension);
        if (fat_strcasecmp(filename, name) == 0) {
            if (entry_offset) *entry_offset = dir_start + offset;
            return parent_cluster;
        }
        offset += sizeof(struct DirEntry);
    }
    return -1;
}

/* Resolve path to cluster number */
int resolve_path(fd, bs, path)
int fd;
struct BootSector *bs;
char *path;
{
    char components[MAX_COMPONENTS][13], name[13], path_copy[MAX_PATH_LEN], *token;
    int count, i, found;
    unsigned short current_cluster;
    unsigned long dir_start;
    struct DirEntry entry;
    memset(&entry, 0, sizeof(entry));

    if (strcmp(path, "/") == 0) return 0;

    strncpy(path_copy, path, MAX_PATH_LEN);
    token = strtok(path_copy, "/");
    count = 0;
    while (token && count < MAX_COMPONENTS) {
        to_83_filename(token, components[count++]);
        token = strtok(NULL, "/");
    }

    current_cluster = 0;
    for (i = 0; i < count; i++) {
        found = 0;
        dir_start = get_cluster_location(bs, current_cluster);
        lseek(fd, dir_start, SEEK_SET);

        while (read(fd, &entry, sizeof(struct DirEntry)) == sizeof(struct DirEntry)) {
            if (entry.filename[0] == 0x00) break;
            if (entry.filename[0] == 0xE5) continue;

            sprintf(name, "%.8s.%.3s", entry.filename, entry.extension);
            if (strcmp(components[i], name) == 0) {
                if (!(entry.attributes & ATTR_DIRECTORY) && i != count - 1) {
                    fprintf(stderr, "Not a directory: %s\n", components[i]);
                    return -1;
                }
                current_cluster = le16_to_cpu(entry.first_cluster);
                found = 1;
                break;
            }
        }

        if (!found) {
            fprintf(stderr, "Path component not found: %s\n", components[i]);
            return -1;
        }
    }
    return current_cluster;
}

/* Initialize new directory cluster */
int initialize_directory_cluster(fd, bs, cluster, parent_cluster)
int fd;
struct BootSector *bs;
unsigned short cluster;
unsigned short parent_cluster;
{
    unsigned char sector[512];
    struct DirEntry dot, dotdot;
    memset(&dot, 0, sizeof(dot));
    memset(&dotdot, 0, sizeof(dotdot));
    unsigned long sector_addr;
    int i;

    sector_addr = get_cluster_location(bs, cluster);
    memset(sector, 0, sizeof(sector));

    memset(&dot, 0, sizeof(struct DirEntry));
    strncpy(dot.filename, ".       ", 8);
    dot.attributes = ATTR_DIRECTORY;
    dot.first_cluster = cluster;

    memset(&dotdot, 0, sizeof(struct DirEntry));
    strncpy(dotdot.filename, "..      ", 8);
    dotdot.attributes = ATTR_DIRECTORY;
    dotdot.first_cluster = parent_cluster;

    lseek(fd, sector_addr * bs->bytes_per_sector, SEEK_SET);
    write(fd, &dot, sizeof(struct DirEntry));
    write(fd, &dotdot, sizeof(struct DirEntry));

    for (i = 2 * sizeof(struct DirEntry); i < bs->bytes_per_sector; i += sizeof(struct DirEntry)) {
        write(fd, sector, sizeof(struct DirEntry));
    }

    return 0;
}

/* Find free directory entry */
int find_free_entry(fd, bs, cluster)
int fd;
struct BootSector *bs;
unsigned short cluster;
{
    unsigned long dir_start, offset;
    struct DirEntry entry;
    memset(&entry, 0, sizeof(entry));

    dir_start = get_cluster_location(bs, cluster);
    lseek(fd, dir_start, SEEK_SET);

    offset = 0;
    while (read(fd, &entry, sizeof(struct DirEntry)) == sizeof(struct DirEntry)) {
        if (entry.filename[0] == 0x00 || entry.filename[0] == 0xE5) {
            return dir_start + offset;
        }
        offset += sizeof(struct DirEntry);
    }
    return 0;
}