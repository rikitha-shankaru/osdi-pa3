#include "fat12.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* Helper: Convert little-endian 16-bit value to host byte order */
static unsigned short le16_to_cpu(val)
unsigned short val;
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    /* For big-endian: swap bytes */
    return ((val & 0xFF) << 8) | ((val & 0xFF00) >> 8);
#else
    /* For little-endian: return as-is */
    return val;
#endif
}

/* Helper: Convert little-endian 32-bit value to host byte order */
static unsigned long le32_to_cpu(val)
unsigned long val;
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    /* For big-endian: swap bytes */
    return ((val & 0xFF) << 24) |
           ((val & 0xFF00) << 8) |
           ((val & 0xFF0000) >> 8) |
           ((val & 0xFF000000) >> 24);
#else
    /* For little-endian: return as-is */
    return val;
#endif
}

static unsigned short cpu_to_le16(val)
unsigned short val;
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    /* For big-endian: swap bytes */
    return ((val & 0xFF) << 8) | ((val & 0xFF00) >> 8);
#else
    /* For little-endian: return as-is */
    return val;
#endif
}

static unsigned long cpu_to_le32(val) 
unsigned long val;
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    /* For big-endian: swap bytes */
    return ((val & 0xFF) << 24) |
           ((val & 0xFF00) << 8) |
           ((val & 0xFF0000) >> 8) |
           ((val & 0xFF000000) >> 24);
#else
    /* For little-endian: return as-is */
    return val;
#endif
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
    /* Seek to start of file */
    if (lseek(fd, 0, SEEK_SET) != 0) {
        perror("Error seeking to start of file");
        return -1;
    }

    if (read(fd, bs, sizeof(struct BootSector)) != sizeof(struct BootSector)) {
        perror("Error reading boot sector");
        return -1;
    }
    
    /* Convert all multi-byte values from little-endian to host byte order */
    bs->bytes_per_sector = le16_to_cpu(bs->bytes_per_sector);
    bs->reserved_sectors = le16_to_cpu(bs->reserved_sectors);
    bs->root_entries = le16_to_cpu(bs->root_entries);
    bs->total_sectors_16 = le16_to_cpu(bs->total_sectors_16);
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
    int i, j;
    unsigned long root_dir_start;
    struct DirEntry entry;

    memset(&entry, 0, sizeof(entry));

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

        /* Skip volume label */
        if (entry.attributes & ATTR_VOLUME_ID)
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

    lseek(fd, root_dir_start, SEEK_SET);
    for (i = 0; i < bs->root_entries; i++) {
        if (read(fd, &entry, sizeof(struct DirEntry)) != sizeof(struct DirEntry)) {
            perror("Error reading directory entry");
            break;
        }

        if (entry.filename[0] == 0x00) break;
        if (entry.filename[0] == 0xE5) continue;

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
        lseek(fd, sector * bs->bytes_per_sector, SEEK_SET);
        
        /* Read only what we need */
        write_size = (file_size < cluster_size) ? file_size : cluster_size;
        if (read(fd, buffer, write_size) != write_size) {
            perror("Error reading cluster data");
            break;
        }

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
    unsigned long root_dir_start, file_size, cluster_size, original_file_size, sector, read_size;
    unsigned long total_clusters, available_clusters;
    FILE *in_file;
    unsigned char *buffer;
    unsigned short first_cluster, prev_cluster, new_cluster;
    int i, free_entry;
    char search_name[11];
    char *last_slash, *filename, dir_path[MAX_PATH_LEN];
    unsigned short parent_cluster;

    memset(&entry, 0, sizeof(entry));
    memset(&new_entry, 0, sizeof(new_entry));

    /* Try to delete any existing file with the same name */
    /* Ignore error if file doesn't exist */
    delete_file(fd, bs, fat_filename);

    /* Get parent directory */
    last_slash = strrchr(fat_filename, '/');
    filename = last_slash ? last_slash + 1 : fat_filename;
    
    if (last_slash) {
        strncpy(dir_path, fat_filename, last_slash - fat_filename);
        dir_path[last_slash - fat_filename] = '\0';
    } else {
        strcpy(dir_path, "/");
    }
    
    /* For root directory, parent_cluster is 0 */
    if (strcmp(dir_path, "/") == 0) {
        parent_cluster = 0;
    } else {
        parent_cluster = resolve_path(fd, bs, dir_path);
        if (parent_cluster == (unsigned short)-1) {
            fprintf(stderr, "Parent directory not found\n");
            return -1;
        }
    }

    /* For root directory, find free entry in root directory */
    if (parent_cluster == 0) {
        root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
        lseek(fd, root_dir_start, SEEK_SET);
        for (i = 0; i < bs->root_entries; i++) {
            if (read(fd, &entry, sizeof(struct DirEntry)) != sizeof(struct DirEntry)) {
                perror("Error reading directory entry");
                return -1;
            }
            if (entry.filename[0] == 0x00 || entry.filename[0] == 0xE5) {
                free_entry = i;
                break;
            }
        }
    } else {
        free_entry = find_free_entry(fd, bs, parent_cluster);
    }

    if (free_entry == -1) {
        fprintf(stderr, "No free directory entries\n");
        return -1;
    }

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
            break;
        }

        sector = get_cluster_location(bs, prev_cluster);
        lseek(fd, sector * bs->bytes_per_sector, SEEK_SET);
        if (write(fd, buffer, read_size) != read_size) {
            perror("Error writing cluster data");
            break;
        }

        file_size -= read_size;

        if (file_size > 0) {
            new_cluster = find_free_cluster(fd, bs);
            if (new_cluster == 0) {
                fprintf(stderr, "No free clusters\n");
                break;
            }
            update_fat(fd, bs, prev_cluster, new_cluster);
            prev_cluster = new_cluster;
        }
    }

    update_fat(fd, bs, prev_cluster, CLUSTER_END);

    /* Set up directory entry */
    to_83_filename(filename, search_name);
    memcpy(new_entry.filename, search_name, 8);
    memcpy(new_entry.extension, search_name + 8, 3);
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
    
    lseek(fd, fat_sector * bs->bytes_per_sector + fat_entry_offset, SEEK_SET);
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
    
    lseek(fd, fat_sector * bs->bytes_per_sector + fat_entry_offset, SEEK_SET);
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
        lseek(fd, (bs->reserved_sectors + (i * bs->sectors_per_fat)) * bs->bytes_per_sector + fat_entry_offset, SEEK_SET);
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

/* Delete file or empty directory */
int delete_file(fd, bs, path)
int fd;
struct BootSector *bs;
char *path;
{
    struct DirEntry entry;
    unsigned long entry_offset;
    unsigned short cluster;
    unsigned short next_cluster;
    unsigned long root_dir_start;
    
    /* Find the file in the directory */
    if (find_file(fd, bs, path, &entry, &entry_offset) != 0) {
        return -1;
    }
    
    /* Check if it's a directory */
    if (entry.attributes & ATTR_DIRECTORY) {
        /* Check if directory is empty */
        if (!is_directory_empty(fd, bs, le16_to_cpu(entry.first_cluster))) {
            printf("Cannot delete non-empty directory\n");
            return -1;
        }
    }
    
    /* Get the cluster chain and free it */
    cluster = le16_to_cpu(entry.first_cluster);
    while (cluster >= 2 && cluster < CLUSTER_END_MIN) {
        next_cluster = read_fat_entry(fd, bs, cluster);
        update_fat(fd, bs, cluster, CLUSTER_FREE);
        cluster = next_cluster;
    }
    
    /* Mark the directory entry as deleted */
    entry.filename[0] = 0xE5;
    
    /* Get the location of the parent directory */
    if (strchr(path, '/') == NULL) {
        /* File is in root directory */
        root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
        lseek(fd, root_dir_start + entry_offset, SEEK_SET);
    } else {
        /* File is in a subdirectory */
        char *last_slash = strrchr(path, '/');
        char parent_path[MAX_PATH_LEN];
        unsigned short parent_cluster;
        
        strncpy(parent_path, path, last_slash - path);
        parent_path[last_slash - path] = '\0';
        
        parent_cluster = resolve_path(fd, bs, parent_path);
        if (parent_cluster == -1) {
            return -1;
        }
        
        lseek(fd, get_cluster_location(bs, parent_cluster) + entry_offset, SEEK_SET);
    }
    
    /* Write the updated directory entry */
    if (write(fd, &entry, sizeof(struct DirEntry)) != sizeof(struct DirEntry)) {
        perror("Error writing directory entry");
        return -1;
    }
    
    return 0;
}

/* Find file entry by path */
int find_file(fd, bs, path, entry, entry_offset)
int fd;
struct BootSector *bs;
char *path;
struct DirEntry *entry;
unsigned long *entry_offset;
{
    char *last_component;
    char path_copy[MAX_PATH_LEN];
    unsigned short parent_cluster;
    unsigned long cluster_location;
    unsigned long offset = 0;
    
    /* Make a copy of the path to work with */
    strncpy(path_copy, path, MAX_PATH_LEN - 1);
    path_copy[MAX_PATH_LEN - 1] = '\0';
    
    /* Get the last component of the path */
    last_component = strrchr(path_copy, '/');
    if (last_component) {
        *last_component = '\0';
        last_component++;
        
        /* Resolve the parent directory */
        parent_cluster = resolve_path(fd, bs, path_copy);
        if (parent_cluster == -1) {
            return -1;
        }
    } else {
        /* File is in root directory */
        parent_cluster = 0;
        last_component = path_copy;
    }
    
    /* Get the location of the parent directory */
    if (parent_cluster == 0) {
        cluster_location = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
    } else {
        cluster_location = get_cluster_location(bs, parent_cluster);
    }
    
    /* Search for the file in the parent directory */
    lseek(fd, cluster_location, SEEK_SET);
    while (read(fd, entry, sizeof(struct DirEntry)) == sizeof(struct DirEntry)) {
        if (entry->filename[0] == 0x00) break;
        if (entry->filename[0] == 0xE5) continue;
        
        /* Skip volume label */
        if (entry->attributes & ATTR_VOLUME_ID) continue;
        
        /* Compare filenames */
        char entry_name[13];
        sprintf(entry_name, "%.8s.%.3s", entry->filename, entry->extension);
        if (fat_strcasecmp(entry_name, last_component) == 0) {
            *entry_offset = offset;
            return 0;
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
    char *component;
    char path_copy[MAX_PATH_LEN];
    unsigned short current_cluster = 0;  // Start at root directory
    struct DirEntry entry;
    unsigned long root_dir_start;
    int found;

    /* Make a copy of the path to work with */
    strncpy(path_copy, path, MAX_PATH_LEN - 1);
    path_copy[MAX_PATH_LEN - 1] = '\0';

    /* Get root directory start */
    root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;

    /* Split path into components */
    component = strtok(path_copy, "/");
    while (component != NULL) {
        found = 0;
        
        /* If we're in root directory */
        if (current_cluster == 0) {
            lseek(fd, root_dir_start, SEEK_SET);
            while (read(fd, &entry, sizeof(struct DirEntry)) == sizeof(struct DirEntry)) {
                if (entry.filename[0] == 0x00) break;
                if (entry.filename[0] == 0xE5) continue;
                
                /* Skip volume label */
                if (entry.attributes & ATTR_VOLUME_ID) continue;
                
                /* Compare filenames */
                char entry_name[13];
                sprintf(entry_name, "%.8s.%.3s", entry.filename, entry.extension);
                if (fat_strcasecmp(entry_name, component) == 0) {
                    found = 1;
                    current_cluster = le16_to_cpu(entry.first_cluster);
                    break;
                }
            }
        } else {
            /* We're in a subdirectory */
            unsigned long cluster_location = get_cluster_location(bs, current_cluster);
            lseek(fd, cluster_location, SEEK_SET);
            
            while (read(fd, &entry, sizeof(struct DirEntry)) == sizeof(struct DirEntry)) {
                if (entry.filename[0] == 0x00) break;
                if (entry.filename[0] == 0xE5) continue;
                
                /* Skip volume label */
                if (entry.attributes & ATTR_VOLUME_ID) continue;
                
                /* Compare filenames */
                char entry_name[13];
                sprintf(entry_name, "%.8s.%.3s", entry.filename, entry.extension);
                if (fat_strcasecmp(entry_name, component) == 0) {
                    found = 1;
                    current_cluster = le16_to_cpu(entry.first_cluster);
                    break;
                }
            }
        }
        
        if (!found) {
            return -1;
        }
        
        component = strtok(NULL, "/");
    }
    
    return current_cluster;
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
        if (strncmp((char *)entry.filename, ".       ", 8) == 0) continue;
        if (strncmp((char *)entry.filename, "..      ", 8) == 0) continue;
        return 0;
    }
    return 1;
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