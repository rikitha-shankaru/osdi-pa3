#include "fat12.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* Helper: Convert little-endian 16-bit value to host byte order */
static uint16_t le16_to_cpu(uint16_t val) {
    return (val >> 8) | (val << 8);
}

/* Helper: Convert little-endian 32-bit value to host byte order */
static uint32_t le32_to_cpu(uint32_t val) {
    return ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) |
           ((val >> 8) & 0xff00) | ((val << 24) & 0xff000000);
}

/*
 * Reads boot sector from disk image
 * Args:
 *   fd - File descriptor of open disk image
 *   bs - Pointer to BootSector struct to populate
 * Returns:
 *   0 on success, -1 on error
 */
int read_boot_sector(int fd, BootSector *bs) {
    /* Read exactly 512 bytes into boot sector struct */
    if (read(fd, bs, sizeof(BootSector)) != sizeof(BootSector)) {
        perror("Failed to read boot sector");
        return -1;
    }
    
    /* Convert multi-byte fields from little-endian to host byte order */
    bs->bytes_per_sector = le16_to_cpu(bs->bytes_per_sector);
    bs->sectors_per_fat = le16_to_cpu(bs->sectors_per_fat);
    bs->root_entries = le16_to_cpu(bs->root_entries);
    bs->total_sectors = le16_to_cpu(bs->total_sectors);
    
    return 0;
}

/*
 * Lists all files in root directory
 * Args:
 *   fd - Open file descriptor of disk image
 *   bs - Pointer to initialized BootSector
 */
void list_root_directory(int fd, BootSector *bs) {
    /* Calculate root directory location */
    uint32_t fat_size = bs->sectors_per_fat * bs->bytes_per_sector;
    uint32_t root_dir_sectors = ((bs->root_entries * 32) + (bs->bytes_per_sector - 1)) / bs->bytes_per_sector;
    uint32_t root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;
    
    /* Seek to start of root directory */
    lseek(fd, root_dir_start, SEEK_SET);
    
    DirEntry entry;
    printf("Type\tSize\tCluster\tName\n");
    printf("----\t----\t-------\t----\n");
    
    /* Read each directory entry (32 bytes each) */
    for (int i = 0; i < bs->root_entries; i++) {
        if (read(fd, &entry, sizeof(DirEntry)) != sizeof(DirEntry)) {
            perror("Error reading directory entry");
            break;
        }

        /* Skip empty or deleted entries */
        if (entry.filename[0] == 0x00) break;  /* End of directory */
        if (entry.filename[0] == 0xE5) continue; /* Deleted file */

        /* Format filename (8.3 format) */
        char name[13];
        snprintf(name, sizeof(name), "%.8s.%.3s", entry.filename, entry.extension);
        
        /* Print entry information */
        printf("0x%02X\t%u\t%u\t%s\n", 
               entry.attributes, 
               le32_to_cpu(entry.file_size),
               le16_to_cpu(entry.first_cluster),
               name);
    }
}

/*
 * Reads a FAT12 cluster entry
 * Args:
 *   fd - Disk image file descriptor
 *   bs - Boot sector info
 *   cluster - Cluster number to read
 * Returns:
 *   Next cluster number in chain (or 0xFFF for end)
 */
static uint16_t read_fat_entry(int fd, BootSector *bs, uint16_t cluster) {
    /* FAT12 uses 12-bit entries packed into bytes */
    uint32_t fat_offset = cluster * 3 / 2;
    uint32_t fat_sector = bs->reserved_sectors + (fat_offset / bs->bytes_per_sector);
    uint32_t entry_offset = fat_offset % bs->bytes_per_sector;
    
    /* Read containing sector */
    lseek(fd, fat_sector * bs->bytes_per_sector, SEEK_SET);
    uint8_t sector[bs->bytes_per_sector];
    read(fd, sector, bs->bytes_per_sector);
    
    /* Extract 12-bit value */
    uint16_t entry = *(uint16_t*)&sector[entry_offset];
    if (cluster & 1) {
        entry >>= 4;  /* Odd cluster uses high 12 bits */
    } else {
        entry &= 0x0FFF; /* Even cluster uses low 12 bits */
    }
    
    return entry;
}

/*
 * Extracts file from FAT12 disk to host filesystem
 * Args:
 *   fd - Disk image file descriptor
 *   bs - Boot sector info
 *   fat_filename - Source filename in 8.3 format (e.g., "TEST.TXT")
 *   host_filename - Destination path on host (e.g., "output.txt")
 * Returns:
 *   0 on success, -1 on error
 */
int copyout(int fd, BootSector *bs, const char *fat_filename, const char *host_filename) {
    DirEntry entry;
    uint32_t root_dir_start, root_dir_sectors;
    uint16_t cluster;
    FILE *out_file;
    uint8_t *buffer;
    int ret = -1;

    /* Calculate root directory location */
    root_dir_sectors = ((bs->root_entries * 32) + (bs->bytes_per_sector - 1)) / bs->bytes_per_sector;
    root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;

    /* Search root directory for the file */
    lseek(fd, root_dir_start, SEEK_SET);
    int found = 0;
    for (int i = 0; i < bs->root_entries; i++) {
        if (read(fd, &entry, sizeof(DirEntry)) != sizeof(DirEntry)) {
            perror("Error reading directory entry");
            goto cleanup;
        }

        /* Skip empty or deleted entries */
        if (entry.filename[0] == 0x00) break;
        if (entry.filename[0] == 0xE5) continue;

        /* Compare filename (case-insensitive) */
        char entry_name[13];
        snprintf(entry_name, sizeof(entry_name), "%.8s.%.3s", entry.filename, entry.extension);
        if (strcasecmp(fat_filename, entry_name) == 0) {
            found = 1;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "File not found: %s\n", fat_filename);
        goto cleanup;
    }

    /* Check if it's a directory */
    if (entry.attributes & ATTR_DIRECTORY) {
        fprintf(stderr, "Cannot copy directories with copyout: %s\n", fat_filename);
        goto cleanup;
    }

    /* Open output file */
    out_file = fopen(host_filename, "wb");
    if (!out_file) {
        perror("Failed to open output file");
        goto cleanup;
    }

    /* Allocate buffer for cluster data */
    uint32_t cluster_size = bs->bytes_per_sector * bs->sectors_per_cluster;
    buffer = malloc(cluster_size);
    if (!buffer) {
        perror("Memory allocation failed");
        goto cleanup;
    }

    /* Follow cluster chain and write data */
    cluster = le16_to_cpu(entry.first_cluster);
    uint32_t remaining_bytes = le32_to_cpu(entry.file_size);

    while (cluster < CLUSTER_END && cluster != CLUSTER_FREE && remaining_bytes > 0) {
        /* Calculate sector address for this cluster */
        uint32_t sector = get_cluster_location(bs, cluster);

        /* Read entire cluster */
        lseek(fd, sector * bs->bytes_per_sector, SEEK_SET);
        if (read(fd, buffer, cluster_size) != cluster_size) {
            perror("Error reading cluster data");
            goto cleanup;
        }

        /* Write to output file (only up to file size) */
        uint32_t write_size = (remaining_bytes < cluster_size) ? remaining_bytes : cluster_size;
        if (fwrite(buffer, 1, write_size, out_file) != write_size) {
            perror("Error writing to output file");
            goto cleanup;
        }

        remaining_bytes -= write_size;

        /* Get next cluster from FAT */
        cluster = read_fat_entry(fd, bs, cluster);
    }

    ret = 0; /* Success */

cleanup:
    if (buffer) free(buffer);
    if (out_file) fclose(out_file);
    return ret;
}

/*
 * Copies file from host to FAT12 disk
 * Args:
 *   fd - Disk image file descriptor
 *   bs - Boot sector info
 *   host_filename - Source file on host (e.g., "input.txt")
 *   fat_filename - Destination name in 8.3 format (e.g., "NEWFILE.TXT")
 * Returns:
 *   0 on success, -1 on error
 */
int copyin(int fd, BootSector *bs, const char *host_filename, const char *fat_filename) {
    DirEntry new_entry;
    uint32_t root_dir_start, root_dir_sectors;
    FILE *in_file;
    uint8_t *buffer;
    uint16_t first_cluster = CLUSTER_FREE, prev_cluster = CLUSTER_FREE;
    int ret = -1;
    uint32_t file_size;
    int free_entry_index = -1;

    /* Calculate root directory location */
    root_dir_sectors = ((bs->root_entries * 32) + (bs->bytes_per_sector - 1)) / bs->bytes_per_sector;
    root_dir_start = (bs->reserved_sectors + (bs->fat_count * bs->sectors_per_fat)) * bs->bytes_per_sector;

    /* Check if filename already exists */
    lseek(fd, root_dir_start, SEEK_SET);
    for (int i = 0; i < bs->root_entries; i++) {
        DirEntry entry;
        if (read(fd, &entry, sizeof(DirEntry)) != sizeof(DirEntry)) {
            perror("Error reading directory entry");
            goto cleanup;
        }

        /* Remember first empty slot */
        if (entry.filename[0] == 0x00 && free_entry_index == -1) {
            free_entry_index = i;
            break; /* Stop at first empty entry */
        }

        /* Skip deleted entries */
        if (entry.filename[0] == 0xE5) continue;

        /* Check for filename conflict */
        char entry_name[13];
        snprintf(entry_name, sizeof(entry_name), "%.8s.%.3s", entry.filename, entry.extension);
        if (strcasecmp(fat_filename, entry_name) == 0) {
            fprintf(stderr, "File already exists: %s\n", fat_filename);
            goto cleanup;
        }
    }

    if (free_entry_index == -1) {
        fprintf(stderr, "Root directory is full\n");
        goto cleanup;
    }

    /* Open input file */
    in_file = fopen(host_filename, "rb");
    if (!in_file) {
        perror("Failed to open input file");
        goto cleanup;
    }

    /* Get file size */
    fseek(in_file, 0, SEEK_END);
    file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    /* Allocate buffer for cluster data */
    uint32_t cluster_size = bs->bytes_per_sector * bs->sectors_per_cluster;
    buffer = malloc(cluster_size);
    if (!buffer) {
        perror("Memory allocation failed");
        goto cleanup;
    }

    /* Allocate clusters and write data */
    uint32_t remaining_bytes = file_size;
    while (remaining_bytes > 0) {
        /* Allocate new cluster */
        uint16_t new_cluster = find_free_cluster(fd, bs);
        if (new_cluster == CLUSTER_FREE) {
            fprintf(stderr, "Disk is full\n");
            goto cleanup;
        }

        /* Update FAT chain */
        if (prev_cluster != CLUSTER_FREE) {
            if (update_fat(fd, bs, prev_cluster, new_cluster) != 0) {
                goto cleanup;
            }
        } else {
            first_cluster = new_cluster;
        }

        /* Mark cluster as end of chain (temporarily) */
        if (update_fat(fd, bs, new_cluster, CLUSTER_END) != 0) {
            goto cleanup;
        }

        /* Read data from input file */
        uint32_t read_size = (remaining_bytes < cluster_size) ? remaining_bytes : cluster_size;
        if (fread(buffer, 1, read_size, in_file) != read_size) {
            perror("Error reading from input file");
            goto cleanup;
        }

        /* Write to disk */
        uint32_t sector = get_cluster_location(bs, new_cluster);
        lseek(fd, sector * bs->bytes_per_sector, SEEK_SET);
        if (write(fd, buffer, cluster_size) != cluster_size) {
            perror("Error writing to disk");
            goto cleanup;
        }

        remaining_bytes -= read_size;
        prev_cluster = new_cluster;
    }

    /* Create directory entry */
    memset(&new_entry, 0, sizeof(DirEntry));
    
    /* Convert to 8.3 format */
    char name[9], ext[4];
    if (sscanf(fat_filename, "%8[^.].%3s", name, ext) != 2) {
        /* Handle files without extension */
        strncpy(name, fat_filename, 8);
        ext[0] = '\0';
    }
    
    /* Pad with spaces */
    strncpy(new_entry.filename, name, 8);
    strncpy(new_entry.extension, ext, 3);
    for (int i = strlen(name); i < 8; i++) new_entry.filename[i] = ' ';
    for (int i = strlen(ext); i < 3; i++) new_entry.extension[i] = ' ';

    /* Set metadata */
    new_entry.attributes = ATTR_ARCHIVE;
    new_entry.first_cluster = htole16(first_cluster);
    new_entry.file_size = htole32(file_size);
    
    /* Get current time/date (DOS format) */
    set_dos_time_date(&new_entry);

    /* Write directory entry */
    lseek(fd, root_dir_start + (free_entry_index * sizeof(DirEntry)), SEEK_SET);
    if (write(fd, &new_entry, sizeof(DirEntry)) != sizeof(DirEntry)) {
        perror("Error writing directory entry");
        goto cleanup;
    }

    ret = 0; /* Success */

cleanup:
    if (buffer) free(buffer);
    if (in_file) fclose(in_file);
    return ret;
}





/* Lists contents of any directory (not just root) */
int list_path(int fd, BootSector *bs, const char *path) {
    if (strcmp(path, "/") == 0) {
        list_root_directory(fd, bs);
        return 0;
    }

    /* Parse path components */
    char *components[16];
    int count = 0;
    char *token = strtok((char*)path, "/");
    while (token != NULL && count < 16) {
        components[count++] = token;
        token = strtok(NULL, "/");
    }

    /* Start from root directory */
    uint32_t current_cluster = 0; // 0 means root
    DirEntry entry;

    for (int i = 0; i < count; i++) {
        bool found = false;
        uint32_t dir_start = get_cluster_location(bs, current_cluster);

        /* Search directory for component */
        lseek(fd, dir_start, SEEK_SET);
        while (read_directory_entry(fd, &entry)) {
            if (entry.filename[0] == 0x00) break;
            if (entry.filename[0] == 0xE5) continue;

            char name[13];
            to_83_filename(components[i], name);
            char entry_name[13];
            snprintf(entry_name, sizeof(entry_name), "%.8s.%.3s", 
                    entry.filename, entry.extension);

            if (strcasecmp(name, entry_name) == 0) {
                if (!(entry.attributes & ATTR_DIRECTORY) && i != count - 1) {
                    printf("Path component is not a directory: %s\n", components[i]);
                    return -1;
                }
                current_cluster = le16_to_cpu(entry.first_cluster);
                found = true;
                break;
            }
        }

        if (!found) {
            printf("Path not found: %s\n", components[i]);
            return -1;
        }
    }

    /* List final directory */
    list_cluster_directory(fd, bs, current_cluster);
    return 0;
}

/* Creates a new file or directory */
int create_file(int fd, BootSector *bs, const char *path, bool is_dir) {
    /* Split path into directory and filename */
    char *last_slash = strrchr(path, '/');
    char *filename = last_slash ? last_slash + 1 : (char*)path;
    char dir_path[256] = {0};
    
    if (last_slash) {
        strncpy(dir_path, path, last_slash - path);
    } else {
        strcpy(dir_path, "/");
    }

    /* Find parent directory */
    uint32_t parent_cluster = resolve_path(fd, bs, dir_path);
    if (parent_cluster == (uint32_t)-1) return -1;

    /* Convert to 8.3 filename */
    char fat_name[13];
    if (!to_83_filename(filename, fat_name)) {
        printf("Invalid filename format\n");
        return -1;
    }

    /* Find free directory entry */
    DirEntry new_entry = {0};
    uint32_t entry_offset = find_free_entry(fd, bs, parent_cluster);
    if (entry_offset == 0) {
        printf("No free directory entries\n");
        return -1;
    }

    /* Prepare new entry */
    memset(new_entry.filename, ' ', 8);
    memset(new_entry.extension, ' ', 3);
    sscanf(fat_name, "%8[^.].%3s", new_entry.filename, new_entry.extension);

    new_entry.attributes = is_dir ? ATTR_DIRECTORY : ATTR_ARCHIVE;
    new_entry.first_cluster = htole16(find_free_cluster(fd, bs));
    new_entry.file_size = 0;

    /* Write directory entry */
    lseek(fd, entry_offset, SEEK_SET);
    write(fd, &new_entry, sizeof(DirEntry));

    /* Initialize directory cluster if needed */
    if (is_dir) {
        initialize_directory_cluster(fd, bs, le16_to_cpu(new_entry.first_cluster), 
                                  parent_cluster);
    }

    return 0;
}

/* Deletes a file or empty directory */
int delete_file(int fd, BootSector *bs, const char *path) {
    /* Resolve path to get directory entry */
    DirEntry entry;
    uint32_t entry_offset;
    uint32_t parent_cluster = find_file_entry(fd, bs, path, &entry, &entry_offset);
    
    if (parent_cluster == (uint32_t)-1) {
        printf("File not found\n");
        return -1;
    }

    /* Check if directory is empty */
    if ((entry.attributes & ATTR_DIRECTORY) && 
        !is_directory_empty(fd, bs, le16_to_cpu(entry.first_cluster))) {
        printf("Directory not empty\n");
        return -1;
    }

    /* Free clusters in FAT */
    uint16_t cluster = le16_to_cpu(entry.first_cluster);
    while (cluster < CLUSTER_END && cluster != CLUSTER_FREE) {
        uint16_t next = read_fat_entry(fd, bs, cluster);
        update_fat(fd, bs, cluster, CLUSTER_FREE);
        cluster = next;
    }

    /* Mark directory entry as deleted */
    lseek(fd, entry_offset, SEEK_SET);
    uint8_t marker = 0xE5;
    write(fd, &marker, 1);

    return 0;
}

/* Modifies file content directly on disk */
int edit_file(int fd, BootSector *bs, const char *path, 
             uint32_t offset, uint8_t *data, uint32_t size) {
    /* Find file and verify size */
    DirEntry entry;
    if (!find_file(fd, bs, path, &entry)) {
        printf("File not found\n");
        return -1;
    }

    uint32_t file_size = le32_to_cpu(entry.file_size);
    if (offset + size > file_size) {
        printf("Edit exceeds file size\n");
        return -1;
    }

    /* Traverse clusters to find target offset */
    uint32_t bytes_remaining = offset;
    uint16_t cluster = le16_to_cpu(entry.first_cluster);
    uint32_t cluster_size = bs->bytes_per_sector * bs->sectors_per_cluster;

    while (bytes_remaining >= cluster_size) {
        cluster = read_fat_entry(fd, bs, cluster);
        if (cluster >= CLUSTER_END) break;
        bytes_remaining -= cluster_size;
    }

    /* Write data */
    uint32_t sector = get_cluster_location(bs, cluster) + (bytes_remaining / bs->bytes_per_sector);
    uint32_t sector_offset = bytes_remaining % bs->bytes_per_sector;
    
    lseek(fd, sector * bs->bytes_per_sector + sector_offset, SEEK_SET);
    write(fd, data, size);

    return 0;
}

