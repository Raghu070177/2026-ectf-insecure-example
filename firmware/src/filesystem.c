/**
 * @file filesystem.c
 * @author Samuel Meyers
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdint.h>
#include "filesystem.h"
#include "simple_flash.h"

// Single global FILE_ALLOCATION_TABLE shared across all translation units
filesystem_entry_t FILE_ALLOCATION_TABLE[MAX_FILE_COUNT];

int load_fat() {
    flash_simple_read((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
    return 0;
}

int store_fat() {
    flash_simple_erase_page(_FLASH_FAT_START);
    return flash_simple_write((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
}

int init_fs() {
    return load_fat();
}

bool is_slot_in_use(slot_t slot) {
    file_t temp_file;
    if (FILE_ALLOCATION_TABLE[slot].flash_addr == 0 ||
        FILE_ALLOCATION_TABLE[slot].length == 0) {
        return false;
    }
    return (!read_file(slot, &temp_file) && temp_file.in_use == FILE_IN_USE);
}

int create_file(
    file_t *dest,
    group_id_t group_id,
    char *name,
    uint16_t contents_len,
    uint8_t *contents
) {
    memset(dest, 0, sizeof(file_t));
    dest->in_use = FILE_IN_USE;
    dest->group_id = group_id;
    dest->contents_len = contents_len;
    strcpy(dest->name, name);
    if (contents_len > 0 && contents != NULL) {
        memcpy(dest->contents, contents, contents_len);
    }
    return 0;
}

int write_file(slot_t slot, file_t *src, uint8_t *uuid) {
    unsigned int length, flash_addr;

    flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    length = FILE_TOTAL_SIZE(src->contents_len);

    // Ensure minimum write size covers the file header
    if (length < (unsigned int)offsetof(file_t, contents)) {
        length = offsetof(file_t, contents);
    }

    // Only erase the pages actually needed for this file size
    // This prevents slow 9-page erase for tiny files (e.g. 0-byte files)
    int pages_needed = (length + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE;
    if (pages_needed > FILE_PAGE_COUNT) pages_needed = FILE_PAGE_COUNT;

    memcpy(&FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
    FILE_ALLOCATION_TABLE[slot].flash_addr = flash_addr;
    FILE_ALLOCATION_TABLE[slot].length = length;
    store_fat();

    for (int i = 0; i < pages_needed; i++) {
        flash_simple_erase_page(flash_addr + (FLASH_PAGE_SIZE * i));
    }

    return flash_simple_write(FILE_ALLOCATION_TABLE[slot].flash_addr, src, length);
}

int read_file(slot_t slot, file_t *dest) {
    int flash_addr, file_size;

    flash_addr = FILE_ALLOCATION_TABLE[slot].flash_addr;
    file_size = FILE_ALLOCATION_TABLE[slot].length;

    if (flash_addr <= 0 || file_size <= 0) {
        return -1;
    }

    flash_simple_read(flash_addr, dest, file_size);
    return 0;
}

const filesystem_entry_t *get_file_metadata(slot_t slot) {
    return &FILE_ALLOCATION_TABLE[slot];
}
