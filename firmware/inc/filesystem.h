/**
 * @file filesystem.h
 * @brief eCTF flash-based filesystem management
 */

#ifndef __FILESYSTEM__
#define __FILESYSTEM__

#include <stdbool.h>
#include <string.h>
#include "simple_flash.h"

typedef unsigned char slot_t;
typedef uint16_t group_id_t;

/**********************************************************
 ********** BEGIN FUNCTIONALLY DEFINED ELEMENTS ***********
 **********************************************************/

#define MAX_FILE_COUNT 8
#define MAX_NAME_SIZE 32
#define MAX_CONTENTS_SIZE 8192

#define _FLASH_FAT_START 0x0003a000
#define UUID_SIZE 16

// filesystem_entry_t - DO NOT add fields - this is stored in flash
// and the layout is fixed. Original: uuid(16) + flash_addr(4) + length(4) = 24 bytes
typedef struct {
    uint8_t uuid[UUID_SIZE];   // 16 bytes
    uint32_t flash_addr;       // 4 bytes
    uint32_t length;           // 4 bytes
} filesystem_entry_t;

// FILE_ALLOCATION_TABLE is defined in filesystem.c - extern here so all files share one instance
extern filesystem_entry_t FILE_ALLOCATION_TABLE[MAX_FILE_COUNT];

/**********************************************************
 *********** END FUNCTIONALLY DEFINED ELEMENTS ************
 **********************************************************/

#define FILE_START_PAGE_FROM_SLOT(slot) (FILES_START_ADDR + (STORED_FILE_SIZE * (slot)))

#define FILE_TOTAL_SIZE(len) (len + offsetof(file_t, contents))

#define FILE_PAGE_COUNT 9
#define STORED_FILE_SIZE (FLASH_PAGE_SIZE * FILE_PAGE_COUNT)
#define FILES_START_ADDR 0x10000

#define FILE_IN_USE 0xdeadbeef

// File structure - group_id is stored inside the file itself
typedef struct {
    uint32_t in_use;
    group_id_t group_id;
    char name[MAX_NAME_SIZE];
    uint16_t contents_len;
    uint8_t contents[MAX_CONTENTS_SIZE];
} file_t;

// Function declarations
int init_fs();
bool is_slot_in_use(slot_t slot);
int create_file(file_t *dest, group_id_t group_id, char *name, uint16_t contents_len, uint8_t *contents);
int write_file(slot_t slot, file_t *src, uint8_t *uuid);
int read_file(slot_t slot, file_t *dest);
const filesystem_entry_t *get_file_metadata(slot_t slot);

#endif
