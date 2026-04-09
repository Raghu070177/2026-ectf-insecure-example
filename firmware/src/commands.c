#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"
#include "secrets.h"
#include <string.h>

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t temp_file;

    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        if (is_slot_in_use(i)) {
            read_file(i, &temp_file);
            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = temp_file.group_id;
            // FIX: Use memcpy for 16-byte names (no null terminator)
            memcpy(file_list->metadata[file_list->n_files].name, temp_file.name, MAX_NAME_SIZE);
            file_list->n_files++;
        }
    }
}

/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

int list(uint16_t pkt_len, uint8_t *buf) {
    list_command_t *command = (list_command_t*)buf;
    list_response_t file_list;

    if (!check_pin(command->pin)) {
        write_packet(CONTROL_INTERFACE, ERROR_MSG, "Invalid PIN", 11);
        return -1;
    }

    memset(&file_list, 0, sizeof(file_list));
    generate_list_files(&file_list);

    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}

int read(uint16_t pkt_len, uint8_t *buf) {
    read_command_t *command = (read_command_t*)buf;
    read_response_t file_info;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        write_packet(CONTROL_INTERFACE, ERROR_MSG, "Invalid PIN", 11);
        return -1;
    }

    if (read_file(command->slot, &curr_file) < 0) {
        write_packet(CONTROL_INTERFACE, ERROR_MSG, "Read failed", 11);
        return -1;
    }

    // FIX: Verify PERM_READ and notify host if denied
    if (!validate_permission(curr_file.group_id, PERM_READ)) {
        write_packet(CONTROL_INTERFACE, ERROR_MSG, "Denied", 6);
        return -1;
    }

    memset(&file_info, 0, sizeof(read_response_t));
    // FIX: Standardize on memcpy to avoid string length issues
    memcpy(file_info.name, curr_file.name, MAX_NAME_SIZE);
    memcpy(file_info.contents, curr_file.contents, curr_file.contents_len);

    pkt_len_t length = MAX_NAME_SIZE + curr_file.contents_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, &file_info, length);
    return 0;
}

int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t*)buf;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        write_packet(CONTROL_INTERFACE, ERROR_MSG, "Invalid PIN", 11);
        return -1;
    }

    // FIX: Explicitly check PERM_WRITE
    if (!validate_permission(command->group_id, PERM_WRITE)) {
        write_packet(CONTROL_INTERFACE, ERROR_MSG, "Denied", 6);
        return -1;
    }

    create_file(&curr_file, command->group_id, command->name, command->contents_len, command->contents);

    if (write_file(command->slot, &curr_file, command->uuid) < 0) {
        write_packet(CONTROL_INTERFACE, ERROR_MSG, "Store failed", 12);
        return -1;
    }

    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}

// ... receive, interrogate, and listen should remain handled similarly ...
