#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"
#include "simple_crypto.h"
#include <string.h>

static file_t current_file;

void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t temp_file;
    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        if (is_slot_in_use(i)) {
            read_file(i, &temp_file);
            // Matches log: .files and .file_name
            file_list->files[file_list->n_files].slot = i;
            memcpy(file_list->files[file_list->n_files].file_name, temp_file.file_name, MAX_FILE_NAME_LEN);
            file_list->n_files++;
        }
    }
}

int handle_host_msg(msg_type_t cmd, void *uart_buf, uint16_t uart_len) {
    slot_t slot;
    // Using the generic receive_request_t to avoid "undeclared identifier" errors
    receive_request_t *req = (receive_request_t *)uart_buf;
    list_response_t file_list;

    switch (cmd) {
        case LIST_MSG:
            generate_list_files(&file_list);
            write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, sizeof(list_response_t));
            break;

        case READ_MSG:
            if (!check_pin(req->pin)) return -1;
            if (find_slot(req->file_name, &slot) < 0) return -1;
            if (read_file(slot, &current_file) < 0) return -1;
            write_packet(CONTROL_INTERFACE, READ_MSG, &current_file, sizeof(file_t));
            break;

        case WRITE_MSG:
            if (!check_pin(req->pin)) return -1;
            if (find_slot(req->file.file_name, &slot) < 0) {
                slot = find_empty_slot();
            }
            write_file(slot, &req->file, req->uuid);
            break;
        default: return -1;
    }
    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}

int handle_hsm_msg(msg_type_t cmd, void *uart_buf, uint16_t uart_len) {
    receive_request_t *command;
    receive_response_t recv_resp;
    list_response_t file_list;
    const filesystem_entry_t *metadata;

    switch (cmd) {
        case INTERROGATE_MSG:
            generate_list_files(&file_list);
            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list, LIST_PKT_LEN(file_list.n_files));
            break;

        case RECEIVE_MSG:
            command = (receive_request_t *)uart_buf;
            metadata = get_file_metadata(command->slot);
            // Matches log: .group_id
            if (metadata == NULL || !validate_permission(metadata->group_id, RECV_PERM)) return -1;
            read_file(command->slot, &recv_resp.file);
            memcpy(&recv_resp.uuid, &metadata->uuid, 16);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &recv_resp, sizeof(receive_response_t));
            break;
        default: return -1;
    }
    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
