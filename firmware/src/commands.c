/**
 * @file commands.c
 * @author Samuel Meyers (Modified)
 * @brief eCTF command handlers with integrated security
 * @date 2026
 */

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"
#include "simple_crypto.h"
#include <string.h>
#include <stdint.h>

/* IMPORTANT COMPONENTS FROM HSM.c */
static file_t current_file;

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/** @brief List out the files on the system using reference design struct names. */
void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t temp_file;

    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        if (is_slot_in_use(i)) {
            read_file(i, &temp_file);
            file_list->entries[file_list->n_files].slot = i;
            // Reference design uses .name and MAX_NAME_LEN
            memcpy(file_list->entries[file_list->n_files].name, temp_file.name, MAX_NAME_LEN);
            file_list->n_files++;
        }
    }
}

/**********************************************************
 ******************* COMMAND HANDLERS *********************
 **********************************************************/

/** @brief Process messages from the Host (Management Interface) */
int handle_host_msg(msg_type_t cmd, void *uart_buf, uint16_t uart_len) {
    slot_t slot;
    // Using receive_request_t as a base if specific request types are missing
    receive_request_t *req_ptr = (receive_request_t *)uart_buf;
    list_response_t file_list;

    switch (cmd) {
        case LIST_MSG:
            generate_list_files(&file_list);
            write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, sizeof(list_response_t));
            break;

        case READ_MSG:
            // Security Check
            if (!check_pin(req_ptr->pin)) {
                print_error("Invalid PIN");
                return -1;
            }

            // Find slot by name (using .name from the request)
            if (find_slot(req_ptr->file_name, &slot) < 0) {
                print_error("File not found");
                return -1;
            }

            if (read_file(slot, &current_file) < 0) {
                print_error("Read failed");
                return -1;
            }

            write_packet(CONTROL_INTERFACE, READ_MSG, &current_file, sizeof(file_t));
            break;

        case WRITE_MSG:
            // Security Check
            if (!check_pin(req_ptr->pin)) {
                print_error("Invalid PIN");
                return -1;
            }

            if (find_slot(req_ptr->file.name, &slot) < 0) {
                slot = find_empty_slot();
                if (slot < 0) return -1;
            }

            if (write_file(slot, &req_ptr->file, req_ptr->uuid) < 0) {
                print_error("Write failed");
                return -1;
            }
            break;

        default:
            return -1;
    }

    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}

/** @brief Process messages from another HSM (Transfer Interface) */
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
            
            // Security Check: Use group_id to match filesystem_entry_t
            if (metadata == NULL || !validate_permission(metadata->group_id, RECV)) {
                print_error("Permission Denied");
                return -1;
            }

            if (read_file(command->slot, &recv_resp.file) < 0) {
                return -1;
            }

            memcpy(&recv_resp.uuid, &metadata->uuid, UUID_SIZE);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &recv_resp, sizeof(receive_response_t));
            break;

        default:
            return -1;
    }

    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
