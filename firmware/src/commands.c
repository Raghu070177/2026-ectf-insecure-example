/**
 * @file commands.c
 * @author Samuel Meyers (Modified for Security)
 * @brief eCTF command handlers with integrated security checks
 * @date 2026
 */

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"      // Added for check_pin and validate_permission
#include "simple_crypto.h"  // Added for cryptographic support
#include <string.h>

/* IMPORTANT COMPONENTS FROM HSM.c */
static file_t current_file;

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/** @brief List out the files on the system. */
void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t temp_file;

    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        if (is_slot_in_use(i)) {
            read_file(i, &temp_file);
            file_list->files[file_list->n_files].slot = i;
            memcpy(file_list->files[file_list->n_files].file_name, temp_file.file_name, MAX_FILE_NAME_LEN);
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
    read_request_t *read_req;
    write_request_t *write_req;
    list_response_t file_list;

    switch (cmd) {
        case LIST_MSG:
            generate_list_files(&file_list);
            write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, sizeof(list_response_t));
            break;

        case READ_MSG:
            read_req = (read_request_t *)uart_buf;

            // SECURITY: Verify PIN before allowing file read
            if (!check_pin(read_req->pin)) {
                print_error("Invalid PIN");
                return -1;
            }

            if (find_slot(read_req->file_name, &slot) < 0) {
                print_error("File not found");
                return -1;
            }

            if (read_file(slot, &current_file) < 0) {
                print_error("Failed to read file");
                return -1;
            }

            write_packet(CONTROL_INTERFACE, READ_MSG, &current_file, sizeof(file_t));
            break;

        case WRITE_MSG:
            write_req = (write_request_t *)uart_buf;

            // SECURITY: Verify PIN before allowing file write
            if (!check_pin(write_req->pin)) {
                print_error("Invalid PIN");
                return -1;
            }

            if (find_slot(write_req->file.file_name, &slot) < 0) {
                slot = find_empty_slot();
                if (slot < 0) {
                    print_error("No empty slots");
                    return -1;
                }
            }

            if (write_file(slot, &write_req->file, write_req->uuid) < 0) {
                print_error("Failed to write file");
                return -1;
            }
            break;

        default:
            print_error("Bad message type");
            return -1;
    }

    // Success ACK
    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}

/** @brief Process messages from another HSM (Transfer Interface) */
int handle_hsm_msg(msg_type_t cmd, void *uart_buf, uint16_t uart_len) {
    receive_request_t *command;
    receive_response_t recv_resp;
    list_response_t file_list;
    filesystem_entry_t *metadata;
    uint16_t write_length;

    switch (cmd) {
        case INTERROGATE_MSG:
            generate_list_files(&file_list);
            write_length = LIST_PKT_LEN(file_list.n_files);
            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list, write_length);
            break;

        case RECEIVE_MSG:
            command = (receive_request_t *)uart_buf;

            // SECURITY: Get metadata and validate group permission
            metadata = get_file_metadata(command->slot);
            
            // Note: 'group' is used here to match filesystem_entry_t definition
            if (metadata == NULL || !validate_permission(metadata->group, RECV)) {
                print_error("Permission Denied");
                return -1;
            }

            if (read_file(command->slot, &recv_resp.file) < 0) {
                print_error("Failed to read file");
                return -1;
            }

            memcpy(&recv_resp.uuid, &metadata->uuid, UUID_SIZE);

            write_length = sizeof(receive_response_t);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &recv_resp, write_length);
            break;

        default:
            print_error("Bad message type");
            return -1;
    }

    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
